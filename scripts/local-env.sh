#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/env.sh"
mkdir -p "$WAF_ROOT/.local"
python3 - "$WAF_ROOT/.local/dev.env" <<'PY'
import base64, os, secrets, socket, sys
from pathlib import Path
path=Path(sys.argv[1])
exists=path.exists()
values={}
if exists:
    for line in path.read_text().splitlines():
        if '=' in line and not line.startswith('#'):
            key,value=line.split('=',1)
            values[key]=value
pending={}
def add(key,value):
    if key not in values:
        pending[key]=value
        values[key]=value
# Old checkouts retain their existing project/volumes and credentials.
# A new checkout gets a unique project, so it cannot reuse a deleted clone's DB.
add('COMPOSE_PROJECT_NAME','cloudinside-waf' if exists else 'waf-'+secrets.token_hex(6))
reserved=[]
def port(key, preferred):
    if key in values: return
    if exists:
        add(key,str(preferred))
        return
    sock=socket.socket()
    try: sock.bind(('127.0.0.1',preferred))
    except OSError: sock.bind(('127.0.0.1',0))
    reserved.append(sock)
    add(key,str(sock.getsockname()[1]))
for key,number in [('WAF_POSTGRES_PORT',15432),('WAF_CLICKHOUSE_PORT',18123),('WAF_REDIS_PORT',16379),('WAF_NATS_PORT',14222)]:
    port(key,number)
add('WAF_DB_PASSWORD',secrets.token_hex(24))
add('DATABASE_URL','postgres://waf:'+values['WAF_DB_PASSWORD']+'@127.0.0.1:'+values['WAF_POSTGRES_PORT']+'/waf')
add('WAF_MASTER_KEY',base64.b64encode(secrets.token_bytes(32)).decode())
add('CONSOLE_SESSION_KEY',base64.b64encode(secrets.token_bytes(32)).decode())
add('CLICKHOUSE_PASSWORD',secrets.token_hex(24))
for key,value in [('WAF_REGION','local-1'),('WAF_DNS_TARGET','edge.localhost'),('CLICKHOUSE_URL','http://127.0.0.1:'+values['WAF_CLICKHOUSE_PORT']),('CLICKHOUSE_USER','waf'),('CLICKHOUSE_DATABASE','waf'),('WAF_API_URL','http://127.0.0.1:9890'),('CONSOLE_ORIGIN','http://127.0.0.1:3000'),('CONSOLE_SECURE_COOKIES','false'),('REDIS_URL','redis://127.0.0.1:'+values['WAF_REDIS_PORT']),('NATS_URL','nats://127.0.0.1:'+values['WAF_NATS_PORT'])]:
    add(key,value)
# No replacement of existing settings. Only generated, shell-safe values are added.
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
with os.fdopen(fd,'a') as out:
    if pending and exists and path.stat().st_size and not path.read_bytes().endswith(b'\n'):
        out.write('\n')
    for key,value in pending.items(): out.write(key+'='+value+'\n')
os.chmod(path,0o600)
for sock in reserved: sock.close()
PY
echo 'Local settings are in .local/dev.env (values not printed; existing settings preserved).'
