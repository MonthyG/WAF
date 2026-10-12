#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/env.sh"
mkdir -p "$WAF_ROOT/.local"
if [[ ! -e "$WAF_ROOT/.local/dev.env" ]]; then
  (umask 077; python3 - "$WAF_ROOT/.local/dev.env" <<'PY'
import base64, secrets, sys
password=secrets.token_hex(24)
with open(sys.argv[1], 'x') as f:
    f.write('WAF_DB_PASSWORD='+password+'\n')
    f.write('DATABASE_URL=postgres://waf:'+password+'@127.0.0.1:15432/waf\n')
    f.write('WAF_MASTER_KEY='+base64.b64encode(secrets.token_bytes(32)).decode()+'\n')
    f.write('WAF_REGION=local-1\nWAF_DNS_TARGET=edge.localhost\n')
PY
  )
fi
python3 - "$WAF_ROOT/.local/dev.env" <<'PYENV'
import base64, secrets, sys
path=sys.argv[1]
with open(path) as f:
    names={line.split('=',1)[0] for line in f if '=' in line}
with open(path,'a') as f:
    if 'CONSOLE_SESSION_KEY' not in names:
        f.write('CONSOLE_SESSION_KEY='+base64.b64encode(secrets.token_bytes(32)).decode()+'\n')
    if 'CLICKHOUSE_PASSWORD' not in names:
        f.write('CLICKHOUSE_PASSWORD='+secrets.token_hex(24)+'\n')
    for name,value in [('CLICKHOUSE_URL','http://127.0.0.1:18123'),('CLICKHOUSE_USER','waf'),('CLICKHOUSE_DATABASE','waf'),('WAF_API_URL','http://127.0.0.1:9890'),('CONSOLE_ORIGIN','http://127.0.0.1:3000'),('CONSOLE_SECURE_COOKIES','false'),('REDIS_URL','redis://127.0.0.1:16379'),('NATS_URL','nats://127.0.0.1:14222')]:
        if name not in names: f.write(name+'='+value+'\n')
PYENV
echo 'Local database and encryption settings are in .local/dev.env (not printed).'
