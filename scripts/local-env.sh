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
echo 'Local database and encryption settings are in .local/dev.env (not printed).'
