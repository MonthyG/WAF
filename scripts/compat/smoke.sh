#!/usr/bin/env bash
set -euo pipefail
source scripts/env.sh
# Verify real routing and enforcement, not only that a binary starts.
python3 - <<'PY'
import json
from pathlib import Path
p=Path('.local/compat.json')
c=json.load(open('waf-node/configs/local.json'))
c['mode']='block'
p.write_text(json.dumps(c))
PY
waf-node/bin/waf-origin >.local/compat-origin.log 2>&1 &
origin=$!
waf-node/bin/waf-proxy -config .local/compat.json >.local/compat-proxy.log 2>&1 &
proxy=$!
trap 'kill "$proxy" "$origin" 2>/dev/null || true; wait || true' EXIT
for attempt in {1..100}; do
  if curl -fsS http://127.0.0.1:9090/readyz >/dev/null 2>&1; then break; fi
  sleep .1
done
[[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: shop.localhost' http://127.0.0.1:8080/)" == 200 ]]
[[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: shop.localhost' 'http://127.0.0.1:8080/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E')" == 403 ]]
echo 'PASS native WAF: benign request 200, XSS request blocked 403'
