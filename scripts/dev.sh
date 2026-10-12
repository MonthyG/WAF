#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/env.sh"
cd "$WAF_ROOT/waf-node"
origin_pid=''
proxy_pid=''
cleanup() {
  [[ -z "$proxy_pid" ]] || kill -TERM "$proxy_pid" 2>/dev/null || true
  [[ -z "$origin_pid" ]] || kill -TERM "$origin_pid" 2>/dev/null || true
  wait || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
./bin/waf-origin & origin_pid=$!
./bin/waf-proxy -config "${WAF_CONFIG:-configs/local.json}" & proxy_pid=$!
for attempt in {1..50}; do
  kill -0 "$origin_pid" "$proxy_pid"
  if curl -fsS --max-time 2 http://127.0.0.1:9090/readyz > /dev/null; then break; fi
  sleep 0.1
done
curl -fsS --max-time 2 http://127.0.0.1:9090/readyz
curl -fsS --max-time 2 -H 'Host: shop.localhost' http://127.0.0.1:8080/
wait -n "$origin_pid" "$proxy_pid"
