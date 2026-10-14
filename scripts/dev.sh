#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/env.sh"
cd "$WAF_ROOT/waf-node"
mkdir -p "$WAF_ROOT/.local"
run_dir="$(mktemp -d "$WAF_ROOT/.local/demo.XXXXXXXX")"
origin_pid=''
proxy_pid=''
cleanup() {
  [[ -z "$proxy_pid" ]] || kill -TERM "$proxy_pid" 2>/dev/null || true
  [[ -z "$origin_pid" ]] || kill -TERM "$origin_pid" 2>/dev/null || true
  wait || true
  rm -rf -- "$run_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
python3 "$WAF_ROOT/scripts/demo-config.py" "${WAF_CONFIG:-configs/local.json}" "$run_dir/config.json" > "$run_dir/addresses"
mapfile -t addresses < "$run_dir/addresses"
proxy_address="${addresses[0]}"
management_address="${addresses[1]}"
origin_address="${addresses[2]}"
hostname="${addresses[3]}"
mode="${addresses[4]}"
./bin/waf-proxy -config "$run_dir/config.json" -check
./bin/waf-origin -listen "$origin_address" & origin_pid=$!
./bin/waf-proxy -config "$run_dir/config.json" & proxy_pid=$!
ready=false
for attempt in {1..100}; do
  if ! kill -0 "$origin_pid" 2>/dev/null || ! kill -0 "$proxy_pid" 2>/dev/null; then
    echo 'Demo startup failed: a child process exited. See its error above.' >&2
    exit 1
  fi
  if curl -fsS --max-time 1 "http://$management_address/readyz" >/dev/null 2>&1 &&
     curl -fsS --max-time 1 "http://$origin_address/" >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then
  echo 'Demo startup timed out waiting for the proxy and origin.' >&2
  exit 1
fi
printf '\nDemo ready: http://%s (mode: %s)\n' "$proxy_address" "$mode"
printf 'Normal request: curl -i -H %q %q\n' "Host: $hostname" "http://$proxy_address/"
printf 'Attack request: curl -i -H %q %q\n' "Host: $hostname" "http://$proxy_address/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
printf 'Readiness: http://%s/readyz\nStop with Ctrl+C.\n\n' "$management_address"
status=0
wait -n "$origin_pid" "$proxy_pid" || status=$?
echo 'A demo process stopped; shutting down the remaining process.' >&2
if [[ "$status" == 0 ]]; then status=1; fi
exit "$status"
