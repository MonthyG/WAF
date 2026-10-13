#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/env.sh"
cd "$WAF_ROOT/waf-node"
mkdir -p reports
run_dir="$(mktemp -d "$WAF_ROOT/waf-node/reports/benchmark.XXXXXX")"
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
[[ -x bin/vegeta ]] || { echo 'Run WAF_INSTALL_BENCHMARK_TOOLS=1 bash scripts/setup.sh first.' >&2; exit 1; }
# Dedicated test ports avoid disturbing an already-running development proxy.
GOMAXPROCS=1 ./bin/waf-origin -listen 127.0.0.1:19080 > "$run_dir/origin.log" 2>&1 & origin_pid=$!
for attempt in {1..50}; do
  kill -0 "$origin_pid"
  if curl -fsS --max-time 1 http://127.0.0.1:19080/ > /dev/null 2>&1; then break; fi
  sleep 0.1
done
for mode in off block; do
  python3 - "$run_dir" "$mode" <<'PY'
import json, sys
directory, mode = sys.argv[1:]
c = json.load(open('configs/local.json'))
c.update(mode=mode, origin='http://127.0.0.1:19080', listen='127.0.0.1:18080', management_listen='127.0.0.1:19090')
with open(directory + '/' + mode + '.json', 'w') as f: json.dump(c, f)
PY
  GOMAXPROCS=1 ./bin/waf-proxy -config "$run_dir/$mode.json" > "$run_dir/$mode.log" 2>&1 & proxy_pid=$!
  for attempt in {1..100}; do
    kill -0 "$proxy_pid"
    if curl -fsS --max-time 1 http://127.0.0.1:19090/readyz > /dev/null 2>&1; then break; fi
    sleep 0.1
  done
  curl -fsS --max-time 2 http://127.0.0.1:19090/readyz > /dev/null
  printf 'GET http://127.0.0.1:18080/products?category=books&page=1\nHost: shop.localhost\nUser-Agent: CloudInside-benchmark\nAccept: application/json\n\n' > "$run_dir/targets.txt"
  GOMAXPROCS=1 ./bin/vegeta attack -targets "$run_dir/targets.txt" -duration 3s -rate 500 -max-workers 64 > /dev/null
  GOMAXPROCS=1 ./bin/vegeta attack -targets "$run_dir/targets.txt" -duration "${WAF_BENCH_DURATION:-15s}" -rate "${WAF_BENCH_RATE:-3000}" -max-workers 128 > "$run_dir/$mode.bin"
  ./bin/vegeta report -type=json "$run_dir/$mode.bin" > "$run_dir/$mode-result.json"
  kill -TERM "$proxy_pid"
  wait "$proxy_pid"
  proxy_pid=''
done
python3 - "$run_dir" <<'PY'
import datetime, json, os, platform, subprocess, sys
directory = sys.argv[1]
off = json.load(open(directory + '/off-result.json'))
block = json.load(open(directory + '/block-result.json'))
summary = {
  'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
  'platform': platform.platform(), 'go': subprocess.check_output(['go', 'version'], text=True).strip(),
  'cpu_count_visible': os.cpu_count(), 'proxy_gomaxprocs': 1,
  'cpu_quota': open('/sys/fs/cgroup/cpu.max').read().strip() if os.path.exists('/sys/fs/cgroup/cpu.max') else 'unknown',
  'workload': 'HTTP GET /products?category=books&page=1; JSON fixture response; local origin; keep-alive; PL1; response inspection off',
  'requested_rate': int(os.getenv('WAF_BENCH_RATE', '3000')),
  'baseline_rps': off['throughput'], 'baseline_p95_ms': off['latencies']['95th']/1e6,
  'waf_rps': block['throughput'], 'waf_p95_ms': block['latencies']['95th']/1e6,
  'added_p95_ms': (block['latencies']['95th']-off['latencies']['95th'])/1e6,
  'baseline_success': off['success'], 'waf_success': block['success'],
  'baseline_status_codes': off['status_codes'], 'waf_status_codes': block['status_codes'],
  'errors': off['errors'] + block['errors'],
  'limitation': 'Shared cloud development host. GOMAXPROCS limits Go parallelism, not dedicated physical CPU allocation. Re-run on deployment hardware.'
}
with open(directory + '/summary.json', 'w') as f: json.dump(summary, f, indent=2); f.write('\n')
print(json.dumps(summary, indent=2))
print('Artifacts: ' + directory)
if off['success'] != 1 or block['success'] != 1: sys.exit('Benchmark had failed requests')
PY
