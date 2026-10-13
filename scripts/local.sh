#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/env.sh"
source "$WAF_ROOT/scripts/lib/check-runtime.sh"
cd "$WAF_ROOT"
command="${1:-doctor}"
shift || true
if [[ ! -f .local/dev.env ]]; then
  echo 'Missing local settings. Run: bash scripts/local-env.sh' >&2
  exit 1
fi
# Local commands deliberately load this checkout's credentials, even in a new shell.
set -a
source .local/dev.env
set +a
compose=(docker compose --env-file "$WAF_ROOT/.local/dev.env")
docker_check() {
  command -v docker >/dev/null || { echo 'Docker is missing; see docs/local-development.md.' >&2; exit 1; }
  docker compose version >/dev/null || { echo 'Docker Compose v2 is required.' >&2; exit 1; }
  if ! docker info >/dev/null 2>&1; then
    if [[ "$(command -v docker)" == /snap/* ]]; then
      echo 'Docker Snap is not accessible. Check: sudo snap services docker; id -nG; ls -l /var/run/docker.sock' >&2
    else
      echo 'Docker is not accessible. Check its daemon and your docker group membership; log in again after group changes.' >&2
    fi
    echo 'Do not run npm as root or chmod the Docker socket. See docs/local-development.md.' >&2
    exit 1
  fi
}
case "$command" in
  up)
    docker_check
    "${compose[@]}" up -d --wait --wait-timeout 120 || {
      echo 'Service startup failed. Do not continue to migrations/tests. Check occupied ports with: sudo ss -ltnp' >&2
      echo 'Ports and their matching URLs are configurable in .local/dev.env; see docs/local-development.md.' >&2
      exit 1
    }
    node scripts/check-services.mjs
    npm run db:migrate --workspace slave
    ;;
  stop)
    docker_check
    "${compose[@]}" stop
    ;;
  doctor)
    docker_check
    "${compose[@]}" ps
    node scripts/check-services.mjs
    ;;
  db-check) node scripts/check-services.mjs --database-only ;;
  exec) exec "$@" ;;
  test)
    docker_check
    node scripts/check-services.mjs --database-only
    exec "$@"
    ;;
  *) echo 'Usage: bash scripts/local.sh {up|stop|doctor|db-check|exec COMMAND...|test COMMAND...}' >&2; exit 2 ;;
esac
