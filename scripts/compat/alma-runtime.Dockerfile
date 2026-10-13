# Separately verifies AlmaLinux userspace when package-repository access is absent.
# First build the Debian compatibility image. Its packages/modules were verified
# by apt, npm integrity hashes and Go checksums. No Alma system libraries are replaced.
FROM waf-compat-debian AS verified
FROM almalinux:9@sha256:9819dc675b67b595c2b59e42be7763fca1a8bb217fa5944e04daa22e9a64db16
COPY --from=verified /usr/local/ /usr/local/
COPY --from=verified /app/ /app/
COPY --from=verified /root/.npm/ /app/.local/cache/npm/
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1 CGO_ENABLED=0 GOPROXY=off
RUN bash -c 'set -euo pipefail; source scripts/env.sh; cd waf-node; go mod verify; for name in waf-proxy waf-origin waf-lint waf-agent; do go build -mod=readonly -o bin/$name ./cmd/$name; done; go test -mod=readonly ./...; cd ..; npm ci --offline; npm run typecheck; npm run build'
CMD ["bash", "scripts/compat/smoke.sh"]
