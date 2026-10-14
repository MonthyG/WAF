# Test userspace compatibility. This is not a production application image.
ARG DISTRO=debian:12-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
FROM node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df AS node
FROM ${DISTRO}
RUN --mount=type=secret,id=trust_bundle \
    if [ -f /run/secrets/trust_bundle ]; then export SSL_CERT_FILE=/run/secrets/trust_bundle CURL_CA_BUNDLE=/run/secrets/trust_bundle; fi; \
    if command -v apt-get >/dev/null; then \
      apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl git make gcc libc6-dev python3 openssl tar gzip xz-utils && rm -rf /var/lib/apt/lists/*; \
    else \
      sed -i -e 's/^mirrorlist=/#mirrorlist=/' -e 's|^# baseurl=https://repo.almalinux.org|baseurl=https://repo.almalinux.org|' /etc/yum.repos.d/almalinux-*.repo && \
      dnf --setopt=sslcacert="${SSL_CERT_FILE:-/etc/pki/tls/certs/ca-bundle.crt}" install -y ca-certificates curl-minimal git make gcc glibc-devel python3 openssl tar gzip xz && dnf clean all; \
    fi
COPY --from=node /usr/local/ /usr/local/
WORKDIR /app
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN --mount=type=secret,id=trust_bundle \
    if [ -f /run/secrets/trust_bundle ]; then export SSL_CERT_FILE=/run/secrets/trust_bundle CURL_CA_BUNDLE=/run/secrets/trust_bundle NODE_EXTRA_CA_CERTS=/run/secrets/trust_bundle GIT_SSL_CAINFO=/run/secrets/trust_bundle; fi; \
    bash scripts/setup.sh && npm ci && npm run typecheck && npm run build && make test
CMD ["bash", "scripts/compat/smoke.sh"]
