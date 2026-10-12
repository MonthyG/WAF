# WAF

Development checkpoint for the WAF-as-a-Service described in [the design](docs/design.md). This is unfinished and not ready for production.

Implemented: Go reverse proxy with Coraza/OWASP CRS, tenant-scoped TypeScript API with Keystone authentication, PostgreSQL migrations, encrypted certificate storage, and NATS/BullMQ configuration distribution to Go agents. The default policy detects attacks; blocking is explicitly enabled per policy.

Still pending: edge TLS and automated ACME issuance/renewal, dashboard, analytics/billing, geo/rate-limit enforcement, and production hardening. Analytics endpoints currently return 501; unsupported rules are rejected by the compiler. The performance target in the design has not been met. Certificate upload/storage does not yet enable HTTPS at the edge.

## Development setup

Requires Linux x86-64, Node.js 24/npm, Docker with Compose, Make, Python 3, curl, and OpenSSL. Run from the repository root:

```bash
bash scripts/setup.sh
source scripts/env.sh
npm ci
bash scripts/local-env.sh
docker compose --env-file .local/dev.env up -d --wait
set -a
source .local/dev.env
set +a
npm run db:migrate
make build test
npm run typecheck
npm run build
npm test
```

The setup script installs checksum-verified Go 1.26.9 into `.local/toolchains`. If the Go module proxy cannot deliver `github.com/klauspost/compress@v1.18.0`, run `GOPROXY=direct go mod download github.com/klauspost/compress@v1.18.0` from `waf-node` after sourcing `scripts/env.sh`, then retry setup; keep checksum verification enabled.

Local secrets are generated in ignored `.local/dev.env`; keep this file private. Compose services bind to loopback and are intended for development. Integration tests create and remove their own test databases, and the distribution test starts temporary Docker containers and two real agents. They use a test Keystone server; a real deployment requires Keystone configuration.

## Try the HTTP proxy

```bash
make dev
```

From another terminal:

```bash
curl -i -H 'Host: shop.localhost' http://127.0.0.1:8080/
curl -i http://127.0.0.1:9090/readyz
```

Both should return HTTP 200. The demo uses detect mode. Stop it with Ctrl-C. Automated integration tests exercise block mode, tenant isolation, configuration propagation, invalid configuration rejection, and reloads under traffic.

## Resume implementation

Start with edge TLS: distribute certificate keys encrypted for each node, implement SNI certificate selection and HTTP-01 challenge handling, then add ACME issuance/renewal. Public Let's Encrypt staging validation needs a controlled domain and publicly reachable edge server. Continue the remaining phases in `docs/design.md` afterward.

Previous distribution acceptance results are recorded in [distribution.json](docs/validation/distribution.json); they are measurements of one development run, not production guarantees. Additional checks: `make race`, `make vet`, `make ftw`, `make ftw-platform`, and `make benchmark`. The original FTW suite has known HTTP-parser expectation differences; platform overrides are documented in `waf-node/ftw/platform-overrides.yaml` and the original suite retains failures.

API contract: [OpenAPI](docs/openapi.json). Main code: `slave/src` (control plane), `waf-node` (data plane). No production deployment or Keystone endpoint registration has been performed.
