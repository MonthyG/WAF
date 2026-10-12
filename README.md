# WAF

Development checkpoint for the WAF-as-a-Service described in [the design](docs/design.md). This is unfinished and not ready for production.

Implemented: Go reverse proxy with Coraza/OWASP CRS, tenant-scoped TypeScript API with Keystone authentication, PostgreSQL migrations, encrypted certificate delivery, HTTPS termination, ACME issuance/renewal, NATS/BullMQ configuration distribution, a Next.js management console, ClickHouse attack logs/metrics, event-based rule exclusions, and usage export. The default policy detects attacks; blocking is explicitly enabled per policy.

Still pending: billing-system integration, geo/rate-limit enforcement, dedicated provisioning, and production hardening. Analytics requires a configured ClickHouse connection and reporting agents; unsupported rules are rejected by the compiler. The performance target in the design has not been met. TLS has passed local ACME integration tests against Pebble; public Let’s Encrypt staging has not been exercised.

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
# Browser workflow test (Chromium required):
npm run test:console
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

See [TLS operations](docs/tls-operations.md) for edge registration, encrypted key delivery, uploads, and ACME configuration. The local CA test issues real one-hour certificates and validates renewal over HTTP-01 with HTTPS redirect enabled.

The console lives at `/console/services/waf`. Source `.local/dev.env`, configure real `KEYSTONE_URL` and `KEYSTONE_SERVICE_TOKEN`, then run `npm run dev:api`, `npm run worker`, `npm run ingest`, and `npm run dev:console` in separate terminals with the same environment. Sign in using a project-scoped Keystone token. `CONSOLE_SESSION_KEY` is generated locally and must remain private. Set `CONSOLE_ORIGIN` to your exact browser origin. In production serve the console over HTTPS and set `CONSOLE_SECURE_COOKIES=true`; the generated local setting is for loopback HTTP only.

For a self-contained browser validation without real Keystone, `npm run test:console` launches a test-only identity server, isolated database, real API/worker/edge, and the built console. It simulates DNS publication, verifies blocking and tenant isolation, and cleans up afterward. Requires Chromium (`CHROMIUM_PATH` overrides `/usr/bin/chromium`). Screenshots are saved in ignored `.local/console-desktop.png` and `.local/console-mobile.png`.

See [analytics operations](docs/analytics-operations.md) for agent reporting, retention, queries, usage export, and collection limits. Validate public DNS/TLS and the complete customer workflow in your staging cloud before production deployment.

Previous distribution acceptance results are recorded in [distribution.json](docs/validation/distribution.json); they are measurements of one development run, not production guarantees. Additional checks: `make race`, `make vet`, `make ftw`, `make ftw-platform`, and `make benchmark`. The original FTW suite has known HTTP-parser expectation differences; platform overrides are documented in `waf-node/ftw/platform-overrides.yaml` and the original suite retains failures.

API contract: [OpenAPI](docs/openapi.json). Main code: `slave/src` (control plane), `waf-node` (data plane). No production deployment or Keystone endpoint registration has been performed. Browser/ACME results are retained under `docs/validation`.

Analytics integration results are recorded in [analytics.json](docs/validation/analytics.json). Usage export is a read-only metering interface; invoice generation and integration with an external billing system remain outstanding.
