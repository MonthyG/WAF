# WAF

Development checkpoint for the WAF-as-a-Service described in [the design](docs/design.md). This is unfinished and not ready for production.

Implemented: Go reverse proxy with Coraza/OWASP CRS, tenant-scoped TypeScript API with Keystone authentication, PostgreSQL migrations, encrypted certificate delivery, HTTPS termination, ACME issuance/renewal, NATS/BullMQ configuration distribution, a Next.js management console, ClickHouse attack logs/metrics, event-based rule exclusions, and usage export. The default policy detects attacks; blocking is explicitly enabled per policy.

Still pending: billing-system integration, geo/rate-limit enforcement, dedicated provisioning, and production hardening. Analytics requires a configured ClickHouse connection and reporting agents; unsupported rules are rejected by the compiler. The performance target in the design has not been met. TLS has passed local ACME integration tests against Pebble; public Let’s Encrypt staging has not been exercised.

## Development setup

Primary targets: Ubuntu 24.04, AlmaLinux 9, and Debian 12 (x86-64). See [OS installation and recovery](docs/local-development.md) for prerequisites, Docker Snap, occupied ports, and database-password recovery. Node.js 24 and Docker Compose v2 are required. Run from the repository root as your normal user:

```bash
bash scripts/setup.sh
source scripts/env.sh
npm ci
bash scripts/local-env.sh
npm run local:up
npm run doctor
make build test
npm run typecheck
npm run build
npm test
# Browser workflow test (Chromium required):
npm run test:console
```

Stop at any failed command. Do not delete/re-clone the checkout or remove database volumes to fix an authentication error. `npm run local:fresh` creates a separate empty installation while preserving old settings and data; see the recovery guide first.

The setup script installs checksum-verified Go 1.26.9 into `.local/toolchains`. If the Go module proxy cannot deliver `github.com/klauspost/compress@v1.18.0`, run `GOPROXY=direct go mod download github.com/klauspost/compress@v1.18.0` from `waf-node` after sourcing `scripts/env.sh`, then retry setup; keep checksum verification enabled.

Local secrets are generated in ignored `.local/dev.env`; keep this file private. Compose services bind to loopback and are intended for development. Integration tests create and remove their own test databases, and the distribution test starts temporary Docker containers and two real agents. They use a test Keystone server; a real deployment requires Keystone configuration.

## Try the HTTP proxy

```bash
make dev
```

The launcher prints **Normal request**, **Attack request**, and **Readiness** commands/addresses. Copy its printed curl commands into another terminal. It prefers ports 8080/9090/9080 and chooses free loopback ports if those are occupied; it never stops another service. Keep the demo terminal open while testing.

The default mode detects attacks: normal requests return 200 and the test attack is logged as detected. To verify blocking instead:

```bash
WAF_DEMO_MODE=block make dev
```

The printed normal request should return **200**, and the printed attack request should return **403**. Stop with Ctrl-C. To choose a fixed proxy port, use `WAF_DEMO_PORT=18080 WAF_DEMO_MODE=block make dev`; an occupied explicit port produces a clear error. `WAF_DEMO_MANAGEMENT_PORT` and `WAF_DEMO_ORIGIN_PORT` are also available. Each run uses a private temporary configuration and its own local origin; source configuration files remain unchanged. A `WAF_CONFIG` file can supply policy settings, but the demo replaces its network addresses/origins with the local fixture.

Automated integration tests exercise block mode, tenant isolation, configuration propagation, invalid configuration rejection, and reloads under traffic. After building, `python3 scripts/test-demo.py` checks occupied-port recovery, real blocking, shutdown, and early child-process failure.

## Resume implementation

See [TLS operations](docs/tls-operations.md) for edge registration, encrypted key delivery, uploads, and ACME configuration. The local CA test issues real one-hour certificates and validates renewal over HTTP-01 with HTTPS redirect enabled.

The console lives at `/console/services/waf`. Source `.local/dev.env`, configure real `KEYSTONE_URL` and `KEYSTONE_SERVICE_TOKEN`, then run `npm run dev:api`, `npm run worker`, `npm run ingest`, and `npm run dev:console` in separate terminals with the same environment. Sign in using a project-scoped Keystone token. `CONSOLE_SESSION_KEY` is generated locally and must remain private. Set `CONSOLE_ORIGIN` to your exact browser origin. In production serve the console over HTTPS and set `CONSOLE_SECURE_COOKIES=true`; the generated local setting is for loopback HTTP only.

For a self-contained browser validation without real Keystone, `npm run test:console` launches a test-only identity server, isolated database, real API/worker/edge, and the built console. It simulates DNS publication, verifies blocking and tenant isolation, and cleans up afterward. Requires Chromium (`CHROMIUM_PATH` overrides `/usr/bin/chromium`). Screenshots are saved in ignored `.local/console-desktop.png` and `.local/console-mobile.png`.

See [analytics operations](docs/analytics-operations.md) for agent reporting, retention, queries, usage export, and collection limits. Validate public DNS/TLS and the complete customer workflow in your staging cloud before production deployment.

Previous distribution acceptance results are recorded in [distribution.json](docs/validation/distribution.json); they are measurements of one development run, not production guarantees. Install the optional benchmark tool with `WAF_INSTALL_BENCHMARK_TOOLS=1 bash scripts/setup.sh` before benchmarking. Additional checks: `make race`, `make vet`, `make ftw`, `make ftw-platform`, and `make benchmark`. The original FTW suite has known HTTP-parser expectation differences; platform overrides are documented in `waf-node/ftw/platform-overrides.yaml` and the original suite retains failures.

API contract: [OpenAPI](docs/openapi.json). Main code: `slave/src` (control plane), `waf-node` (data plane). No production deployment or Keystone endpoint registration has been performed. Browser/ACME results are retained under `docs/validation`.

Analytics integration results are recorded in [analytics.json](docs/validation/analytics.json). Usage export is a read-only metering interface; invoice generation and integration with an external billing system remain outstanding.
