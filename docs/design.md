# WAF as a Service — Design Document

**Product:** HostingInside CloudInside — WAF as a Service ("CloudInside WAF")
**Status:** Draft v0.1
**Owner:** David
**Last updated:** 2026-10-12

---

## 0. How to use this document

This is the source of truth for building the WAF service. It is written to be executable by humans and AI coding agents alike:

- Every component has a **responsibility**, **interfaces**, and **acceptance criteria**.
- Build strictly in the phase order in §12. Do not start a phase until the previous phase's acceptance criteria pass.
- When this doc and the code disagree, update the doc in the same PR.
- Words **MUST / SHOULD / MAY** follow RFC 2119.

---

## 1. Summary

Add a Web Application Firewall service to the CloudInside OpenStack cloud. Customers protect HTTP/HTTPS sites (usually running on their CloudInside instances) by routing traffic through managed WAF nodes that filter requests with the OWASP Core Rule Set (CRS) and customer-defined rules.

The service is a **standalone OpenStack-style service** registered in the Keystone catalog as `waf`, with its API running on the controller. It is **not** a patch to nova-api.

## 2. Goals and non-goals

### Goals
1. Customers can protect a domain in under 5 minutes from the console.
2. OWASP CRS protection with tunable paranoia level and detect/block modes.
3. Custom rules: IP allow/deny, path exclusions, rule exclusions, rate limits.
4. TLS termination with customer-uploaded certs or automatic ACME (Let's Encrypt).
5. Per-site attack log and traffic metrics in the console.
6. Usage metering for billing.
7. Native feel: Keystone auth, project scoping, listed in the service catalog.

### Non-goals (v1)
- Writing our own rule/inspection engine (we embed **Coraza**).
- Bot management, CAPTCHA/JS challenges, CDN caching.
- Inline L2/L3 filtering or Neutron service chaining (networking-sfc).
- Non-HTTP protocols.

## 3. Key decisions

| ID | Decision | Rationale |
|----|----------|-----------|
| D1 | Separate service, not inside nova-api | Upgrades of Nova must not break us; follows Octavia/Designate precedent. |
| D2 | Control plane lives in **slave** as module `waf`, exposed at `/v1/waf/*` | Reuses existing controller→service→client layering, Drizzle, BullMQ, auth helpers. May be split out later. |
| D3 | Data plane is a custom **Go reverse proxy embedding Coraza + CRS** | Coraza is OWASP, Apache-2.0, ModSecurity-compatible, native Go. We own the proxy, config, and tenancy. |
| D4 | Config distribution over **NATS JetStream** | Already in our stack; durable, replayable, per-node subjects. |
| D5 | **Shared edge** mode first; **Dedicated VM** mode later | Shared edge needs no Neutron work and ships fastest. |
| D6 | New sites default to **detect** mode | False positives kill adoption; customers opt into block. |
| D7 | Logs to **ClickHouse** | High-volume append-only analytics; cheap aggregation for metrics and billing. |

## 4. Glossary

- **Site** — one protected hostname (e.g. `shop.example.com`) with one or more origins.
- **Origin** — backend the WAF forwards to (`ip:port`, http/https).
- **Policy** — CRS settings + mode attached to a site.
- **Rule** — customer custom rule (IP list, exclusion, rate limit).
- **Edge node** — shared WAF node running `waf-proxy` + `waf-agent`.
- **Dedicated node** — per-project WAF VM booted through Nova.
- **Config revision** — monotonically increasing version of a site's compiled config.

## 5. Architecture

```
 Browser
   │
 Console (Next.js)  ── /api/waf/* route handlers
   │
 console-api (Express)  ── enqueues jobs, billing
   │
 slave  /v1/waf/*  ◄── Keystone catalog: service "waf"
   │  ├─ Postgres (waf_* tables, Drizzle)
   │  ├─ BullMQ workers (provision, cert, compile)
   │  └─ NATS JetStream publisher
   │
   ├──► subject waf.config.<node_id>  ──►  waf-agent ──► waf-proxy (Coraza+CRS)
   ◄─── subject waf.node.heartbeat     ◄──  waf-agent
   ◄─── subject waf.events.<node_id>   ◄──  waf-proxy audit log
                                                │
                                   ingest worker → ClickHouse
                                                │
  Client traffic ─► DNS / floating IP ─► waf-proxy ─► customer origin
```

### 5.1 Components

| Component | Language | Runs on | Responsibility |
|-----------|----------|---------|----------------|
| `slave/src/modules/waf` | TypeScript | controller | Public API, validation, Keystone auth, persistence, config compile, publish |
| `waf-worker` jobs | TypeScript (BullMQ) | controller | Provisioning, ACME issuance/renewal, origin lockdown, dedicated VM boot |
| `waf-proxy` | Go | edge/dedicated nodes | TLS termination, Coraza inspection, reverse proxy, metrics |
| `waf-agent` | Go (same binary, `agent` subcommand, or sidecar) | edge/dedicated nodes | Subscribe to config, validate, hot-swap, heartbeat |
| `waf-ingest` | TypeScript or Go | controller/log node | NATS events → ClickHouse |
| Console WAF pages | Next.js | console | UI under **Services → WAF** |

## 6. Data model (Postgres, Drizzle)

All tables include `id uuid pk`, `created_at`, `updated_at`. All tenant tables include `project_id` (Keystone project UUID) and `region_id`.

### 6.1 `waf_sites`
| Column | Type | Notes |
|---|---|---|
| project_id | uuid | indexed |
| region_id | text | e.g. `ap-hongkong-1` |
| hostname | text | unique per region; lowercase; wildcard `*.x` allowed in v2 |
| mode | enum `shared`,`dedicated` | |
| status | enum `pending`,`provisioning`,`active`,`error`,`deleting` | |
| policy_id | uuid fk | |
| certificate_id | uuid fk null | |
| http_redirect | bool | force HTTPS |
| config_revision | bigint | bumped on any change |
| applied_revision | bigint | lowest revision confirmed by all assigned nodes |
| verification_token | text | DNS TXT ownership check |
| verified_at | timestamptz null | |

### 6.2 `waf_origins`
`site_id`, `address` (IP or host), `port`, `scheme` (`http`/`https`), `weight`, `health_check_path`, `instance_id` (Nova UUID, nullable — used for SG lockdown).

### 6.3 `waf_policies`
| Column | Type | Default |
|---|---|---|
| project_id | uuid | |
| name | text | |
| engine_mode | enum `detect`,`block`,`off` | `detect` |
| paranoia_level | int 1–4 | 1 |
| inbound_anomaly_threshold | int | 5 |
| outbound_anomaly_threshold | int | 4 |
| request_body_limit_kb | int | 1024 |
| inspect_response_body | bool | false |

### 6.4 `waf_rules`
| Column | Type | Notes |
|---|---|---|
| policy_id | uuid | |
| priority | int | lower runs first |
| type | enum `ip_allow`,`ip_deny`,`geo_deny`,`rule_exclusion`,`path_exclusion`,`rate_limit`,`raw` | `raw` admin-only |
| spec | jsonb | type-specific, schema-validated (see §7.4) |
| enabled | bool | |

### 6.5 `waf_certificates`
`project_id`, `source` (`upload`,`acme`), `domains text[]`, `cert_pem`, `key_pem_encrypted` (AES-256-GCM, key from env/KMS), `not_after`, `acme_status`, `last_error`.

### 6.6 `waf_nodes`
`region_id`, `kind` (`edge`,`dedicated`), `project_id` (null for edge), `nova_instance_id`, `mgmt_ip`, `public_ip`, `version`, `status` (`online`,`degraded`,`offline`,`draining`), `last_heartbeat_at`, `applied_revision_map jsonb`.

### 6.7 `waf_site_nodes`
Assignment table: `site_id`, `node_id`.

### 6.8 `cloud_waf_products`
Mirrors existing product tables: `region_id`, `name`, `mode`, `monthly_price`, `included_requests_m`, `per_million_price`, `included_sites`, `hidden`.

## 7. Control plane API

Base: `https://api.<region>.cloudinside/waf/v1` (public), `http://controller:9890/v1/waf` (internal).
Auth: `X-Auth-Token` (Keystone). Errors use the existing `HttpError` shape `{ error: { code, message, details? } }`.

### 7.1 Keystone registration
```bash
openstack service create --name waf --description "WAF as a Service" waf
openstack endpoint create --region <region> waf public   https://api.<region>.cloudinside/waf/v1
openstack endpoint create --region <region> waf internal http://controller:9890/v1/waf
openstack endpoint create --region <region> waf admin    http://controller:9890/v1/waf
```

### 7.2 Auth middleware
1. Read `X-Auth-Token`; 401 if missing.
2. Validate via `GET /v3/auth/tokens` with `X-Auth-Token: <service token>` and `X-Subject-Token: <user token>`.
3. Cache result (keyed by SHA-256 of token) until `expires_at` or 5 min, whichever is sooner.
4. Attach `req.ctx = { userId, projectId, roles }`.
5. Every query MUST filter by `projectId` unless the role is `admin`.

### 7.3 Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/sites` | List sites in project |
| POST | `/sites` | Create site (→ `pending`, returns verification token) |
| GET | `/sites/:id` | Site detail incl. status, revisions, DNS target |
| PATCH | `/sites/:id` | Update hostname-independent settings |
| DELETE | `/sites/:id` | Async delete |
| POST | `/sites/:id/verify` | Check DNS TXT, then provision |
| GET/POST/DELETE | `/sites/:id/origins[/:originId]` | Manage origins |
| GET/POST/PATCH/DELETE | `/policies[/:id]` | Manage policies |
| GET/POST/PATCH/DELETE | `/policies/:id/rules[/:ruleId]` | Manage rules |
| POST | `/certificates` | Upload cert or request ACME |
| GET/DELETE | `/certificates[/:id]` | |
| GET | `/sites/:id/events?from&to&action&rule_id&ip&limit&cursor` | Attack log (ClickHouse) |
| GET | `/sites/:id/metrics?from&to&step` | Requests, blocked, bandwidth, latency p50/p95 |
| POST | `/sites/:id/events/:eventId/exclude` | One-click: create rule_exclusion from an event |
| GET | `/nodes` | admin only |
| POST | `/nodes/:id/drain` | admin only |

### 7.4 Rule spec schemas (zod)

```ts
ip_allow / ip_deny:   { cidrs: string[] }                         // max 1000
geo_deny:             { countries: string[] }                     // ISO-3166 alpha-2
rule_exclusion:       { rule_ids: number[], path_prefix?: string, args?: string[] }
path_exclusion:       { path_prefix: string }                     // skip WAF inspection entirely
rate_limit:           { key: "ip" | "ip+path", limit: number, window_s: number,
                        path_prefix?: string, action: "block" | "log" }
raw:                  { seclang: string }                         // admin only, compiled+tested before save
```

### 7.5 Example: create site
```http
POST /v1/waf/sites
{
  "hostname": "shop.example.com",
  "mode": "shared",
  "origins": [{ "address": "203.0.113.10", "port": 443, "scheme": "https", "instance_id": "…" }],
  "policy": { "engine_mode": "detect", "paranoia_level": 1 },
  "tls": { "source": "acme" }
}
→ 202
{
  "id": "…", "status": "pending",
  "verification": { "type": "TXT", "name": "_cloudinside-waf.shop.example.com", "value": "ciw-…" },
  "dns_target": { "type": "CNAME", "value": "edge.ap-hongkong-1.waf.cloudinside.net" }
}
```

## 8. Config compilation and distribution

### 8.1 Compile
On any change to a site, its origins, its policy, its rules, or its certificate:
1. Increment `waf_sites.config_revision` in the same transaction.
2. Enqueue BullMQ job `waf.compile` `{ siteId, revision }` (deduplicated by siteId; latest revision wins).
3. Worker builds a **SiteBundle**:

```jsonc
{
  "site_id": "…", "revision": 42, "hostname": "shop.example.com",
  "tls": { "cert_pem": "…", "key_pem": "…" },            // key encrypted with node public key
  "origins": [{ "url": "https://203.0.113.10:443", "weight": 1 }],
  "http_redirect": true,
  "limits": { "request_body_kb": 1024 },
  "rate_limits": [ … ],
  "seclang": "SecRuleEngine DetectionOnly\nInclude @crs-setup\n…\nInclude @owasp_crs/*.conf\n…"
}
```

4. Validate `seclang` by compiling it with Coraza in the worker (Go helper binary `waf-lint` invoked via child process). Fail → site `error`, store message, do not publish.

### 8.2 Rule ordering in generated SecLang
1. Engine mode + body limits
2. CRS setup (paranoia level, thresholds)
3. IP allow (ctl:ruleEngine=Off for matches)
4. IP deny / geo deny (deny early)
5. Path exclusions
6. Rule exclusions (`ctl:ruleRemoveById` / `ruleRemoveTargetById`)
7. CRS rules
8. Custom raw rules

Custom rule IDs are allocated from range **9,000,000–9,099,999** per site to avoid collisions with CRS.

### 8.3 Distribution (NATS JetStream)

| Subject | Direction | Payload |
|---|---|---|
| `waf.config.<node_id>` | control → node | `{ op: "upsert"\|"delete", bundle }` |
| `waf.node.heartbeat` | node → control | `{ node_id, version, load, applied: { site_id: revision } }` every 10 s |
| `waf.node.ack` | node → control | `{ node_id, site_id, revision, ok, error? }` |
| `waf.events.<node_id>` | node → ingest | batched audit events |

Stream `WAF_CONFIG`: work-queue retention per node subject, max age 7 d.
On agent start: request a full snapshot (`waf.config.snapshot.<node_id>` request/reply), then follow the stream.

## 9. Data plane

### 9.1 waf-proxy (Go)
- Listeners: `:80`, `:443` (TLS via `GetCertificate` keyed by SNI from an in-memory map).
- Request path:
  1. Match `Host` → site (404 page if unknown).
  2. Redirect to HTTPS if configured.
  3. Rate-limit check (in-memory token buckets; v2: shared via NATS KV or Redis).
  4. Coraza transaction: connection → URI → request headers → request body → evaluate.
  5. If interrupted and mode is `block` → return 403 branded page with event ID.
  6. Forward via `httputil.ReverseProxy` to chosen origin; set `X-Forwarded-For`, `X-Forwarded-Proto`, `X-CloudInside-WAF-Event` (if logged).
  7. Optional response inspection (off by default).
  8. Close transaction; emit audit event if any rule matched.
- Site configs stored behind `atomic.Pointer[SiteTable]` → swap is lock-free and existing connections finish on the old table.
- Coraza WAF instances are compiled once per site revision and reused across requests.
- Exposes `/metrics` (Prometheus) on management interface only.

### 9.2 waf-agent
- Subscribes to `waf.config.<node_id>`.
- For each bundle: decrypt key → compile Coraza instance → health-check origin (non-blocking) → swap into table → publish `waf.node.ack`.
- On compile failure: keep previous revision, ack `ok: false`.
- Sends heartbeat every 10 s; control plane marks node `offline` after 30 s and reassigns sites.

### 9.3 Node image
- Ubuntu LTS minimal + `waf-proxy` binary + CRS release pinned by version + systemd units + node_exporter.
- Built with Packer, uploaded to Glance as `cloudinside-waf-<version>`.
- Boot config via cloud-init: `node_id`, NATS URL, NATS credentials, node keypair.

## 10. Deployment modes

### 10.1 Shared edge (v1)
- ≥2 edge nodes per region behind a shared floating IP pair (keepalived VRRP) or DNS round robin.
- Customer creates CNAME (or A record to edge VIP) for the hostname.
- Site assigned to all edge nodes in the region.
- **Origin lockdown job:** if an origin has `instance_id`, add Neutron security-group rules allowing 80/443 only from edge node IPs, and remove `0.0.0.0/0` on those ports (with customer opt-in confirmation in UI).

### 10.2 Dedicated VM (v2)
- BullMQ job `waf.provision.dedicated` (pattern of `createInstanceJob`):
  1. Nova boot from `cloudinside-waf-*` image, flavor from product.
  2. Ports: management network + tenant network.
  3. Associate floating IP (new or moved from customer).
  4. Wait for heartbeat (timeout 10 min) → assign project sites → `active`.
- Instance is owned by the service project, not the customer's project (customer can't SSH or tamper).

## 11. TLS

- **Upload:** validate PEM, key match, chain, expiry, domain coverage.
- **ACME:** HTTP-01 handled by waf-proxy at `/.well-known/acme-challenge/*` (served from bundle-delivered tokens). Worker job `waf.cert.issue`; renewal job runs daily, renews at <30 days remaining.
- Private keys: encrypted at rest (AES-256-GCM, master key from env/KMS); re-encrypted to each node's public key in bundles.

## 12. Implementation phases

Each phase lists the deliverables and the acceptance criteria that must pass.

### Phase 1 — Data plane spike
- `waf-proxy` with one hardcoded site, Coraza + CRS PL1.
- **Accept:** `go-ftw` CRS regression suite passes ≥ 99%; SQLi/XSS payloads blocked in block mode; benign traffic benchmark recorded (target: ≥ 3k req/s per vCPU at PL1 on our hardware, p95 added latency < 5 ms).

### Phase 2 — Control plane CRUD
- `slave/src/modules/waf/{sites,origins,policies,rules,certificates}` with controller/service layering, Drizzle migrations, zod validation, Keystone middleware, catalog registration.
- **Accept:** integration tests for every endpoint; cross-project access returns 404; OpenAPI spec generated.

### Phase 3 — Compile + distribute
- `waf.compile` worker, `waf-lint`, NATS subjects, waf-agent hot reload, heartbeats.
- **Accept:** config change reaches all edge nodes in < 5 s p95; invalid rule never reaches a node; killing a node triggers `offline` within 30 s; zero dropped connections during reload under load test.

### Phase 4 — TLS
- Upload + ACME issuance and renewal.
- **Accept:** new site gets valid cert end-to-end automatically; renewal tested with short-lived staging certs.

### Phase 5 — Console
- Next.js pages under **Services → WAF**: site list, create wizard (hostname → origin → DNS verify → done), policy editor, rule editor, attack log with one-click exclusion, metrics charts.
- **Accept:** a new user protects a test domain in < 5 minutes without docs.

### Phase 6 — Logs, metrics, billing
- `waf-ingest` → ClickHouse tables `waf_events`, `waf_requests_1m`; metering export to console-api billing.
- **Accept:** request counts in console match proxy counters within 0.5%; 30-day retention enforced.

### Phase 7 — Origin lockdown + hardening
- Security-group lockdown job, rate limits, geo deny.
- **Accept:** direct-to-origin requests fail after lockdown; rate limit enforced within 5% of configured value.

### Phase 8 — Dedicated mode
- Provisioning job, product tier, node ownership in service project.
- **Accept:** dedicated WAF active within 10 minutes of order; teardown leaves no orphan ports/IPs.

## 13. Observability

- Prometheus metrics: `waf_requests_total{site,action}`, `waf_rule_hits_total{site,rule_id}`, `waf_upstream_latency_seconds`, `waf_config_revision{site}`, `waf_agent_apply_failures_total`.
- Alerts: node offline, apply failures > 0 for 5 min, cert expiring < 14 d with renewal failing, origin 5xx rate > 20%.
- Every audit event carries `event_id`, shown to blocked users so support can look it up.

## 14. Security

- WAF nodes accept management traffic only on the management network.
- NATS: per-node credentials scoped to its own subjects (publish heartbeat/ack/events, subscribe own config).
- `raw` SecLang rules are admin-only; customer rules are compiled from typed specs only (no injection into SecLang).
- Hostname ownership must be verified (DNS TXT) before a site goes active — prevents hijacking someone else's domain on the shared edge.
- Audit log of all control-plane mutations (who, what, when).

## 15. Testing strategy

| Layer | Tooling |
|---|---|
| Proxy/engine | Go unit tests, `go-ftw` with CRS tests, fuzzing on SecLang generator |
| Control plane | Vitest/Jest + Supertest, test Postgres via Docker |
| Distribution | Integration test with embedded NATS server + 2 agents |
| End-to-end | Staging region: console → create site → curl attack payloads → assert event appears |
| Load | `k6` or `vegeta` against edge node, with and without PL2 |

## 16. Open questions

1. Rate-limit state sharing across edge nodes: NATS KV vs Redis?
2. Barbican vs our own encrypted storage for keys?
3. Pricing unit: per site, per million requests, or per GB?
4. Do we support wildcard hostnames in v1?
5. GeoIP database source and license (MaxMind GeoLite2 vs DB-IP)?

## 17. Repository layout (proposed)

```
slave/src/modules/waf/
  sites/        sites.controller.ts  sites.service.ts  sites.schema.ts
  origins/      …
  policies/     …
  rules/        …  rules.compiler.ts   # spec → SecLang
  certificates/ …
  auth/         keystone.middleware.ts
slave/src/workers/jobs/waf.job.ts       # compile, cert issue/renew, lockdown, provision
slave/src/db/schema/waf.ts              # Drizzle tables

waf-node/                               # new Go repo
  cmd/waf-proxy/
  cmd/waf-lint/
  internal/proxy/  internal/agent/  internal/coraza/  internal/tls/  internal/ratelimit/
  packer/
  ftw/

console/app/console/services/waf/       # UI pages
console/app/api/waf/                    # route handlers → console-api
```
