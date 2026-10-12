# Analytics and metering

Run the normal README setup first. Compose starts a pinned ClickHouse server on loopback port 18123 with persistent storage and a locally generated password. `scripts/local-env.sh` preserves existing credentials and adds missing ClickHouse settings without printing them.

Source `.local/dev.env` in each terminal. Start `npm run ingest` alongside the API, configuration worker, and console. Ingestion creates the ClickHouse database/tables and the `WAF_EVENTS` JetStream stream. Configure `CLICKHOUSE_URL`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`, and optionally `CLICKHOUSE_DATABASE` on the API and ingest process. Use HTTPS for remote ClickHouse and authenticated NATS with appropriate subject permissions.

Start each registered edge agent with `-state-dir /private/path/unique-to-this-node`. Keep the same directory across restarts, private and writable by that node. Without this flag the node does not report analytics. Ingestion trusts PostgreSQL assignment history for project/region ownership, rejects unassigned sites and mismatched node subjects, and acknowledges messages after both event and aggregate inserts succeed. Assignment history remains after site deletion so delayed telemetry can be attributed. NATS must restrict each node to its own event subject; the subject alone is not authentication.

The console's Attack log supports time, action, rule ID and IP filters plus pagination. Event exclusions remove selected matched CRS rules for a path prefix, and affect every site sharing that policy; the confirmation explains this scope. Metrics shows recorded requests, blocked/detected counts, bytes, mean request duration, and one-minute series. An empty result means no matching data has arrived, not proof that collection is healthy. Redirects, ACME challenges, and requests rejected before site dispatch are excluded. A duration average is not a latency percentile.

API endpoints are documented in `docs/openapi.json`: `GET /sites/:id/events`, `GET /sites/:id/metrics`, `POST /sites/:id/events/:eventId/exclude`, and project-scoped `GET /usage`. All tenant queries include project and region. A missing ClickHouse configuration returns an explicit unavailable response.

Export usage with explicit half-open, UTC minute boundaries (replace the UUID and interval with your project and recent dates):

```bash
npm run meter -- --project-id PROJECT_UUID --from 2026-10-12T00:00:00Z --to 2026-10-12T01:00:00Z
```

This operator CLI reads ClickHouse directly and can export any project accessible to its database credentials; tenant clients must use the authenticated API. Output contains per-site and total request/byte counts. Repeated exports are read-only. Keep closed-window exports in the external billing system, allow for late delivery, and reconcile corrections before issuing invoices. No invoice generation, charging, or external console-api billing integration is implemented.

Both ClickHouse tables have 30-day TTLs; deletion occurs asynchronously during merges. Query intervals are limited to 30 days; older retained intervals can be empty after expiration. Stable batch IDs and `ReplacingMergeTree` with `FINAL` reads prevent retry duplicates from inflating counts, including partial insert retries. Attack records contain IP and bounded path/rule identifiers, but omit query strings, headers, cookies, matched values and bodies. Treat paths/IPs as sensitive; apply operator access controls and retention to backups too.

Collection is bounded, not a lossless billing ledger. The node buffers up to 10,000 observations, batches up to 128 or one second, and writes a private disk spool capped at 256 MiB. A hard crash can lose buffered observations. Queue or spool exhaustion drops observations and increments `waf_telemetry_dropped_total`; monitor this plus `waf_telemetry_publish_failures_total`, ingestion errors, disk capacity, and collection freshness. JetStream retains queued messages for at most 24 hours and 1 GiB; prolonged outages can expire data. The current consumer inserts serially and needs load/capacity testing before production billing.

`npm test` includes a real ClickHouse/NATS/edge integration test comparing recorded counts with edge counters, retry deduplication, pagination, tenant isolation, path-scoped exclusions, usage exports and TTL deletion. `npm run test:console` exercises real analytics through Chromium using test-only identity and simulated DNS. Evidence is under `docs/validation`; it does not establish production capacity or public deployment readiness.
