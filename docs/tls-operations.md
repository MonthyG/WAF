# TLS development and operator setup

The agent serves HTTP and optional HTTPS with per-domain SNI certificates. Private keys are encrypted at rest with AES-256-GCM and delivered as RSA-OAEP-SHA256/AES-256-GCM envelopes unique to each node. Envelopes authenticate the site ID and revision. Invalid updates preserve the last good configuration. Public certificate chains are included; plaintext private keys are never persisted in configuration bundles.

## Local validation

Follow the root README setup, then run `npm test`. The ACME integration test launches the pinned official Pebble image with a temporary CA certificate, isolated database, Redis, NATS, and a real Go agent. It verifies HTTP-01, trusted HTTPS, one-hour certificates, renewal with HTTPS redirect enabled, and challenge cleanup. CA challenge verification and TLS verification remain enabled. The test uses Linux Docker host networking for Pebble; other services use isolated loopback ports. Logs are in ignored `.local/acme-test.log`; they are development diagnostics, not production telemetry.

## Register an edge node

Generate the private key **on the edge node** and keep it readable only by the agent:

```bash
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out node-key.pem
openssl pkey -in node-key.pem -pubout -out node-public.pem
```

Transfer only `node-public.pem` to the control-plane operator. From the repository root, with `DATABASE_URL` and `WAF_REGION` configured:

```bash
npm run node:register -- --public-key /path/to/node-public.pem \
  --public-ip 203.0.113.10 --mgmt-ip 10.0.0.10
```

Replace example addresses with your real node addresses. Save the UUID printed by the command; `--node-id UUID` makes identical registration repeatable. This administrative CLI uses database credentials and must not be exposed to tenants.

Run the edge agent with that UUID, the private key, and its own NATS credential file:

```bash
waf-node/bin/waf-agent -node-id UUID \
  -nats tls://nats.example.com:4222 -credentials /path/to/node.creds \
  -node-key /path/to/node-key.pem \
  -listen 0.0.0.0:80 -tls-listen 0.0.0.0:443 \
  -management 127.0.0.1:9090
```

Binding privileged ports requires a service manager/socket setup or a narrowly scoped `CAP_NET_BIND_SERVICE` capability. For local tests use ports 8080/8443. Management endpoints remain loopback-only.

NATS access must be provisioned per node: publish `waf.node.heartbeat.UUID`, `waf.node.ack.UUID`, and request `waf.config.snapshot.UUID`; receive only its own config/durable consumer and private reply inbox. Configure the necessary JetStream API/ACK permissions for that node's durable consumer. The development Compose NATS instance has no authentication and must remain local. Production NATS account/permission provisioning is not automated yet.

## API and worker

The API requires `DATABASE_URL`, `WAF_MASTER_KEY` (base64 encoding of exactly 32 random bytes), `WAF_DNS_TARGET`, `KEYSTONE_URL`, and `KEYSTONE_SERVICE_TOKEN`. The worker requires the same database/master key/region plus `REDIS_URL`, `NATS_URL`, and `NATS_CREDENTIALS` for remote NATS. Preserve the master key securely across restarts; changing it prevents decryption of existing certificate and ACME account keys.

Run `npm run dev:api` and `npm run worker` as separate processes. Certificate uploads work without ACME configuration. To enable ACME, configure:

```text
ACME_DIRECTORY_URL=https://acme-staging-v02.api.letsencrypt.org/directory
ACME_EMAIL=your-real-operator-email
ACME_TERMS_AGREED=true
```

Set the terms flag only after accepting the CA's terms. Without ACME configuration, issuance jobs remain pending. Keep staging and production databases/accounts separate while testing. Staging certificates are intentionally not browser-trusted.

The API accepts `tls: {"source":"acme"}` when creating a site. Verify the returned DNS TXT record, and route the hostname's A/AAAA records (or CNAME target) to the assigned edge nodes. Port 80 must reach the agent on **every assigned node**. Ownership verification queues issuance automatically. A site stays provisioning until its certificate is ready and every assigned node has applied the configuration.

Alternatively, upload using `POST /v1/waf/certificates` with `source`, `domains`, `cert_pem`, and `key_pem`, then attach `certificate_id` using `PATCH /v1/waf/sites/:id`. Never put private keys or Keystone tokens into shell command arguments or source control. Set `http_redirect: true` after a valid certificate is attached. Redirects retain path/query and use standard HTTPS port 443.

## Renewal and diagnostics

The worker checks hourly for certificates expiring within 30 days and schedules renewal. Failed issuance gets three queue attempts with exponential backoff; existing certificate material is retained. Pending job deduplication prevents the hourly scheduler from multiplying outstanding renewal jobs. Exhausted jobs are marked error; due certificates are reconsidered at the next hourly sweep. Initial issuance without any certificate needs operator investigation/retry after exhausted attempts.

HTTP-01 tokens are delivered only for verified sites, expire after 15 minutes, and bypass both WAF inspection and HTTPS redirect. Expired/unknown tokens return 404. Private keys and CA response bodies are omitted from error messages. ACME account keys are encrypted at rest.

Recorded local results: `docs/validation/acme.json` and `docs/validation/distribution.json`. Public Let's Encrypt staging issuance has not been tested; that requires your domain, public routing, and an operator email/terms agreement. Certificate delivery does not replace production NATS authorization, durable secret storage, monitoring, or the remaining design phases.
