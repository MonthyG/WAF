import { clickHouseFromEnv } from './modules/waf/analytics/clickhouse.js';
import { AnalyticsService } from './modules/waf/analytics/analytics.service.js';
import { resolveTxt } from 'node:dns/promises';
import { createApp } from './app.js';
import { connect } from './db/index.js';
import { WafService } from './modules/waf/waf.service.js';
import { lintRaw } from './modules/waf/rules/lint.js';
import { fileURLToPath } from 'node:url';

function required(name: string) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}
const key = Buffer.from(required('WAF_MASTER_KEY'), 'base64');
if (key.length !== 32) throw new Error('WAF_MASTER_KEY must be a base64-encoded 32-byte key');
const conn = connect(required('DATABASE_URL'));
const clickhouse = clickHouseFromEnv();
const service = new WafService(conn.db, {
  region: process.env.WAF_REGION ?? 'local-1',
  analytics: clickhouse
    ? new AnalyticsService(clickhouse, process.env.WAF_REGION ?? 'local-1')
    : undefined,
  dnsTarget: required('WAF_DNS_TARGET'),
  masterKey: key,
  resolveTxt,
  lint: lintRaw(
    process.env.WAF_LINT_BINARY ??
      fileURLToPath(new URL('../../waf-node/bin/waf-lint', import.meta.url)),
  ),
});
const serviceToken = required('KEYSTONE_SERVICE_TOKEN');
const app = createApp(service, {
  url: required('KEYSTONE_URL'),
  serviceToken: async () => serviceToken,
});
const server = app.listen(
  Number(process.env.PORT ?? 9890),
  process.env.BIND_ADDRESS ?? '127.0.0.1',
  () => console.log('CloudInside WAF API listening'),
);
server.requestTimeout = 30000;
server.headersTimeout = 10000;
for (const signal of ['SIGINT', 'SIGTERM'] as const)
  process.once(signal, () => {
    server.close(async () => {
      await conn.close();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 30000).unref();
  });
