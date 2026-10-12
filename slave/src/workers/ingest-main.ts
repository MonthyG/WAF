import { connect } from '../db/index.js';
import { clickHouseFromEnv } from '../modules/waf/analytics/clickhouse.js';
import { startIngest } from './waf-ingest.js';
if (!process.env.DATABASE_URL || !process.env.NATS_URL)
  throw new Error('DATABASE_URL and NATS_URL are required');
const ch = clickHouseFromEnv();
if (!ch) throw new Error('CLICKHOUSE_URL is required');
const conn = connect(process.env.DATABASE_URL),
  worker = await startIngest(conn.db, ch, {
    natsURL: process.env.NATS_URL,
    natsCredentials: process.env.NATS_CREDENTIALS,
  });
console.log('WAF ingestion ready');
for (const signal of ['SIGINT', 'SIGTERM'] as const)
  process.once(signal, async () => {
    await worker.close();
    await conn.close();
    process.exit(0);
  });
