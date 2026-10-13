import postgres from 'postgres';
import Redis from 'ioredis';
import { connect as connectNATS } from 'nats';
let failed = false;
const db = postgres(process.env.DATABASE_URL ?? '', { max: 1, connect_timeout: 5 });
try {
  if (!process.env.DATABASE_URL) throw new Error('missing_url');
  await db`select 1`;
  console.log('PASS PostgreSQL: authenticated query succeeded');
} catch (error) {
  failed = true;
  if (error.code === '28P01') {
    console.error('FAIL PostgreSQL: stored database password does not match .local/dev.env.');
    console.error(
      'A deleted/re-cloned checkout can leave old Docker volumes behind. Restore the matching env backup, or use the documented isolated fresh-start procedure. No volumes have been deleted.',
    );
  } else {
    console.error(
      'FAIL PostgreSQL: connection unavailable. Check service health, DATABASE_URL and WAF_POSTGRES_PORT.',
    );
  }
} finally {
  await db.end({ timeout: 2 });
}
if (!process.argv.includes('--database-only')) {
  const redis = new Redis(process.env.REDIS_URL, {
    lazyConnect: true,
    enableOfflineQueue: false,
    connectTimeout: 5000,
    retryStrategy: () => null,
  });
  redis.on('error', () => {});
  try {
    await redis.connect();
    if ((await redis.ping()) !== 'PONG') throw new Error('unavailable');
    console.log('PASS Redis: PING succeeded');
  } catch {
    failed = true;
    console.error('FAIL Redis: check service health, REDIS_URL and WAF_REDIS_PORT.');
  } finally {
    redis.disconnect();
  }
  try {
    const nats = await connectNATS({
      servers: process.env.NATS_URL,
      timeout: 5000,
      maxReconnectAttempts: 0,
    });
    try {
      await nats.jetstreamManager();
      console.log('PASS NATS: JetStream is available');
    } finally {
      await nats.close();
    }
  } catch {
    failed = true;
    console.error('FAIL NATS: check service health, JetStream, NATS_URL and WAF_NATS_PORT.');
  }

  try {
    const url = new URL(process.env.CLICKHOUSE_URL);
    url.searchParams.set('query', 'SELECT 1');
    const response = await fetch(url, {
      method: 'POST',
      redirect: 'error',
      signal: AbortSignal.timeout(5000),
      headers: {
        Authorization:
          'Basic ' +
          Buffer.from(`${process.env.CLICKHOUSE_USER}:${process.env.CLICKHOUSE_PASSWORD}`).toString(
            'base64',
          ),
      },
    });
    if (!response.ok || (await response.text()).trim() !== '1') throw new Error('unavailable');
    console.log('PASS ClickHouse: authenticated query succeeded');
  } catch {
    failed = true;
    console.error(
      'FAIL ClickHouse: check service health, CLICKHOUSE_URL/password and WAF_CLICKHOUSE_PORT.',
    );
  }
}
if (failed) {
  console.error(
    'Fix these prerequisites before migrations or integration tests. See docs/local-development.md.',
  );
  process.exitCode = 1;
}
