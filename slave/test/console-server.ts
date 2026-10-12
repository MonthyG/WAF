import { ClickHouse } from '../src/modules/waf/analytics/clickhouse.js';
import { AnalyticsService } from '../src/modules/waf/analytics/analytics.service.js';
import { startIngest } from '../src/workers/waf-ingest.js';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
// Explicitly launched by Playwright only; never imported by the production API.
import { createServer } from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { resolve } from 'node:path';
import { sql } from 'drizzle-orm';
import { connect } from '../src/db/index.js';
import { migrateDatabase } from '../src/db/migrate.js';
import * as s from '../src/db/schema.js';
import { createApp } from '../src/app.js';
import { WafService } from '../src/modules/waf/waf.service.js';
import { lintRaw } from '../src/modules/waf/rules/lint.js';
import { startWorker } from '../src/workers/waf-worker.js';

if (process.env.WAF_CONSOLE_TEST !== 'true')
  throw new Error('This fixture requires WAF_CONSOLE_TEST=true');
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL required');
const admin = connect(process.env.DATABASE_URL),
  dbName = 'waf_console_' + randomBytes(8).toString('hex');
await admin.db.execute(sql`CREATE DATABASE ${sql.identifier(dbName)}`);
const url = new URL(process.env.DATABASE_URL);
url.pathname = '/' + dbName;
await migrateDatabase(url.toString());
const conn = connect(url.toString());
const containers: string[] = [];
const container = (image: string, port: number, args: string[], env: string[] = []) => {
  const id = execFileSync(
    'docker',
    [
      'run',
      '--rm',
      '-d',
      ...env.flatMap((v) => ['-e', v]),
      '-p',
      `127.0.0.1::${port}`,
      image,
      ...args,
    ],
    { encoding: 'utf8' },
  ).trim();
  containers.push(id);
  return execFileSync('docker', ['port', id, String(port)], { encoding: 'utf8' }).trim();
};
const nats = container(
  'nats:2.11.8-alpine@sha256:71092f77d707a4a81b12aca5096d6b2d2e07ad16aa57c84066940a17af74f61a',
  4222,
  ['-js'],
);
const redis = container(
  'redis:8.2.2-alpine@sha256:59b6e694653476de2c992937ebe1c64182af4728e54bb49e9b7a6c26614d8933',
  6379,
  [],
);
const chPassword = randomBytes(24).toString('hex');
const chAddress = container(
  'clickhouse/clickhouse-server:25.8@sha256:0152dd511befe6a2c2ef53e930726179669b08116da78500b37c51c96ff5ee77',
  8123,
  [],
  ['CLICKHOUSE_USER=waf', 'CLICKHOUSE_PASSWORD=' + chPassword],
);
const ch = new ClickHouse({ url: 'http://' + chAddress, username: 'waf', password: chPassword });
for (let attempt = 0; attempt < 100; attempt++) {
  try {
    await ch.execute('SELECT 1', {}, undefined, true);
    break;
  } catch {
    if (attempt === 99) throw new Error('ClickHouse did not start');
    await new Promise((r) => setTimeout(r, 300));
  }
}
const ingestion = await startIngest(conn.db, ch, { natsURL: 'nats://' + nats });
const telemetryDirectory = await mkdtemp(resolve(tmpdir(), 'waf-console-telemetry-'));
const nodeId = randomUUID(),
  projectId = randomUUID(),
  otherProject = randomUUID(),
  serviceToken = randomBytes(24).toString('hex');
await conn.db.insert(s.nodes).values({
  id: nodeId,
  regionId: 'local-1',
  kind: 'edge',
  publicIp: '127.0.0.1',
  mgmtIp: '127.0.0.1',
  version: 'test',
});
const worker = await startWorker(conn.db, {
  redisURL: 'redis://' + redis,
  natsURL: 'nats://' + nats,
  region: 'local-1',
  lintBinary: resolve('../waf-node/bin/waf-lint'),
  queueName: 'console-' + randomBytes(4).toString('hex'),
});
const agent = spawn(
  resolve('../waf-node/bin/waf-agent'),
  [
    '-state-dir',
    telemetryDirectory,
    '-node-id',
    nodeId,
    '-nats',
    'nats://' + nats,
    '-listen',
    '127.0.0.1:19980',
    '-management',
    '127.0.0.1:19990',
  ],
  { stdio: 'ignore' },
);
const txt = new Map<string, string[][]>();
const identity = createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/test/dns') {
    let body = '';
    req.on('data', (b) => (body += b));
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        txt.set(data.name, [[data.value]]);
        res.writeHead(204).end();
      } catch {
        res.writeHead(400).end();
      }
    });
    return;
  }
  const token = req.headers['x-subject-token'];
  if (
    req.url !== '/v3/auth/tokens' ||
    req.headers['x-auth-token'] !== serviceToken ||
    !['console-e2e-project-token', 'console-e2e-other-token'].includes(String(token))
  ) {
    res.writeHead(401).end();
    return;
  }
  res.setHeader('Content-Type', 'application/json');
  res.end(
    JSON.stringify({
      token: {
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        user: { id: 'test-user' },
        project: { id: token === 'console-e2e-project-token' ? projectId : otherProject },
        roles: [{ name: 'member' }],
      },
    }),
  );
});
identity.listen(19902, '127.0.0.1');
await once(identity, 'listening');
const service = new WafService(conn.db, {
  region: 'local-1',
  analytics: new AnalyticsService(ch, 'local-1'),
  dnsTarget: 'edge.localhost',
  masterKey: randomBytes(32),
  resolveTxt: async (name) => txt.get(name) ?? [],
  lint: lintRaw(resolve('../waf-node/bin/waf-lint')),
});
const api = createApp(service, {
  url: 'http://127.0.0.1:19902',
  serviceToken: async () => serviceToken,
}).listen(19901, '127.0.0.1');
const origin = createServer((_req, res) => res.end('Your application is online'));
origin.listen(19903, '127.0.0.1');
let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  await Promise.all(
    [api, identity, origin].map((server) => new Promise<void>((r) => server.close(() => r()))),
  );
  agent.kill('SIGTERM');
  await Promise.race([once(agent, 'exit'), new Promise((r) => setTimeout(r, 2000))]);
  if (agent.exitCode === null) agent.kill('SIGKILL');
  await ingestion.close();
  await worker.close();
  await rm(telemetryDirectory, { recursive: true, force: true });
  await conn.close();
  for (const id of containers)
    try {
      execFileSync('docker', ['stop', '-t', '1', id], { stdio: 'ignore' });
    } catch {}
  await admin.db.execute(sql`DROP DATABASE ${sql.identifier(dbName)}`);
  await admin.close();
  process.exit(0);
}
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => void stop());
console.log('Console test API ready on loopback');
