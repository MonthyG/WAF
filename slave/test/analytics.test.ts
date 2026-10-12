import { it, expect } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { createServer as tcpServer } from 'node:net';
import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdir, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { eq, sql } from 'drizzle-orm';
import request from 'supertest';
import { JSONCodec } from 'nats';
import { connect } from '../src/db/index.js';
import { migrateDatabase } from '../src/db/migrate.js';
import * as s from '../src/db/schema.js';
import { WafService } from '../src/modules/waf/waf.service.js';
import { startWorker } from '../src/workers/waf-worker.js';
import { startIngest, ingestBatch, InvalidTelemetry } from '../src/workers/waf-ingest.js';
import { ClickHouse } from '../src/modules/waf/analytics/clickhouse.js';
import {
  AnalyticsService,
  eventsQuery,
  rangeQuery,
} from '../src/modules/waf/analytics/analytics.service.js';
import { siteInput } from '../src/modules/waf/validation.js';
import { lintRaw } from '../src/modules/waf/rules/lint.js';
import { createApp } from '../src/app.js';

async function waitFor<T>(
  fn: () => Promise<T>,
  check: (v: T) => boolean,
  timeout = 15000,
): Promise<T> {
  const until = Date.now() + timeout;
  let last: unknown;
  while (Date.now() < until) {
    try {
      const value = await fn();
      last = value;
      if (check(value)) return value;
    } catch (e) {
      last = e;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('Condition timed out: ' + JSON.stringify(last));
}
async function port() {
  const server = tcpServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('port');
  await new Promise<void>((r) => server.close(() => r()));
  return address.port;
}

it('ingests real edge traffic exactly once, isolates tenants, excludes events, and exports metering with 30-day TTL', async () => {
  const base = process.env.DATABASE_URL;
  if (!base) throw new Error('DATABASE_URL required');
  const admin = connect(base),
    dbName = 'waf_analytics_' + randomBytes(8).toString('hex');
  const temp = await mkdtemp(resolve(tmpdir(), 'waf-analytics-'));
  const containers: string[] = [];
  let agent: ChildProcess | undefined,
    db: ReturnType<typeof connect> | undefined,
    worker: Awaited<ReturnType<typeof startWorker>> | undefined,
    ingest: Awaited<ReturnType<typeof startIngest>> | undefined;
  const project = randomUUID(),
    otherProject = randomUUID(),
    node = randomUUID(),
    serviceToken = randomBytes(24).toString('hex'),
    txt = new Map<string, string[][]>();
  const origin = createServer((_req, res) => {
    res.setHeader('Content-Type', 'text/plain');
    res.end('origin');
  });
  const identity = createServer((req, res) => {
    const token = req.headers['x-subject-token'];
    if (
      req.headers['x-auth-token'] !== serviceToken ||
      !['owner', 'other'].includes(String(token))
    ) {
      res.writeHead(401).end();
      return;
    }
    res.setHeader('Content-Type', 'application/json');
    res.end(
      JSON.stringify({
        token: {
          expires_at: new Date(Date.now() + 60000).toISOString(),
          user: { id: 'test' },
          project: { id: token === 'owner' ? project : otherProject },
          roles: [{ name: 'member' }],
        },
      }),
    );
  });
  try {
    const container = (image: string, inside: number, args: string[], env: string[] = []) => {
      const id = execFileSync(
        'docker',
        [
          'run',
          '--rm',
          '-d',
          ...env.flatMap((v) => ['-e', v]),
          '-p',
          `127.0.0.1::${inside}`,
          image,
          ...args,
        ],
        { encoding: 'utf8' },
      ).trim();
      containers.push(id);
      return execFileSync('docker', ['port', id, String(inside)], { encoding: 'utf8' }).trim();
    };
    const password = randomBytes(24).toString('hex');
    const clickhouse = container(
      'clickhouse/clickhouse-server:25.8@sha256:0152dd511befe6a2c2ef53e930726179669b08116da78500b37c51c96ff5ee77',
      8123,
      [],
      ['CLICKHOUSE_USER=waf', 'CLICKHOUSE_PASSWORD=' + password],
    );
    const ch = new ClickHouse({ url: 'http://' + clickhouse, username: 'waf', password });
    await waitFor(
      () => ch.execute('SELECT 1', {}, undefined, true),
      (v) => v.trim() === '1',
      45000,
    );
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
    await admin.db.execute(sql`CREATE DATABASE ${sql.identifier(dbName)}`);
    const url = new URL(base);
    url.pathname = '/' + dbName;
    await migrateDatabase(url.toString());
    db = connect(url.toString());
    await db.db
      .insert(s.nodes)
      .values({
        id: node,
        regionId: 'local-1',
        kind: 'edge',
        publicIp: '127.0.0.1',
        mgmtIp: '127.0.0.1',
        version: 'test',
      });
    ingest = await startIngest(db.db, ch, { natsURL: 'nats://' + nats });
    worker = await startWorker(db.db, {
      redisURL: 'redis://' + redis,
      natsURL: 'nats://' + nats,
      region: 'local-1',
      lintBinary: resolve('../waf-node/bin/waf-lint'),
      queueName: 'analytics-' + randomBytes(4).toString('hex'),
    });
    const traffic = await port(),
      management = await port();
    agent = spawn(
      resolve('../waf-node/bin/waf-agent'),
      [
        '-node-id',
        node,
        '-nats',
        'nats://' + nats,
        '-listen',
        `127.0.0.1:${traffic}`,
        '-management',
        `127.0.0.1:${management}`,
        '-state-dir',
        temp,
      ],
      { stdio: 'ignore' },
    );
    await waitFor(
      () => db!.db.select().from(s.nodes),
      (rows) => rows[0]?.status === 'online',
    );
    origin.listen(0, '127.0.0.1');
    await once(origin, 'listening');
    identity.listen(0, '127.0.0.1');
    await once(identity, 'listening');
    const oa = origin.address(),
      ia = identity.address();
    if (!oa || typeof oa === 'string' || !ia || typeof ia === 'string')
      throw new Error('fixture addresses');
    const analytics = new AnalyticsService(ch, 'local-1'),
      ctx = { projectId: project, userId: 'test', roles: ['member'] };
    const svc = new WafService(db.db, {
      region: 'local-1',
      dnsTarget: 'edge.localhost',
      masterKey: randomBytes(32),
      resolveTxt: async (name) => txt.get(name) ?? [],
      lint: lintRaw(resolve('../waf-node/bin/waf-lint')),
      analytics,
    });
    const app = createApp(svc, {
      url: `http://127.0.0.1:${ia.port}`,
      serviceToken: async () => serviceToken,
    });
    const site = await svc.createSite(
      ctx,
      siteInput.parse({
        hostname: 'shop.localhost',
        policy: { engine_mode: 'block' },
        origins: [{ address: '127.0.0.1', port: oa.port, scheme: 'http' }],
      }),
    );
    const id = String(site.id),
      verification = site.verification as { name: string; value: string };
    txt.set(verification.name, [[verification.value]]);
    await svc.verifySite(ctx, id);
    await waitFor(
      () => svc.getSite(ctx, id),
      (v) => v.status === 'active',
    );
    const hit = (path: string) =>
      new Promise<number>((resolve, reject) => {
        const req = httpRequest(
          {
            hostname: '127.0.0.1',
            port: traffic,
            path,
            headers: { Host: 'shop.localhost', 'User-Agent': 'WAF analytics test' },
          },
          (res) => {
            res.resume();
            res.on('end', () => resolve(res.statusCode!));
          },
        );
        req.on('error', reject);
        req.end();
      });
    for (let i = 0; i < 200; i++)
      expect(await hit('/catalog?access_token=private-query')).toBe(200);
    const attack = '/search?q=' + encodeURIComponent('<script>alert(1)</script>');
    for (let i = 0; i < 5; i++) expect(await hit(attack)).toBe(403);
    const metrics = await waitFor(
      () => analytics.metrics(project, id, {}),
      (v) => v.totals.requests === 205,
      20000,
    );
    expect(metrics.totals.blocked).toBe(5);
    expect(metrics.totals.detected).toBe(0);
    const prometheus = await (await fetch(`http://127.0.0.1:${management}/metrics`)).text();
    const counted = [...prometheus.matchAll(/waf_requests_total\{[^\n]+\} (\d+)/g)].reduce(
      (n, m) => n + Number(m[1]),
      0,
    );
    expect(counted).toBe(metrics.totals.requests);
    expect(prometheus).toContain('waf_telemetry_dropped_total 0');
    const events = await analytics.events(project, id, eventsQuery.parse({ limit: 2 }));
    expect(events.events).toHaveLength(2);
    expect(events.next_cursor).toBeTruthy();
    expect(JSON.stringify(events)).not.toContain('private-query');
    expect(events.events.every((e) => e.path === '/search' && e.action === 'blocked')).toBe(true);
    const next = await analytics.events(
      project,
      id,
      eventsQuery.parse({ limit: 10, cursor: events.next_cursor }),
    );
    expect(next.events).toHaveLength(3);
    for (const endpoint of ['events', 'metrics'])
      expect(
        (await request(app).get(`/v1/waf/sites/${id}/${endpoint}`).set('X-Auth-Token', 'other'))
          .status,
      ).toBe(404);
    expect(
      (await request(app).get(`/v1/waf/sites/${id}/metrics`).set('X-Auth-Token', 'owner')).body
        .totals.requests,
    ).toBe(205);
    const event = events.events[0];
    const ruleIDs = event.rule_ids.filter((n) => n >= 941000 && n < 942000);
    expect(ruleIDs.length).toBeGreaterThan(0);
    const excluded = await request(app)
      .post(`/v1/waf/sites/${id}/events/${event.event_id}/exclude`)
      .set('X-Auth-Token', 'owner')
      .send({ rule_ids: ruleIDs, path_prefix: '/search' });
    expect(excluded.status, excluded.text).toBe(201);
    await waitFor(
      () => svc.getSite(ctx, id),
      (v) => v.config_revision === v.applied_revision,
    );
    expect(await hit(attack)).toBe(200);
    expect(await hit('/other?q=' + encodeURIComponent('<script>alert(1)</script>'))).toBe(403);
    // Replay a complete identical batch with a different JetStream message ID.
    const synthetic = {
      batch_id: randomBytes(16).toString('hex'),
      node_id: node,
      requests: [
        {
          event_id: 'replay-test',
          site_id: id,
          timestamp: new Date().toISOString(),
          action: 'allowed',
          method: 'GET',
          status: 200,
          bytes_out: 6,
          duration_ms: 1,
        },
      ],
    };
    await ingestBatch(db.db, ch, `waf.events.${node}`, synthetic);
    await ingestBatch(db.db, ch, `waf.events.${node}`, synthetic);
    const total = await waitFor(
      () => analytics.metrics(project, id, {}),
      (v) => v.totals.requests === 208,
      20000,
    );
    expect(total.totals.requests).toBe(208);
    await expect(
      ingestBatch(db.db, ch, `waf.events.${randomUUID()}`, synthetic),
    ).rejects.toBeInstanceOf(InvalidTelemetry);
    await expect(
      ingestBatch(db.db, ch, `waf.events.${node}`, {
        ...synthetic,
        requests: [{ ...synthetic.requests[0], site_id: randomUUID() }],
      }),
    ).rejects.toBeInstanceOf(InvalidTelemetry);
    const from = new Date(Math.floor((Date.now() - 3600000) / 60000) * 60000).toISOString(),
      to = new Date(Math.ceil(Date.now() / 60000) * 60000).toISOString();
    const usage = await analytics.usage(project, rangeQuery.parse({ from, to }));
    expect(usage.requests).toBe(208);
    expect(
      (await request(app).get('/v1/waf/usage').query({ from, to }).set('X-Auth-Token', 'other'))
        .body.requests,
    ).toBe(0);
    const definitions = await ch.rows<{ statement: string }>('SHOW CREATE TABLE waf_events');
    expect(definitions[0].statement).toContain('toIntervalDay(30)');
    await ch.insert('waf_events', [
      {
        ...event,
        event_id: 'expired',
        timestamp: new Date(Date.now() - 31 * 86400000).toISOString(),
      },
    ]);
    await ch.execute('ALTER TABLE waf_events MATERIALIZE TTL SETTINGS mutations_sync=1');
    expect(
      await ch.rows("SELECT event_id FROM waf_events FINAL WHERE event_id='expired'"),
    ).toHaveLength(0);
    await mkdir('../docs/validation', { recursive: true });
    await writeFile(
      '../docs/validation/analytics.json',
      JSON.stringify(
        {
          recorded_at: new Date().toISOString(),
          real_clickhouse: true,
          edge_requests: 205,
          recorded_requests: 205,
          count_difference_percent: 0,
          attack_events: 5,
          duplicate_batch_counted_once: true,
          tenant_isolation: true,
          event_exclusion_verified: true,
          metering_export_verified: true,
          retention_days: 30,
          ttl_expiration_verified: true,
        },
        null,
        2,
      ) + '\n',
    );
  } finally {
    if (agent && agent.exitCode === null && agent.signalCode === null) {
      agent.kill('SIGTERM');
      await Promise.race([once(agent, 'exit'), new Promise((r) => setTimeout(r, 4000))]);
      if (agent.exitCode === null && agent.signalCode === null) agent.kill('SIGKILL');
    }
    if (ingest) await ingest.close();
    if (worker) await worker.close();
    await Promise.all(
      [origin, identity].map((server) => new Promise<void>((r) => server.close(() => r()))),
    );
    if (db) await db.close();
    for (const id of containers)
      try {
        execFileSync('docker', ['stop', '-t', '1', id], { stdio: 'ignore' });
      } catch {}
    await admin.db.execute(sql`DROP DATABASE IF EXISTS ${sql.identifier(dbName)}`);
    await admin.close();
    await rm(temp, { recursive: true, force: true });
  }
}, 150000);
