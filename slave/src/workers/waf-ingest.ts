import {
  connect,
  JSONCodec,
  RetentionPolicy,
  StorageType,
  nanos,
  AckPolicy,
  DeliverPolicy,
  credsAuthenticator,
  type JsMsg,
} from 'nats';
import { readFile } from 'node:fs/promises';
import { and, eq, inArray } from 'drizzle-orm';
import { z } from 'zod';
import type { DB } from '../db/index.js';
import * as s from '../db/schema.js';
import { ClickHouse } from '../modules/waf/analytics/clickhouse.js';

const observation = z
  .object({
    event_id: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
    site_id: z.string().uuid(),
    timestamp: z.string().datetime({ offset: true }),
    action: z.enum(['allowed', 'blocked', 'detected', 'error', 'rejected']),
    method: z.string().max(32),
    path: z.string().max(2048).optional().default(''),
    client_ip: z.string().max(64).optional().default(''),
    rule_ids: z.array(z.number().int().positive()).max(1000).optional().default([]),
    status: z.number().int().min(100).max(599),
    bytes_out: z.number().int().nonnegative().safe(),
    duration_ms: z.number().nonnegative().finite(),
  })
  .strict();
const batchSchema = z
  .object({
    batch_id: z.string().regex(/^[0-9a-f]{32}$/),
    node_id: z.string().uuid(),
    requests: z.array(observation).min(1).max(128),
  })
  .strict();
const codec = JSONCodec();
export class InvalidTelemetry extends Error {}
export async function ingestBatch(db: DB, ch: ClickHouse, subject: string, data: unknown) {
  const parsed = batchSchema.safeParse(data);
  if (!parsed.success) throw new InvalidTelemetry('Invalid batch schema');
  const batch = parsed.data;
  if (subject !== `waf.events.${batch.node_id}`)
    throw new InvalidTelemetry('Node identity does not match subject');
  const history = await db
    .select()
    .from(s.siteNodeHistory)
    .where(
      and(
        eq(s.siteNodeHistory.nodeId, batch.node_id),
        inArray(s.siteNodeHistory.siteId, [...new Set(batch.requests.map((r) => r.site_id))]),
      ),
    );
  const owned = new Map(history.map((h) => [h.siteId, h]));
  const events: unknown[] = [];
  const minutes = new Map<
    string,
    {
      project_id: string;
      region_id: string;
      site_id: string;
      node_id: string;
      batch_id: string;
      minute: string;
      action: string;
      requests: number;
      bytes_out: number;
      duration_ms: number;
    }
  >();
  for (const request of batch.requests) {
    const owner = owned.get(request.site_id);
    if (!owner) throw new InvalidTelemetry('Site was never assigned to node');
    const time = Date.parse(request.timestamp);
    if (time > Date.now() + 300000) throw new InvalidTelemetry('Timestamp is in the future');
    if (time < Date.now() - 30 * 86400000) continue;
    const scope = {
      project_id: owner.projectId,
      region_id: owner.regionId,
      site_id: request.site_id,
      node_id: batch.node_id,
    };
    if (request.rule_ids.length)
      events.push({
        ...scope,
        event_id: request.event_id,
        timestamp: request.timestamp,
        action: request.action,
        method: request.method,
        path: request.path,
        client_ip: request.client_ip,
        rule_ids: request.rule_ids,
        status: request.status,
        duration_ms: request.duration_ms,
      });
    const minute = new Date(Math.floor(time / 60000) * 60000).toISOString(),
      key = [request.site_id, minute, request.action].join(':');
    const total = minutes.get(key) ?? {
      ...scope,
      batch_id: batch.batch_id,
      minute,
      action: request.action,
      requests: 0,
      bytes_out: 0,
      duration_ms: 0,
    };
    total.requests++;
    total.bytes_out += request.bytes_out;
    total.duration_ms += request.duration_ms;
    minutes.set(key, total);
  }
  // ReplacingMergeTree + FINAL reads make re-delivery idempotent across either
  // insertion failing. The batch ID remains stable in the agent's disk spool.
  await ch.insert('waf_events', events);
  await ch.insert('waf_requests_1m', [...minutes.values()]);
}

export async function startIngest(
  db: DB,
  ch: ClickHouse,
  options: { natsURL: string; natsCredentials?: string },
) {
  const credentials = options.natsCredentials ? await readFile(options.natsCredentials) : undefined;
  if (
    !credentials &&
    !['127.0.0.1', 'localhost', '[::1]'].includes(new URL(options.natsURL).hostname)
  )
    throw new Error('Remote NATS requires credentials');
  await ch.migrate();
  const nc = await connect({
    servers: options.natsURL,
    ...(credentials ? { authenticator: credsAuthenticator(credentials) } : {}),
    name: 'waf-ingest',
    maxReconnectAttempts: -1,
  });
  const jsm = await nc.jetstreamManager();
  try {
    await jsm.streams.info('WAF_EVENTS');
  } catch (err) {
    if ((err as { code?: string }).code !== '404') throw err;
    await jsm.streams.add({
      name: 'WAF_EVENTS',
      subjects: ['waf.events.*'],
      retention: RetentionPolicy.Workqueue,
      storage: StorageType.File,
      max_age: nanos(24 * 3600000),
      max_bytes: 1024 * 1024 * 1024,
      duplicate_window: nanos(120000),
    });
  }
  try {
    await jsm.consumers.info('WAF_EVENTS', 'waf-ingest');
  } catch (err) {
    if ((err as { code?: string }).code !== '404') throw err;
    await jsm.consumers.add('WAF_EVENTS', {
      durable_name: 'waf-ingest',
      ack_policy: AckPolicy.Explicit,
      deliver_policy: DeliverPolicy.All,
      filter_subject: 'waf.events.*',
      ack_wait: nanos(60000),
      max_ack_pending: 32,
    });
  }
  const consumer = await nc.jetstream().consumers.get('WAF_EVENTS', 'waf-ingest');
  let stopping = false;
  const task = (async () => {
    while (!stopping) {
      let message: JsMsg | null = null;
      try {
        message = await consumer.next({ expires: 1000 });
        if (!message) continue;
        let data: unknown;
        try {
          data = codec.decode(message.data);
        } catch {
          throw new InvalidTelemetry('Invalid JSON');
        }
        await ingestBatch(db, ch, message.subject, data);
        message.ack();
      } catch (err) {
        if (stopping) break;
        if (err instanceof InvalidTelemetry) {
          message?.term(err.message);
          console.error('Rejected invalid telemetry batch');
        } else {
          message?.nak(1000);
          console.error('Telemetry ingestion unavailable; delivery will retry');
          await new Promise((r) => setTimeout(r, 250));
        }
      }
    }
  })();
  return {
    nc,
    async close() {
      stopping = true;
      await task;
      await nc.drain();
    },
  };
}
