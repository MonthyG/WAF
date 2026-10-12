import { Queue, Worker } from 'bullmq';
import { Redis } from 'ioredis';
import {
  connect,
  JSONCodec,
  RetentionPolicy,
  StorageType,
  nanos,
  type NatsConnection,
  type Msg,
  credsAuthenticator,
} from 'nats';
import { readFile } from 'node:fs/promises';
import { and, eq, inArray, lt, ne, sql, gt } from 'drizzle-orm';
import { z } from 'zod';
import type { DB, Transaction } from '../db/index.js';
import * as s from '../db/schema.js';
import { compileBundle, type SiteBundle } from '../modules/waf/rules/rules.compiler.js';
import { lintCompiled } from '../modules/waf/rules/lint.js';

import { AcmeService, type AcmeOptions } from '../modules/waf/certificates/acme.service.js';
import {
  decryptKey,
  validateCertificate,
} from '../modules/waf/certificates/certificates.service.js';
import { sealForNode } from '../modules/waf/certificates/envelope.js';
const codec = JSONCodec();
const heartbeat = z.object({
  node_id: z.string().uuid(),
  version: z.string().max(128),
  load: z.number(),
  applied: z.record(z.number().int().nonnegative()),
});
const ackSchema = z.object({
  node_id: z.string().uuid(),
  site_id: z.string().uuid(),
  revision: z.number().int().positive(),
  ok: z.boolean(),
  error: z.string().max(512).optional(),
});
export type WorkerOptions = {
  redisURL: string;
  natsURL: string;
  natsCredentials?: string;
  region: string;
  lintBinary: string;
  queueName?: string;
  masterKey?: Buffer;
  acme?: Omit<AcmeOptions, 'masterKey' | 'region'>;
};
const lock = async (tx: Transaction) => {
  await tx.execute(sql`select pg_advisory_xact_lock(963281)`);
};

export async function startWorker(db: DB, o: WorkerOptions) {
  if (o.masterKey && o.masterKey.length !== 32) throw new Error('Master key must contain 32 bytes');
  if (o.acme && !o.masterKey) throw new Error('ACME requires a master key');
  const creds = o.natsCredentials ? await readFile(o.natsCredentials) : undefined;
  const host = new URL(o.natsURL).hostname;
  if (!creds && !['127.0.0.1', '[::1]', 'localhost'].includes(host))
    throw new Error('Non-loopback NATS requires credentials');
  const nc = await connect({
    servers: o.natsURL,
    ...(creds ? { authenticator: credsAuthenticator(creds) } : {}),
    name: 'waf-control',
    maxReconnectAttempts: -1,
  });
  const jsm = await nc.jetstreamManager();
  try {
    await jsm.streams.info('WAF_CONFIG');
  } catch (err) {
    if ((err as { code?: string }).code !== '404') throw err;
    await jsm.streams.add({
      name: 'WAF_CONFIG',
      subjects: ['waf.config.*'],
      retention: RetentionPolicy.Workqueue,
      storage: StorageType.File,
      max_age: nanos(7 * 24 * 3600 * 1000),
    });
  }
  const js = nc.jetstream();
  const redis = new Redis(o.redisURL, { maxRetriesPerRequest: null });
  const queueName = o.queueName ?? `waf-compile-${o.region}`;
  const queue = new Queue(queueName, { connection: redis });
  const acmeService =
    o.acme && o.masterKey
      ? new AcmeService(db, { ...o.acme, masterKey: o.masterKey, region: o.region })
      : undefined;
  const certQueue = acmeService
    ? new Queue(queueName + '-certificates', { connection: redis })
    : undefined;
  let stopping = false,
    pumping = false;
  const tasks: Promise<unknown>[] = [];
  const subscribe = (subject: string, fn: (m: Msg) => Promise<void>) => {
    const sub = nc.subscribe(subject, { queue: `waf-control-${o.region}` });
    tasks.push(
      (async () => {
        for await (const m of sub) {
          try {
            await fn(m);
          } catch {
            console.error(
              JSON.stringify({
                level: 'error',
                message: 'WAF control message failed',
                subject: m.subject,
              }),
            );
          }
        }
      })(),
    );
  };

  async function forNode(tx: Transaction, bundle: SiteBundle, node: typeof s.nodes.$inferSelect) {
    const activeChallenges = await tx
      .select()
      .from(s.challenges)
      .where(and(eq(s.challenges.siteId, bundle.site_id), gt(s.challenges.expiresAt, new Date())));
    bundle = {
      ...bundle,
      challenges: activeChallenges.map((c) => ({
        token: c.token,
        authorization: c.authorization,
        expires_at: c.expiresAt.toISOString(),
      })),
    };
    if (!bundle.certificate_id) return bundle;
    const [site] = await tx.select().from(s.sites).where(eq(s.sites.id, bundle.site_id));
    const [cert] = await tx
      .select()
      .from(s.certificates)
      .where(
        and(
          eq(s.certificates.id, bundle.certificate_id),
          eq(s.certificates.projectId, site.projectId),
          eq(s.certificates.regionId, o.region),
        ),
      );
    if (!cert?.certPem || !cert.keyPemEncrypted) {
      if (cert?.source === 'acme' && !bundle.http_redirect) return bundle;
      throw new Error('Certificate is not ready');
    }
    if (!o.masterKey || !node.publicKeyPem)
      throw new Error('Certificate delivery requires master and node encryption keys');
    const key = decryptKey(cert.keyPemEncrypted, o.masterKey, `${cert.projectId}:${cert.id}`);
    validateCertificate(cert.certPem, key, [bundle.hostname]);
    return {
      ...bundle,
      tls: {
        cert_pem: cert.certPem,
        key_encrypted: sealForNode(key, node.publicKeyPem, bundle.site_id, bundle.revision),
      },
    };
  }

  // Membership changes need a new desired revision immediately. Otherwise an
  // old ACK can mark the site active while reassignment is still queued.
  async function queueMembershipRevision(tx: Transaction, siteId: string) {
    const [site] = await tx
      .update(s.sites)
      .set({
        configRevision: sql`${s.sites.configRevision}+1`,
        status: 'provisioning',
        updatedAt: new Date(),
      })
      .where(and(eq(s.sites.id, siteId), ne(s.sites.status, 'deleting')))
      .returning();
    if (site)
      await tx.insert(s.jobs).values({ kind: 'compile', siteId, revision: site.configRevision });
  }

  async function settle(tx: Transaction, siteId: string) {
    const [site] = await tx.select().from(s.sites).where(eq(s.sites.id, siteId)).for('update');
    if (!site) return;
    const assigned = await tx
      .select({ node: s.nodes })
      .from(s.siteNodes)
      .innerJoin(s.nodes, eq(s.siteNodes.nodeId, s.nodes.id))
      .where(eq(s.siteNodes.siteId, siteId));
    if (!assigned.length) return;
    let certificateReady = true;
    if (site.certificateId) {
      const [cert] = await tx
        .select()
        .from(s.certificates)
        .where(eq(s.certificates.id, site.certificateId));
      certificateReady = !!cert?.certPem && !!cert.notAfter && cert.notAfter > new Date();
    }
    const min = Math.min(...assigned.map((a) => a.node.appliedRevisionMap[siteId] ?? 0));
    if (site.status === 'deleting' && min >= site.configRevision) {
      await tx.delete(s.sites).where(eq(s.sites.id, siteId));
      return;
    }
    await tx
      .update(s.sites)
      .set({
        appliedRevision: Math.min(min, site.configRevision),
        ...(min >= site.configRevision && site.verifiedAt && certificateReady
          ? { status: 'active', lastError: null }
          : site.status === 'active'
            ? { status: 'provisioning' }
            : {}),
        updatedAt: new Date(),
      })
      .where(eq(s.sites.id, siteId));
  }

  subscribe('waf.node.heartbeat.*', async (m) => {
    const parsed = heartbeat.safeParse(codec.decode(m.data));
    if (!parsed.success) return;
    const h = parsed.data;
    if (m.subject !== `waf.node.heartbeat.${h.node_id}`) return;
    await db.transaction(async (tx) => {
      await lock(tx);
      const [node] = await tx
        .select()
        .from(s.nodes)
        .where(and(eq(s.nodes.id, h.node_id), eq(s.nodes.regionId, o.region)))
        .for('update');
      if (!node) return;
      const applied = { ...h.applied };
      await tx
        .update(s.nodes)
        .set({
          version: h.version,
          lastHeartbeatAt: new Date(),
          status: node.status === 'draining' ? 'draining' : 'online',
          appliedRevisionMap: applied,
          updatedAt: new Date(),
        })
        .where(eq(s.nodes.id, node.id));
      const assignments = await tx
        .select()
        .from(s.siteNodes)
        .where(eq(s.siteNodes.nodeId, node.id));
      for (const a of assignments) await settle(tx, a.siteId);
      if (node.status === 'offline') {
        const sites = await tx
          .select()
          .from(s.sites)
          .where(and(eq(s.sites.regionId, o.region), ne(s.sites.status, 'deleting')));
        for (const site of sites)
          if (site.verifiedAt) {
            await queueMembershipRevision(tx, site.id);
          }
      }
    });
  });
  subscribe('waf.node.ack.*', async (m) => {
    const parsed = ackSchema.safeParse(codec.decode(m.data));
    if (!parsed.success) return;
    const a = parsed.data;
    if (m.subject !== `waf.node.ack.${a.node_id}`) return;
    await db.transaction(async (tx) => {
      await lock(tx);
      const [assigned] = await tx
        .select()
        .from(s.siteNodes)
        .where(and(eq(s.siteNodes.nodeId, a.node_id), eq(s.siteNodes.siteId, a.site_id)));
      if (!assigned) return;
      const [node] = await tx
        .select()
        .from(s.nodes)
        .where(and(eq(s.nodes.id, a.node_id), eq(s.nodes.regionId, o.region)))
        .for('update');
      if (!node) return;
      const [site] = await tx.select().from(s.sites).where(eq(s.sites.id, a.site_id));
      if (!site || a.revision > site.configRevision) return;
      if (!a.ok) {
        if (a.revision === site.configRevision)
          await tx
            .update(s.sites)
            .set({ status: 'error', lastError: 'Edge node rejected the configuration' })
            .where(eq(s.sites.id, site.id));
        return;
      }
      await tx
        .update(s.nodes)
        .set({
          appliedRevisionMap: {
            ...node.appliedRevisionMap,
            [a.site_id]: Math.max(node.appliedRevisionMap[a.site_id] ?? 0, a.revision),
          },
        })
        .where(eq(s.nodes.id, node.id));
      await settle(tx, a.site_id);
    });
  });
  subscribe('waf.config.snapshot.*', async (m) => {
    const id = m.subject.split('.').at(-1);
    if (!id || !z.string().uuid().safeParse(id).success) return;
    await db.transaction(async (tx) => {
      await lock(tx);
      const [node] = await tx
        .select()
        .from(s.nodes)
        .where(and(eq(s.nodes.id, id), eq(s.nodes.regionId, o.region)));
      if (!node) return;
      const rows = await tx
        .select({ bundle: s.bundles.payload })
        .from(s.siteNodes)
        .innerJoin(s.sites, eq(s.siteNodes.siteId, s.sites.id))
        .innerJoin(s.bundles, eq(s.bundles.siteId, s.sites.id))
        .where(and(eq(s.siteNodes.nodeId, id), ne(s.sites.status, 'deleting')));
      const info = await jsm.streams.info('WAF_CONFIG');
      m.respond(
        codec.encode({
          bundles: await Promise.all(rows.map((r) => forNode(tx, r.bundle as SiteBundle, node))),
          sequence: info.state.last_seq,
        }),
      );
    });
  });

  const worker = new Worker(
    queueName,
    async (task) => {
      const jobId = String(task.data.outboxId);
      let publicationFailed = false;
      await db.transaction(async (tx) => {
        await lock(tx);
        const [job] = await tx.select().from(s.jobs).where(eq(s.jobs.id, jobId)).for('update');
        if (!job || job.status === 'done') return;
        if (job.kind === 'node.drain') {
          const id = z.string().uuid().parse(job.payload.nodeId);
          const assignments = await tx.select().from(s.siteNodes).where(eq(s.siteNodes.nodeId, id));
          for (const a of assignments)
            await tx.insert(s.jobs).values({ kind: 'compile', siteId: a.siteId });
          await tx
            .update(s.jobs)
            .set({ status: 'done', updatedAt: new Date() })
            .where(eq(s.jobs.id, jobId));
          return;
        }
        if (!job.siteId) {
          await tx
            .update(s.jobs)
            .set({ status: 'error', lastError: 'Job requires a later implementation phase' })
            .where(eq(s.jobs.id, jobId));
          return;
        }
        const [site] = await tx
          .select()
          .from(s.sites)
          .where(and(eq(s.sites.id, job.siteId), eq(s.sites.regionId, o.region)))
          .for('update');
        if (!site || (!site.verifiedAt && site.status !== 'deleting')) {
          await tx.update(s.jobs).set({ status: 'done' }).where(eq(s.jobs.id, jobId));
          return;
        }
        if (job.revision && job.revision < site.configRevision) {
          await tx.update(s.jobs).set({ status: 'done' }).where(eq(s.jobs.id, jobId));
          return;
        }
        let payload: Record<string, unknown>;
        const deliveries = new Map<string, unknown>();
        let assigned = await tx
          .select({ node: s.nodes })
          .from(s.siteNodes)
          .innerJoin(s.nodes, eq(s.nodes.id, s.siteNodes.nodeId))
          .where(eq(s.siteNodes.siteId, site.id));
        if (site.status === 'deleting')
          payload = { op: 'delete', bundle: { site_id: site.id, revision: site.configRevision } };
        else {
          try {
            const [policy] = await tx
              .select()
              .from(s.policies)
              .where(
                and(eq(s.policies.id, site.policyId), eq(s.policies.projectId, site.projectId)),
              );
            const origins = await tx
              .select()
              .from(s.origins)
              .where(and(eq(s.origins.siteId, site.id), eq(s.origins.projectId, site.projectId)));
            const rules = await tx
              .select()
              .from(s.rules)
              .where(
                and(eq(s.rules.policyId, site.policyId), eq(s.rules.projectId, site.projectId)),
              );
            const available = await tx
              .select()
              .from(s.nodes)
              .where(
                and(
                  eq(s.nodes.regionId, o.region),
                  eq(s.nodes.kind, 'edge'),
                  eq(s.nodes.status, 'online'),
                ),
              );
            if (!available.length) throw new Error('No online edge nodes are available');
            const removed = assigned.filter((a) => !available.some((n) => n.id === a.node.id));
            if (
              assigned.length &&
              (removed.length || available.some((n) => !assigned.some((a) => a.node.id === n.id)))
            ) {
              site.configRevision++;
              await tx
                .update(s.sites)
                .set({ configRevision: site.configRevision, updatedAt: new Date() })
                .where(eq(s.sites.id, site.id));
            }
            const bundle = compileBundle(site, policy, origins, rules);
            await lintCompiled(o.lintBinary, bundle.seclang);
            for (const node of available)
              deliveries.set(node.id, { op: 'upsert', bundle: await forNode(tx, bundle, node) });
            for (const a of removed) {
              await js.publish(
                `waf.config.${a.node.id}`,
                codec.encode({
                  op: 'delete',
                  bundle: { site_id: site.id, revision: site.configRevision },
                }),
              );
            }
            await tx.delete(s.siteNodes).where(eq(s.siteNodes.siteId, site.id));
            await tx
              .insert(s.siteNodes)
              .values(available.map((n) => ({ siteId: site.id, nodeId: n.id })));
            await tx
              .insert(s.siteNodeHistory)
              .values(
                available.map((node) => ({
                  siteId: site.id,
                  nodeId: node.id,
                  projectId: site.projectId,
                  regionId: site.regionId,
                })),
              )
              .onConflictDoNothing();
            assigned = available.map((node) => ({ node }));
            await tx
              .insert(s.bundles)
              .values({
                siteId: site.id,
                revision: bundle.revision,
                payload: bundle as unknown as Record<string, unknown>,
              })
              .onConflictDoUpdate({
                target: s.bundles.siteId,
                set: {
                  revision: bundle.revision,
                  payload: bundle as unknown as Record<string, unknown>,
                  updatedAt: new Date(),
                },
              });
            payload = { op: 'upsert', bundle };
            await tx
              .update(s.sites)
              .set({ status: 'provisioning', lastError: null })
              .where(eq(s.sites.id, site.id));
          } catch (err) {
            const message =
              err instanceof Error && err.message.includes('Phase 7')
                ? err.message
                : 'Configuration failed validation or no edge node is available';
            await tx
              .update(s.sites)
              .set({ status: 'error', lastError: message })
              .where(eq(s.sites.id, site.id));
            await tx
              .update(s.jobs)
              .set({ status: 'error', lastError: message })
              .where(eq(s.jobs.id, jobId));
            return;
          }
        }
        // Hold the same advisory lock as snapshots. Commit a compiled bundle even
        // if publication fails, so a snapshot never skips an uncommitted revision.
        try {
          for (const a of assigned)
            await js.publish(
              `waf.config.${a.node.id}`,
              codec.encode(deliveries.get(a.node.id) ?? payload),
              {
                msgID: `${a.node.id}-${site.id}-${site.configRevision}-${site.status === 'deleting' ? 'delete' : 'upsert'}`,
              },
            );
        } catch {
          publicationFailed = true;
        }
        if (!assigned.length && site.status === 'deleting')
          await tx.delete(s.sites).where(eq(s.sites.id, site.id));
        await tx
          .update(s.jobs)
          .set({
            status: publicationFailed ? 'queued' : 'done',
            attempts: job.attempts + 1,
            lastError: publicationFailed ? 'NATS publication failed' : null,
            updatedAt: new Date(),
          })
          .where(eq(s.jobs.id, jobId));
        if (!publicationFailed && site.status !== 'deleting') await settle(tx, site.id);
      });
      if (publicationFailed) throw new Error('NATS publication failed');
    },
    { connection: redis, concurrency: 2 },
  );
  worker.on('error', () => console.error('WAF worker connection error'));
  worker.on('failed', () => console.error('WAF job failed; retry scheduled by BullMQ'));

  const certWorker = acmeService
    ? new Worker(
        queueName + '-certificates',
        async (task) => {
          const jobId = String(task.data.outboxId);
          const [job] = await db.select().from(s.jobs).where(eq(s.jobs.id, jobId));
          if (!job || job.status === 'done') return;
          const id = z.string().uuid().parse(job.payload.certificateId);
          try {
            await acmeService.issue(id);
            await db
              .update(s.jobs)
              .set({ status: 'done', lastError: null, updatedAt: new Date() })
              .where(eq(s.jobs.id, jobId));
          } catch {
            await db
              .update(s.jobs)
              .set({
                attempts: job.attempts + 1,
                lastError: 'ACME issuance failed',
                updatedAt: new Date(),
              })
              .where(eq(s.jobs.id, jobId));
            throw new Error('ACME issuance failed');
          }
        },
        { connection: redis, concurrency: 1 },
      )
    : undefined;
  certWorker?.on('error', () => console.error('Certificate worker connection error'));
  const exhausted = async (
    task:
      { data: { outboxId: string }; attemptsMade: number; opts: { attempts?: number } } | undefined,
  ) => {
    if (task && task.attemptsMade >= (task.opts.attempts ?? 1))
      await db
        .update(s.jobs)
        .set({ status: 'error', lastError: 'Retry attempts exhausted', updatedAt: new Date() })
        .where(eq(s.jobs.id, task.data.outboxId));
  };
  worker.on('failed', (task) => {
    void exhausted(task).catch(() => console.error('Failed to record exhausted job'));
  });
  certWorker?.on('failed', (task) => {
    void exhausted(task).catch(() => console.error('Failed to record exhausted certificate job'));
  });
  let lastRenewal = 0;
  async function pump() {
    if (stopping || pumping) return;
    pumping = true;
    try {
      if (acmeService && Date.now() - lastRenewal > 3600000) {
        await acmeService.scheduleRenewals();
        lastRenewal = Date.now();
      }
      const pending = await db
        .select()
        .from(s.jobs)
        .where(
          and(
            inArray(s.jobs.status, ['pending', 'queued']),
            sql`(
      exists(select 1 from waf_sites where id=${s.jobs.siteId} and region_id=${o.region}) or
      exists(select 1 from waf_nodes where id::text=${s.jobs.payload}->>'nodeId' and region_id=${o.region}) or
      exists(select 1 from waf_certificates where id::text=${s.jobs.payload}->>'certificateId' and region_id=${o.region})
    )`,
          ),
        )
        .limit(100);
      for (const job of pending) {
        const target = job.kind === 'cert.issue' ? certQueue : queue;
        if (!target) continue;
        await db
          .update(s.jobs)
          .set({ status: 'queued' })
          .where(and(eq(s.jobs.id, job.id), eq(s.jobs.status, 'pending')));
        try {
          await target.add(
            job.kind,
            { outboxId: job.id },
            {
              jobId: job.id,
              attempts: job.kind === 'cert.issue' ? 3 : 10,
              backoff: { type: 'exponential', delay: job.kind === 'cert.issue' ? 60000 : 1000 },
              removeOnComplete: 1000,
              removeOnFail: 1000,
            },
          );
        } catch {
          await db
            .update(s.jobs)
            .set({ status: 'pending' })
            .where(and(eq(s.jobs.id, job.id), eq(s.jobs.status, 'queued')));
        }
      }
      await db.transaction(async (tx) => {
        await lock(tx);
        const offline = await tx
          .update(s.nodes)
          .set({ status: 'offline', updatedAt: new Date() })
          .where(
            and(
              eq(s.nodes.regionId, o.region),
              inArray(s.nodes.status, ['online', 'degraded']),
              lt(s.nodes.lastHeartbeatAt, new Date(Date.now() - 29000)),
            ),
          )
          .returning();
        for (const node of offline) {
          const affected = await tx
            .select()
            .from(s.siteNodes)
            .where(eq(s.siteNodes.nodeId, node.id));
          for (const a of affected) await queueMembershipRevision(tx, a.siteId);
        }
      });
    } finally {
      pumping = false;
    }
  }
  const interval = setInterval(
    () => void pump().catch(() => console.error('WAF outbox pump failed')),
    250,
  );
  await nc.flush();
  await worker.waitUntilReady();
  await pump();
  return {
    nc,
    async close() {
      stopping = true;
      clearInterval(interval);
      while (pumping) await new Promise((r) => setTimeout(r, 10));
      await certWorker?.close();
      await certQueue?.close();
      await worker.close();
      await queue.close();
      await redis.quit();
      await nc.drain();
      await Promise.allSettled(tasks);
    },
  };
}
