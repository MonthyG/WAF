import * as acme from 'acme-client';
import { randomUUID } from 'node:crypto';
import { and, eq, inArray, lt, ne, sql } from 'drizzle-orm';
import type { DB, Transaction } from '../../../db/index.js';
import * as s from '../../../db/schema.js';
import { decryptKey, encryptKey, validateCertificate } from './certificates.service.js';

export type AcmeOptions = {
  directoryURL: string;
  email: string;
  termsAgreed: boolean;
  masterKey: Buffer;
  region: string;
};

async function bump(tx: Transaction, siteId: string) {
  const [site] = await tx
    .update(s.sites)
    .set({
      configRevision: sql`${s.sites.configRevision}+1`,
      status: 'provisioning',
      updatedAt: new Date(),
    })
    .where(and(eq(s.sites.id, siteId), ne(s.sites.status, 'deleting')))
    .returning();
  if (!site) throw new Error('Site no longer available');
  await tx.insert(s.jobs).values({ kind: 'compile', siteId, revision: site.configRevision });
  return site.configRevision;
}

export class AcmeService {
  constructor(
    readonly db: DB,
    readonly options: AcmeOptions,
  ) {
    const url = new URL(options.directoryURL);
    if (url.protocol !== 'https:') throw new Error('ACME directory must use HTTPS');
    if (!options.termsAgreed || !options.email || options.masterKey.length !== 32)
      throw new Error('ACME email, terms agreement, and master key are required');
  }

  async accountKey() {
    return this.db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(963282)`);
      const { directoryURL, email, masterKey } = this.options;
      const [existing] = await tx
        .select()
        .from(s.acmeAccounts)
        .where(and(eq(s.acmeAccounts.directory, directoryURL), eq(s.acmeAccounts.email, email)));
      if (existing) return decryptKey(existing.keyEncrypted, masterKey, `acme:${existing.id}`);
      const id = randomUUID(),
        key = (await acme.crypto.createPrivateKey()).toString();
      await tx
        .insert(s.acmeAccounts)
        .values({
          id,
          directory: directoryURL,
          email,
          keyEncrypted: encryptKey(key, masterKey, `acme:${id}`),
        });
      return key;
    });
  }

  async challenge(
    certificate: typeof s.certificates.$inferSelect,
    domain: string,
    token: string,
    authorization: string,
    remove = false,
  ) {
    if (!/^[A-Za-z0-9_-]{16,256}$/.test(token) || !authorization.startsWith(token + '.'))
      throw new Error('Invalid ACME challenge');
    const applied = await this.db.transaction(async (tx) => {
      const [site] = await tx
        .select()
        .from(s.sites)
        .where(
          and(
            eq(s.sites.hostname, domain),
            eq(s.sites.projectId, certificate.projectId),
            eq(s.sites.regionId, certificate.regionId),
            ne(s.sites.status, 'deleting'),
          ),
        )
        .for('update');
      if (!site?.verifiedAt) throw new Error('Domain ownership is not verified');
      if (remove)
        await tx
          .delete(s.challenges)
          .where(and(eq(s.challenges.siteId, site.id), eq(s.challenges.token, token)));
      else
        await tx
          .insert(s.challenges)
          .values({
            siteId: site.id,
            token,
            authorization,
            expiresAt: new Date(Date.now() + 15 * 60 * 1000),
          })
          .onConflictDoUpdate({
            target: [s.challenges.siteId, s.challenges.token],
            set: { authorization, expiresAt: new Date(Date.now() + 15 * 60 * 1000) },
          });
      return { id: site.id, revision: await bump(tx, site.id) };
    });
    if (remove) return;
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
      const [site] = await this.db.select().from(s.sites).where(eq(s.sites.id, applied.id));
      if (!site || site.status === 'error' || site.status === 'deleting')
        throw new Error('Challenge delivery failed');
      const assigned = await this.db
        .select({ node: s.nodes })
        .from(s.siteNodes)
        .innerJoin(s.nodes, eq(s.nodes.id, s.siteNodes.nodeId))
        .where(eq(s.siteNodes.siteId, site.id));
      if (
        assigned.length &&
        assigned.every(
          ({ node }) =>
            node.status === 'online' && (node.appliedRevisionMap[site.id] ?? 0) >= applied.revision,
        )
      )
        return;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error('Challenge delivery timed out');
  }

  async issue(id: string) {
    const [cert] = await this.db
      .select()
      .from(s.certificates)
      .where(
        and(
          eq(s.certificates.id, id),
          eq(s.certificates.regionId, this.options.region),
          eq(s.certificates.source, 'acme'),
        ),
      );
    if (!cert) return;
    if (cert.notAfter && cert.notAfter.getTime() > Date.now() + 30 * 86400000) return;
    for (const domain of cert.domains) {
      const [site] = await this.db
        .select()
        .from(s.sites)
        .where(
          and(
            eq(s.sites.hostname, domain),
            eq(s.sites.projectId, cert.projectId),
            eq(s.sites.regionId, cert.regionId),
            ne(s.sites.status, 'deleting'),
          ),
        );
      if (!site?.verifiedAt) throw new Error('Domain ownership is not verified');
    }
    await this.db
      .update(s.certificates)
      .set({ acmeStatus: 'issuing', lastError: null, updatedAt: new Date() })
      .where(eq(s.certificates.id, id));
    try {
      const client = new acme.Client({
        directoryUrl: this.options.directoryURL,
        accountKey: await this.accountKey(),
        backoffAttempts: 10,
        backoffMin: 1000,
        backoffMax: 10000,
      });
      const [key, csr] = await acme.crypto.createCsr({
        commonName: cert.domains[0],
        altNames: cert.domains,
      });
      const pem = await client.auto({
        csr,
        email: this.options.email,
        termsOfServiceAgreed: this.options.termsAgreed,
        challengePriority: ['http-01'],
        challengeCreateFn: async (authz, c, authorization) => {
          if (c.type !== 'http-01') throw new Error('Only HTTP-01 is supported');
          await this.challenge(cert, authz.identifier.value, c.token, authorization);
        },
        challengeRemoveFn: async (authz, c, authorization) => {
          await this.challenge(cert, authz.identifier.value, c.token, authorization, true);
        },
      });
      const { notAfter } = validateCertificate(pem, key.toString(), cert.domains);
      await this.db.transaction(async (tx) => {
        const [present] = await tx
          .select()
          .from(s.certificates)
          .where(eq(s.certificates.id, id))
          .for('update');
        if (!present) return;
        await tx
          .update(s.certificates)
          .set({
            certPem: pem,
            keyPemEncrypted: encryptKey(
              key.toString(),
              this.options.masterKey,
              `${cert.projectId}:${id}`,
            ),
            notAfter,
            acmeStatus: 'valid',
            lastError: null,
            updatedAt: new Date(),
          })
          .where(eq(s.certificates.id, id));
        const sites = await tx
          .select()
          .from(s.sites)
          .where(and(eq(s.sites.certificateId, id), ne(s.sites.status, 'deleting')));
        for (const site of sites) await bump(tx, site.id);
      });
    } catch {
      await this.db
        .update(s.certificates)
        .set({
          acmeStatus: 'error',
          lastError:
            'ACME issuance failed; check domain routing, challenge delivery, and CA availability',
          updatedAt: new Date(),
        })
        .where(eq(s.certificates.id, id));
      throw new Error('ACME issuance failed');
    }
  }

  async scheduleRenewals() {
    await this.db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(963283)`);
      const due = await tx
        .select()
        .from(s.certificates)
        .where(
          and(
            eq(s.certificates.regionId, this.options.region),
            eq(s.certificates.source, 'acme'),
            lt(s.certificates.notAfter, new Date(Date.now() + 30 * 86400000)),
          ),
        );
      for (const cert of due) {
        const [pending] = await tx
          .select()
          .from(s.jobs)
          .where(
            and(
              eq(s.jobs.kind, 'cert.issue'),
              inArray(s.jobs.status, ['pending', 'queued']),
              sql`${s.jobs.payload}->>'certificateId' = ${cert.id}`,
            ),
          )
          .limit(1);
        if (!pending)
          await tx
            .insert(s.jobs)
            .values({ kind: 'cert.issue', payload: { certificateId: cert.id } });
      }
      const expired = await tx
        .delete(s.challenges)
        .where(lt(s.challenges.expiresAt, new Date()))
        .returning();
      for (const id of new Set(expired.map((c) => c.siteId))) {
        const [site] = await tx
          .select()
          .from(s.sites)
          .where(and(eq(s.sites.id, id), ne(s.sites.status, 'deleting')));
        if (site) await bump(tx, id);
      }
    });
  }
}
