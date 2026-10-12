import { randomBytes, randomUUID, X509Certificate } from 'node:crypto';
import { and, eq, ne, sql, asc } from 'drizzle-orm';
import type { DB, Transaction } from '../../db/index.js';
import * as s from '../../db/schema.js';
import type { Context } from './auth/keystone.middleware.js';
import { HttpError, notFound } from './errors.js';
import { camel, dto, policyInput, ruleInput } from './validation.js';
import { encryptKey, validateCertificate } from './certificates/certificates.service.js';
import type { z } from 'zod';
import type {
  siteInput,
  sitePatch,
  originInput,
  policyPatch,
  rulePatch,
  certificateInput,
} from './validation.js';

type Exec = DB | Transaction;
export type ServiceOptions = {
  region: string;
  dnsTarget: string;
  masterKey: Buffer;
  resolveTxt: (name: string) => Promise<string[][]>;
  lint?: (seclang: string) => Promise<void>;
};
export class WafService {
  constructor(
    readonly db: DB,
    readonly options: ServiceOptions,
  ) {}
  scope(ctx: Context) {
    return ctx.projectId;
  }
  async audit(tx: Transaction, ctx: Context, action: string, id: string) {
    await tx
      .insert(s.audit)
      .values({
        projectId: ctx.projectId,
        regionId: this.options.region,
        userId: ctx.userId,
        action,
        resourceId: id,
      });
  }
  async site(tx: Exec, ctx: Context, id: string, lock = false) {
    const q = tx
      .select()
      .from(s.sites)
      .where(
        and(
          eq(s.sites.id, id),
          eq(s.sites.projectId, ctx.projectId),
          eq(s.sites.regionId, this.options.region),
        ),
      )
      .limit(1);
    const [row] = await (lock ? q.for('update') : q);
    if (!row) throw notFound();
    return row;
  }
  async policy(tx: Exec, ctx: Context, id: string) {
    const [row] = await tx
      .select()
      .from(s.policies)
      .where(
        and(
          eq(s.policies.id, id),
          eq(s.policies.projectId, ctx.projectId),
          eq(s.policies.regionId, this.options.region),
        ),
      )
      .limit(1);
    if (!row) throw notFound();
    return row;
  }
  async certificate(tx: Exec, ctx: Context, id: string) {
    const [row] = await tx
      .select()
      .from(s.certificates)
      .where(
        and(
          eq(s.certificates.id, id),
          eq(s.certificates.projectId, ctx.projectId),
          eq(s.certificates.regionId, this.options.region),
        ),
      )
      .limit(1);
    if (!row) throw notFound();
    return row;
  }
  async bump(tx: Transaction, ctx: Context, id: string, kind = 'compile') {
    const [site] = await tx
      .update(s.sites)
      .set({ configRevision: sql`${s.sites.configRevision}+1`, updatedAt: new Date() })
      .where(and(eq(s.sites.id, id), eq(s.sites.projectId, ctx.projectId)))
      .returning();
    await tx.insert(s.jobs).values({ kind, siteId: id, revision: site.configRevision });
  }
  async bumpPolicy(tx: Transaction, ctx: Context, id: string) {
    const sites = await tx
      .select()
      .from(s.sites)
      .where(and(eq(s.sites.policyId, id), eq(s.sites.projectId, ctx.projectId)))
      .orderBy(asc(s.sites.id));
    for (const site of sites) await this.bump(tx, ctx, site.id);
  }
  siteDTO(site: typeof s.sites.$inferSelect) {
    return {
      ...dto(site),
      verification: {
        type: 'TXT',
        name: `_cloudinside-waf.${site.hostname}`,
        value: site.verificationToken,
      },
      dns_target: { type: 'CNAME', value: this.options.dnsTarget },
    };
  }
  async listSites(ctx: Context) {
    return (
      await this.db
        .select()
        .from(s.sites)
        .where(and(eq(s.sites.projectId, ctx.projectId), eq(s.sites.regionId, this.options.region)))
        .orderBy(asc(s.sites.createdAt))
        .limit(1000)
    ).map((v) => this.siteDTO(v));
  }
  async getSite(ctx: Context, id: string) {
    const site = await this.site(this.db, ctx, id);
    return {
      ...this.siteDTO(site),
      origins: await this.listOrigins(ctx, id),
      policy: dto(await this.policy(this.db, ctx, site.policyId)),
    };
  }
  async createSite(ctx: Context, input: z.infer<typeof siteInput>) {
    return this.db.transaction(async (tx) => {
      let policyId = input.policy_id;
      if (policyId) await this.policy(tx, ctx, policyId);
      else {
        const [p] = await tx
          .insert(s.policies)
          .values({
            ...camel<typeof s.policies.$inferInsert>(policyInput.parse(input.policy ?? {})),
            projectId: ctx.projectId,
            regionId: this.options.region,
          })
          .returning();
        policyId = p.id;
      }
      const [site] = await tx
        .insert(s.sites)
        .values({
          projectId: ctx.projectId,
          regionId: this.options.region,
          hostname: input.hostname,
          policyId,
          verificationToken: 'ciw-' + randomBytes(24).toString('hex'),
        })
        .returning();
      await tx
        .insert(s.origins)
        .values(
          input.origins.map((o) => ({
            ...camel<typeof s.origins.$inferInsert>(o),
            siteId: site.id,
            projectId: ctx.projectId,
            regionId: this.options.region,
          })),
        );
      if (input.tls) {
        const [cert] = await tx
          .insert(s.certificates)
          .values({
            projectId: ctx.projectId,
            regionId: this.options.region,
            source: 'acme',
            domains: [site.hostname],
            acmeStatus: 'pending',
          })
          .returning();
        await tx.update(s.sites).set({ certificateId: cert.id }).where(eq(s.sites.id, site.id));
        site.certificateId = cert.id;
      }
      await this.audit(tx, ctx, 'site.create', site.id);
      return this.siteDTO(site);
    });
  }
  async updateSite(ctx: Context, id: string, input: z.infer<typeof sitePatch>) {
    return this.db.transaction(async (tx) => {
      const site = await this.site(tx, ctx, id, true);
      if (site.status === 'deleting')
        throw new HttpError(409, 'site_deleting', 'Site is being deleted');
      if (input.policy_id) await this.policy(tx, ctx, input.policy_id);
      const certId = input.certificate_id === undefined ? site.certificateId : input.certificate_id;
      if (certId) {
        const cert = await this.certificate(tx, ctx, certId);
        if (
          !cert.certPem ||
          !cert.notAfter ||
          cert.notAfter <= new Date() ||
          !new X509Certificate(cert.certPem).checkHost(site.hostname)
        )
          throw new HttpError(
            422,
            'invalid_certificate',
            'Certificate is not ready or does not cover this site',
          );
      }
      if ((input.http_redirect ?? site.httpRedirect) && !certId)
        throw new HttpError(
          422,
          'certificate_required',
          'A valid certificate is required for HTTPS redirection',
        );
      await tx.update(s.sites).set(camel(input)).where(eq(s.sites.id, id));
      await this.bump(tx, ctx, id);
      await this.audit(tx, ctx, 'site.update', id);
      return this.siteDTO(await this.site(tx, ctx, id));
    });
  }
  async deleteSite(ctx: Context, id: string) {
    await this.db.transaction(async (tx) => {
      const site = await this.site(tx, ctx, id, true);
      if (site.status === 'deleting') return;
      await tx.update(s.sites).set({ status: 'deleting' }).where(eq(s.sites.id, id));
      await this.bump(tx, ctx, id, 'delete');
      await this.audit(tx, ctx, 'site.delete', id);
    });
  }
  async verifySite(ctx: Context, id: string) {
    const candidate = await this.site(this.db, ctx, id);
    let values: string[][];
    try {
      values = await this.options.resolveTxt(`_cloudinside-waf.${candidate.hostname}`);
    } catch {
      throw new HttpError(422, 'verification_failed', 'Ownership TXT record was not found');
    }
    if (!values.some((parts) => parts.join('') === candidate.verificationToken))
      throw new HttpError(422, 'verification_failed', 'Ownership TXT record does not match');
    return this.db.transaction(async (tx) => {
      const site = await this.site(tx, ctx, id, true);
      if (site.status === 'deleting')
        throw new HttpError(409, 'site_deleting', 'Site is being deleted');
      if (!site.verifiedAt) {
        await tx
          .update(s.sites)
          .set({ verifiedAt: new Date(), status: 'provisioning' })
          .where(eq(s.sites.id, id));
        await this.bump(tx, ctx, id);
        if (site.certificateId)
          await tx
            .insert(s.jobs)
            .values({ kind: 'cert.issue', payload: { certificateId: site.certificateId } });
        await this.audit(tx, ctx, 'site.verify', id);
      }
      return this.siteDTO(await this.site(tx, ctx, id));
    });
  }
  async listOrigins(ctx: Context, siteId: string) {
    await this.site(this.db, ctx, siteId);
    return (
      await this.db
        .select()
        .from(s.origins)
        .where(and(eq(s.origins.siteId, siteId), eq(s.origins.projectId, ctx.projectId)))
    ).map(dto);
  }
  async addOrigin(ctx: Context, siteId: string, input: z.infer<typeof originInput>) {
    return this.db.transaction(async (tx) => {
      const site = await this.site(tx, ctx, siteId, true);
      if (site.status === 'deleting')
        throw new HttpError(409, 'site_deleting', 'Site is being deleted');
      const existing = await tx.select().from(s.origins).where(eq(s.origins.siteId, siteId));
      if (existing.length >= 20)
        throw new HttpError(422, 'origin_limit', 'Maximum 20 origins per site');
      const [o] = await tx
        .insert(s.origins)
        .values({
          ...camel<typeof s.origins.$inferInsert>(input),
          siteId,
          projectId: ctx.projectId,
          regionId: this.options.region,
        })
        .returning();
      await this.bump(tx, ctx, siteId);
      await this.audit(tx, ctx, 'origin.create', o.id);
      return dto(o);
    });
  }
  async deleteOrigin(ctx: Context, siteId: string, id: string) {
    await this.db.transaction(async (tx) => {
      await this.site(tx, ctx, siteId, true);
      const list = await tx
        .select()
        .from(s.origins)
        .where(and(eq(s.origins.siteId, siteId), eq(s.origins.projectId, ctx.projectId)));
      if (!list.some((o) => o.id === id)) throw notFound();
      if (list.length === 1)
        throw new HttpError(409, 'last_origin', 'A site requires at least one origin');
      await tx.delete(s.origins).where(and(eq(s.origins.id, id), eq(s.origins.siteId, siteId)));
      await this.bump(tx, ctx, siteId);
      await this.audit(tx, ctx, 'origin.delete', id);
    });
  }
  async listPolicies(ctx: Context) {
    return (
      await this.db
        .select()
        .from(s.policies)
        .where(
          and(
            eq(s.policies.projectId, ctx.projectId),
            eq(s.policies.regionId, this.options.region),
          ),
        )
    ).map(dto);
  }
  async createPolicy(ctx: Context, input: z.infer<typeof policyInput>) {
    return this.db.transaction(async (tx) => {
      const [p] = await tx
        .insert(s.policies)
        .values({
          ...camel<typeof s.policies.$inferInsert>(input),
          projectId: ctx.projectId,
          regionId: this.options.region,
        })
        .returning();
      await this.audit(tx, ctx, 'policy.create', p.id);
      return dto(p);
    });
  }
  async updatePolicy(ctx: Context, id: string, input: z.infer<typeof policyPatch>) {
    return this.db.transaction(async (tx) => {
      await this.policy(tx, ctx, id);
      const [p] = await tx
        .update(s.policies)
        .set({ ...camel(input), updatedAt: new Date() })
        .where(eq(s.policies.id, id))
        .returning();
      await this.bumpPolicy(tx, ctx, id);
      await this.audit(tx, ctx, 'policy.update', id);
      return dto(p);
    });
  }
  async deletePolicy(ctx: Context, id: string) {
    await this.db.transaction(async (tx) => {
      await this.policy(tx, ctx, id);
      const [site] = await tx.select().from(s.sites).where(eq(s.sites.policyId, id)).limit(1);
      if (site) throw new HttpError(409, 'policy_in_use', 'Policy is attached to a site');
      await tx.delete(s.policies).where(eq(s.policies.id, id));
      await this.audit(tx, ctx, 'policy.delete', id);
    });
  }
  async listRules(ctx: Context, policyId: string) {
    await this.policy(this.db, ctx, policyId);
    return (
      await this.db
        .select()
        .from(s.rules)
        .where(and(eq(s.rules.policyId, policyId), eq(s.rules.projectId, ctx.projectId)))
        .orderBy(asc(s.rules.priority), asc(s.rules.id))
    ).map(dto);
  }
  async validateRule(ctx: Context, input: z.infer<typeof ruleInput>) {
    if (input.type === 'raw') {
      if (!ctx.roles.includes('admin'))
        throw new HttpError(403, 'forbidden', 'Raw rules require administrator role');
      if (!this.options.lint)
        throw new HttpError(503, 'lint_unavailable', 'Raw rule validation is unavailable');
      await this.options.lint(input.spec.seclang);
    }
  }
  async createRule(ctx: Context, policyId: string, input: z.infer<typeof ruleInput>) {
    await this.policy(this.db, ctx, policyId);
    await this.validateRule(ctx, input);
    return this.db.transaction(async (tx) => {
      await this.policy(tx, ctx, policyId);
      const [r] = await tx
        .insert(s.rules)
        .values({ ...input, policyId, projectId: ctx.projectId, regionId: this.options.region })
        .returning();
      await this.bumpPolicy(tx, ctx, policyId);
      await this.audit(tx, ctx, 'rule.create', r.id);
      return dto(r);
    });
  }
  async updateRule(ctx: Context, policyId: string, id: string, input: z.infer<typeof rulePatch>) {
    return this.db.transaction(async (tx) => {
      await this.policy(tx, ctx, policyId);
      const [old] = await tx
        .select()
        .from(s.rules)
        .where(
          and(
            eq(s.rules.id, id),
            eq(s.rules.policyId, policyId),
            eq(s.rules.projectId, ctx.projectId),
          ),
        )
        .for('update');
      if (!old) throw notFound();
      const parsed = ruleInput.parse({
        type: old.type,
        spec: input.spec ?? old.spec,
        enabled: input.enabled ?? old.enabled,
        priority: input.priority ?? old.priority,
      });
      await this.validateRule(ctx, parsed);
      const [r] = await tx
        .update(s.rules)
        .set({ ...parsed, updatedAt: new Date() })
        .where(eq(s.rules.id, id))
        .returning();
      await this.bumpPolicy(tx, ctx, policyId);
      await this.audit(tx, ctx, 'rule.update', id);
      return dto(r);
    });
  }
  async deleteRule(ctx: Context, policyId: string, id: string) {
    await this.db.transaction(async (tx) => {
      await this.policy(tx, ctx, policyId);
      const rows = await tx
        .delete(s.rules)
        .where(
          and(
            eq(s.rules.id, id),
            eq(s.rules.policyId, policyId),
            eq(s.rules.projectId, ctx.projectId),
          ),
        )
        .returning();
      if (!rows.length) throw notFound();
      await this.bumpPolicy(tx, ctx, policyId);
      await this.audit(tx, ctx, 'rule.delete', id);
    });
  }
  async listCertificates(ctx: Context) {
    return (
      await this.db
        .select()
        .from(s.certificates)
        .where(
          and(
            eq(s.certificates.projectId, ctx.projectId),
            eq(s.certificates.regionId, this.options.region),
          ),
        )
    ).map(dto);
  }
  async createCertificate(ctx: Context, input: z.infer<typeof certificateInput>) {
    return this.db.transaction(async (tx) => {
      const id = randomUUID();
      let certPem: string | undefined,
        keyPemEncrypted: string | undefined,
        notAfter: Date | undefined;
      if (input.source === 'upload') {
        notAfter = validateCertificate(input.cert_pem, input.key_pem, input.domains).notAfter;
        certPem = input.cert_pem;
        keyPemEncrypted = encryptKey(
          input.key_pem,
          this.options.masterKey,
          `${ctx.projectId}:${id}`,
        );
      } else {
        for (const domain of input.domains) {
          const [owned] = await tx
            .select()
            .from(s.sites)
            .where(
              and(
                eq(s.sites.hostname, domain),
                eq(s.sites.projectId, ctx.projectId),
                eq(s.sites.regionId, this.options.region),
              ),
            )
            .limit(1);
          if (!owned?.verifiedAt)
            throw new HttpError(
              422,
              'verification_required',
              'Verify domain ownership before requesting ACME issuance',
            );
        }
      }
      const [cert] = await tx
        .insert(s.certificates)
        .values({
          id,
          projectId: ctx.projectId,
          regionId: this.options.region,
          source: input.source,
          domains: input.domains,
          certPem,
          keyPemEncrypted,
          notAfter,
          acmeStatus: input.source === 'acme' ? 'pending' : null,
        })
        .returning();
      if (input.source === 'acme')
        await tx.insert(s.jobs).values({ kind: 'cert.issue', payload: { certificateId: id } });
      await this.audit(tx, ctx, 'certificate.create', id);
      return dto(cert);
    });
  }
  async deleteCertificate(ctx: Context, id: string) {
    await this.db.transaction(async (tx) => {
      await this.certificate(tx, ctx, id);
      const [site] = await tx.select().from(s.sites).where(eq(s.sites.certificateId, id)).limit(1);
      if (site) throw new HttpError(409, 'certificate_in_use', 'Certificate is attached to a site');
      await tx.delete(s.certificates).where(eq(s.certificates.id, id));
      await this.audit(tx, ctx, 'certificate.delete', id);
    });
  }
  async listNodes() {
    return (
      await this.db.select().from(s.nodes).where(eq(s.nodes.regionId, this.options.region))
    ).map(dto);
  }
  async drainNode(ctx: Context, id: string) {
    return this.db.transaction(async (tx) => {
      const [node] = await tx
        .update(s.nodes)
        .set({ status: 'draining', updatedAt: new Date() })
        .where(and(eq(s.nodes.id, id), eq(s.nodes.regionId, this.options.region)))
        .returning();
      if (!node) throw notFound();
      await tx.insert(s.jobs).values({ kind: 'node.drain', payload: { nodeId: id } });
      await this.audit(tx, ctx, 'node.drain', id);
      return dto(node);
    });
  }
}
