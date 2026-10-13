import { beforeAll, afterAll, describe, it, expect } from 'vitest';
import request from 'supertest';
import { createServer, type Server } from 'node:http';
import { randomUUID, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { sql, eq } from 'drizzle-orm';
import { connect } from '../src/db/index.js';
import { migrateDatabase } from '../src/db/migrate.js';
import * as schema from '../src/db/schema.js';
import { createApp } from '../src/app.js';
import { WafService } from '../src/modules/waf/waf.service.js';
import { lintRaw } from '../src/modules/waf/rules/lint.js';
import { decryptKey } from '../src/modules/waf/certificates/certificates.service.js';

describe('PostgreSQL + Keystone HTTP integration', () => {
  const projectA = randomUUID(),
    projectB = randomUUID(),
    masterKey = randomBytes(32),
    serviceToken = randomBytes(24).toString('hex');
  const tokens = new Map([
    ['tenant-a', { project: projectA, roles: ['member'] }],
    ['tenant-b', { project: projectB, roles: ['member'] }],
    ['admin', { project: projectA, roles: ['admin'] }],
  ]);
  const txt = new Map<string, string[][]>();
  let identity: Server;
  let conn: ReturnType<typeof connect>;
  let admin: ReturnType<typeof connect>;
  let app: ReturnType<typeof createApp>;
  let dbName: string;
  let databaseCreated = false;
  let identityCalls = 0;
  let certDir: string;
  const origin = { address: '203.0.113.10', port: 8080, scheme: 'http' };
  const api = (token = 'tenant-a') => ({
    get: (path: string) =>
      request(app)
        .get('/v1/waf' + path)
        .set('X-Auth-Token', token),
    post: (path: string, body: unknown = {}) =>
      request(app)
        .post('/v1/waf' + path)
        .set('X-Auth-Token', token)
        .send(body),
    patch: (path: string, body: unknown) =>
      request(app)
        .patch('/v1/waf' + path)
        .set('X-Auth-Token', token)
        .send(body),
    del: (path: string) =>
      request(app)
        .delete('/v1/waf' + path)
        .set('X-Auth-Token', token),
  });
  const createSite = async () => {
    const res = await api().post('/sites', {
      hostname: `shop-${randomBytes(4).toString('hex')}.example.com`,
      origins: [origin],
    });
    expect(res.status, res.text).toBe(202);
    return res.body;
  };
  beforeAll(async () => {
    const base = process.env.DATABASE_URL;
    if (!base) throw new Error('DATABASE_URL required: start compose and source .local/dev.env');
    admin = connect(base);
    dbName = 'waf_test_' + randomBytes(8).toString('hex');
    await admin.db.execute(sql`CREATE DATABASE ${sql.identifier(dbName)}`);
    databaseCreated = true;
    const url = new URL(base);
    url.pathname = '/' + dbName;
    await migrateDatabase(url.toString());
    conn = connect(url.toString());
    identity = createServer((req, res) => {
      identityCalls++;
      if (req.url !== '/v3/auth/tokens' || req.headers['x-auth-token'] !== serviceToken) {
        res.writeHead(403).end();
        return;
      }
      const name = req.headers['x-subject-token'] as string;
      const t = tokens.get(name);
      if (!t) {
        res.writeHead(404).end();
        return;
      }
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          token: {
            expires_at: new Date(Date.now() + 60000).toISOString(),
            user: { id: 'test-user' },
            project: { id: t.project.replaceAll('-', '') },
            roles: t.roles.map((name) => ({ name })),
          },
        }),
      );
    });
    await new Promise<void>((r) => identity.listen(0, '127.0.0.1', r));
    const address = identity.address();
    if (!address || typeof address === 'string') throw new Error('identity address');
    const service = new WafService(conn.db, {
      region: 'local-1',
      dnsTarget: 'edge.localhost',
      masterKey,
      resolveTxt: async (name) => txt.get(name) ?? [],
      lint: lintRaw(resolve('../waf-node/bin/waf-lint')),
    });
    app = createApp(service, {
      url: `http://127.0.0.1:${address.port}`,
      serviceToken: async () => serviceToken,
    });
    certDir = await mkdtemp(join(tmpdir(), 'waf-cert-test-'));
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        join(certDir, 'key.pem'),
        '-out',
        join(certDir, 'cert.pem'),
        '-days',
        '1',
        '-subj',
        '/CN=cert.example.com',
        '-addext',
        'subjectAltName=DNS:cert.example.com',
      ],
      { stdio: 'ignore' },
    );
  }, 30000);
  afterAll(async () => {
    if (identity) await new Promise<void>((r, j) => identity.close((e) => (e ? j(e) : r())));
    if (conn) await conn.close();
    if (admin) {
      if (databaseCreated) await admin.db.execute(sql`DROP DATABASE ${sql.identifier(dbName)}`);
      await admin.close();
    }
    if (certDir) await rm(certDir, { recursive: true });
  });
  it('requires validated project tokens and caches only successful authentication', async () => {
    expect((await request(app).get('/v1/waf/sites')).status).toBe(401);
    expect((await api('bad').get('/sites')).status).toBe(401);
    const before = identityCalls;
    expect((await api().get('/sites')).status).toBe(200);
    expect((await api().get('/sites')).status).toBe(200);
    expect(identityCalls - before).toBe(1);
    expect((await request(app).get('/waf/v1/sites').set('X-Auth-Token', 'tenant-a')).status).toBe(
      200,
    );
  });
  it('creates, reads, updates, lists, and deletes policies; enforces tenant scope', async () => {
    const made = await api().post('/policies', { name: 'Shop policy' });
    expect(made.status, made.text).toBe(201);
    const id = made.body.id;
    expect(made.body.engine_mode).toBe('detect');
    expect((await api().get('/policies')).body.policies.some((p: any) => p.id === id)).toBe(true);
    expect((await api().get('/policies/' + id)).status).toBe(200);
    expect((await api('tenant-b').get('/policies/' + id)).status).toBe(404);
    expect((await api('tenant-b').patch('/policies/' + id, { name: 'stolen' })).status).toBe(404);
    expect((await api('tenant-b').del('/policies/' + id)).status).toBe(404);
    expect((await api().patch('/policies/' + id, { paranoia_level: 5 })).status).toBe(422);
    expect((await api().patch('/policies/' + id, { engine_mode: 'block' })).body.engine_mode).toBe(
      'block',
    );
    expect((await api().del('/policies/' + id)).status).toBe(204);
    expect((await api().get('/policies/' + id)).status).toBe(404);
  });
  it('creates pending sites, verifies DNS exactly, and queues revisions transactionally', async () => {
    const site = await createSite();
    expect(site.status).toBe('pending');
    expect(site.config_revision).toBe(1);
    expect((await api().get('/sites/' + site.id)).body.origins).toHaveLength(1);
    expect((await api().get('/sites')).body.sites.some((s: any) => s.id === site.id)).toBe(true);
    expect((await api('tenant-b').get('/sites/' + site.id)).status).toBe(404);
    expect((await api('tenant-b').post(`/sites/${site.id}/verify`)).status).toBe(404);
    expect(
      (await api('tenant-b').patch('/sites/' + site.id, { http_redirect: false })).status,
    ).toBe(404);
    expect((await api('tenant-b').del('/sites/' + site.id)).status).toBe(404);
    expect(
      (await api().post('/sites', { hostname: site.hostname, origins: [origin] })).status,
    ).toBe(409);
    expect((await api().post(`/sites/${site.id}/verify`)).status).toBe(422);
    txt.set(site.verification.name, [
      [site.verification.value.slice(0, 10), site.verification.value.slice(10)],
    ]);
    const verified = await api().post(`/sites/${site.id}/verify`);
    expect(verified.status, verified.text).toBe(202);
    expect(verified.body.status).toBe('provisioning');
    expect(verified.body.config_revision).toBe(2);
    expect((await api().post(`/sites/${site.id}/verify`)).body.config_revision).toBe(2);
    const rows = await conn.db.select().from(schema.jobs).where(eq(schema.jobs.siteId, site.id));
    expect(rows).toHaveLength(1);
    expect(rows[0].revision).toBe(2);
    expect(
      (await api().patch('/sites/' + site.id, { hostname: 'changed.example.com' })).status,
    ).toBe(422);
    expect((await api().patch('/sites/' + site.id, { http_redirect: true })).status).toBe(422);
    expect(
      (await api().patch('/sites/' + site.id, { http_redirect: false })).body.config_revision,
    ).toBe(3);
    expect((await api().del('/sites/' + site.id)).status).toBe(202);
    expect((await api().get('/sites/' + site.id)).body.status).toBe('deleting');
  });
  it('manages origins, prevents cross-project writes and preserves at least one origin', async () => {
    const site = await createSite();
    const list = await api().get(`/sites/${site.id}/origins`);
    const first = list.body.origins[0].id;
    expect((await api().del(`/sites/${site.id}/origins/${first}`)).status).toBe(409);
    expect((await api('tenant-b').get(`/sites/${site.id}/origins`)).status).toBe(404);
    expect((await api('tenant-b').post(`/sites/${site.id}/origins`, origin)).status).toBe(404);
    expect((await api('tenant-b').del(`/sites/${site.id}/origins/${first}`)).status).toBe(404);
    const added = await api().post(`/sites/${site.id}/origins`, {
      ...origin,
      address: '203.0.113.11',
    });
    expect(added.status).toBe(201);
    expect((await api().del(`/sites/${site.id}/origins/${added.body.id}`)).status).toBe(204);
    expect((await api().post(`/sites/${site.id}/origins`, { ...origin, port: 0 })).status).toBe(
      422,
    );
  });
  it('validates all rule kinds and increments every attached site revision', async () => {
    const site = await createSite();
    const policyId = site.policy_id;
    const path = `/policies/${policyId}/rules`;
    const specs = [
      { type: 'ip_allow', spec: { cidrs: ['192.0.2.0/24'] } },
      { type: 'ip_deny', spec: { cidrs: ['2001:db8::/32'] } },
      { type: 'geo_deny', spec: { countries: ['TW'] } },
      {
        type: 'rule_exclusion',
        spec: { rule_ids: [942100], args: ['search'], path_prefix: '/search' },
      },
      { type: 'path_exclusion', spec: { path_prefix: '/health' } },
      { type: 'rate_limit', spec: { key: 'ip', limit: 100, window_s: 60, action: 'block' } },
    ];
    for (const spec of specs) expect((await api().post(path, spec)).status).toBe(201);
    const list = await api().get(path);
    expect(list.body.rules).toHaveLength(6);
    const id = list.body.rules[0].id;
    expect((await api('tenant-b').get(path)).status).toBe(404);
    expect((await api('tenant-b').post(path, specs[0])).status).toBe(404);
    expect((await api('tenant-b').patch(path + '/' + id, { enabled: false })).status).toBe(404);
    expect((await api('tenant-b').del(path + '/' + id)).status).toBe(404);
    expect((await api().patch(path + '/' + id, { enabled: false })).body.enabled).toBe(false);
    expect((await api().del(path + '/' + id)).status).toBe(204);
    expect((await api().get('/sites/' + site.id)).body.config_revision).toBe(9);
    expect(
      (await api().post(path, { type: 'ip_deny', spec: { cidrs: ['192.0.2.0/99'] } })).status,
    ).toBe(422);
    expect(
      (
        await api().post(path, {
          type: 'path_exclusion',
          spec: { path_prefix: '/safe"\nSecRuleEngine Off' },
        })
      ).status,
    ).toBe(422);
    const raw = {
      type: 'raw',
      spec: { seclang: 'SecRule ARGS:q "@contains attack" "id:9000100,phase:2,deny,status:403"' },
    };
    expect((await api().post(path, raw)).status).toBe(403);
    expect((await api('admin').post(path, raw)).status).toBe(201);
    expect(
      (
        await api('admin').post(path, {
          type: 'raw',
          spec: { seclang: 'SecRule ARGS:q "@rx [" "id:9000101,phase:2,deny"' },
        })
      ).status,
    ).toBe(422);
    expect(
      (await api('admin').post(path, { type: 'raw', spec: { seclang: 'Include /etc/passwd' } }))
        .status,
    ).toBe(422);
    expect((await api().del('/policies/' + policyId)).status).toBe(409);
  });
  it('encrypts certificate keys, validates coverage, and never returns private material', async () => {
    const cert_pem = await readFile(join(certDir, 'cert.pem'), 'utf8'),
      key_pem = await readFile(join(certDir, 'key.pem'), 'utf8');
    const made = await api().post('/certificates', {
      source: 'upload',
      domains: ['cert.example.com'],
      cert_pem,
      key_pem,
    });
    expect(made.status, made.text).toBe(202);
    const id = made.body.id;
    expect(made.text).not.toContain('PRIVATE KEY');
    expect(made.body).not.toHaveProperty('key_pem_encrypted');
    expect((await api().get('/certificates')).body.certificates.some((c: any) => c.id === id)).toBe(
      true,
    );
    expect((await api().get('/certificates/' + id)).status).toBe(200);
    expect((await api('tenant-b').get('/certificates/' + id)).status).toBe(404);
    expect((await api('tenant-b').del('/certificates/' + id)).status).toBe(404);
    const [stored] = await conn.db
      .select()
      .from(schema.certificates)
      .where(eq(schema.certificates.id, id));
    expect(stored.keyPemEncrypted).not.toContain('PRIVATE KEY');
    expect(decryptKey(stored.keyPemEncrypted!, masterKey, `${projectA}:${id}`)).toBe(key_pem);
    expect(() => decryptKey(stored.keyPemEncrypted!, masterKey, `${projectB}:${id}`)).toThrow();
    expect(
      (
        await api().post('/certificates', {
          source: 'upload',
          domains: ['wrong.example.com'],
          cert_pem,
          key_pem,
        })
      ).status,
    ).toBe(422);
    expect(
      (
        await api().post('/certificates', {
          source: 'upload',
          domains: ['cert.example.com'],
          cert_pem,
          key_pem: 'invalid',
        })
      ).status,
    ).toBe(422);
    const site = (await api().post('/sites', { hostname: 'cert.example.com', origins: [origin] }))
      .body;
    expect(
      (await api().patch('/sites/' + site.id, { certificate_id: id, http_redirect: true })).status,
    ).toBe(200);
    expect((await api().del('/certificates/' + id)).status).toBe(409);
    expect(
      (await api().patch('/sites/' + site.id, { certificate_id: null, http_redirect: false }))
        .status,
    ).toBe(200);
    expect((await api().del('/certificates/' + id)).status).toBe(204);
    expect(
      (await api().post('/certificates', { source: 'acme', domains: ['unowned.example.com'] }))
        .status,
    ).toBe(422);
  });
  it('restricts node management to administrators and audits mutation identities', async () => {
    const [node] = await conn.db
      .insert(schema.nodes)
      .values({
        regionId: 'local-1',
        kind: 'edge',
        mgmtIp: '192.0.2.1',
        publicIp: '203.0.113.1',
        version: 'test',
      })
      .returning();
    expect((await api().get('/nodes')).status).toBe(403);
    expect((await api().post(`/nodes/${node.id}/drain`)).status).toBe(403);
    expect((await api('admin').get('/nodes')).body.nodes).toHaveLength(1);
    expect((await api('admin').post(`/nodes/${node.id}/drain`)).body.status).toBe('draining');
    const audit = await conn.db
      .select()
      .from(schema.audit)
      .where(eq(schema.audit.resourceId, node.id));
    expect(audit[0].userId).toBe('test-user');
    expect(audit[0].action).toBe('node.drain');
  });
  it('serves generated OpenAPI and reports unavailable later-phase analytics explicitly', async () => {
    expect((await request(app).get('/readyz')).status).toBe(200);
    expect((await request(app).get('/healthz')).status).toBe(200);
    const spec = await request(app).get('/openapi.json');
    expect(spec.status, spec.text).toBe(200);
    expect(spec.body.paths['/sites/{id}'].patch).toBeDefined();
    expect(Object.keys(spec.body.paths).length).toBeGreaterThan(10);
    const site = await createSite();
    for (const path of ['events', 'metrics']) {
      expect((await api().get(`/sites/${site.id}/${path}`)).status).toBe(501);
      expect((await api('tenant-b').get(`/sites/${site.id}/${path}`)).status).toBe(404);
    }
    expect((await api().post(`/sites/${site.id}/events/${randomUUID()}/exclude`)).status).toBe(501);
    expect((await api().get('/sites/not-a-uuid')).status).toBe(422);
  });
});
