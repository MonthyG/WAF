import { it, expect } from 'vitest';
import * as acme from 'acme-client';
import { randomBytes, randomUUID, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { Agent as HTTPAgent, createServer } from 'node:http';
import { Agent as HTTPSAgent, request as httpsRequest } from 'node:https';
import { createServer as tcpServer } from 'node:net';
import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdir, writeFile, mkdtemp, readFile, rm } from 'node:fs/promises';
import { eq, sql } from 'drizzle-orm';
import { connect } from '../src/db/index.js';
import { migrateDatabase } from '../src/db/migrate.js';
import * as s from '../src/db/schema.js';
import { WafService } from '../src/modules/waf/waf.service.js';
import { AcmeService } from '../src/modules/waf/certificates/acme.service.js';
import { startWorker } from '../src/workers/waf-worker.js';
import { siteInput, sitePatch } from '../src/modules/waf/validation.js';
import { lintRaw } from '../src/modules/waf/rules/lint.js';

async function waitFor<T>(
  fn: () => Promise<T>,
  check: (v: T) => boolean,
  timeout = 30000,
): Promise<T> {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await fn();
    if (check(value)) return value;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('Condition timed out');
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

it('issues and renews through Pebble with real HTTP-01 validation and trusted HTTPS', async () => {
  const base = process.env.DATABASE_URL;
  if (!base) throw new Error('DATABASE_URL required');
  let databaseCreated = false;
  const admin = connect(base),
    dbName = 'waf_acme_' + randomBytes(8).toString('hex');
  const temp = await mkdtemp(resolve(tmpdir(), 'waf-acme-'));
  const containers: string[] = [];
  let db: ReturnType<typeof connect> | undefined,
    worker: Awaited<ReturnType<typeof startWorker>> | undefined,
    agent: ChildProcess | undefined,
    logs = '';
  const httpPort = await port(),
    tlsPort = await port(),
    mgmtPort = await port(),
    caPort = await port(),
    caMgmt = await port();
  const masterKey = randomBytes(32),
    nodeId = randomUUID();
  const origin = createServer((_req, res) => res.end('origin'));
  const oldHTTP = acme.axios.defaults.httpAgent,
    oldHTTPS = acme.axios.defaults.httpsAgent,
    oldProxy = acme.axios.defaults.proxy;
  const settings = (
    acme.axios.defaults as typeof acme.axios.defaults & {
      acmeSettings: { httpChallengePort: number };
    }
  ).acmeSettings;
  const oldPort = settings.httpChallengePort;
  try {
    const nodeKey = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    await writeFile(resolve(temp, 'node.pem'), nodeKey.privateKey, { mode: 0o600 });
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        resolve(temp, 'ca-key.pem'),
        '-out',
        resolve(temp, 'ca.pem'),
        '-days',
        '1',
        '-subj',
        '/CN=localhost',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
      ],
      { stdio: 'ignore' },
    );
    const ca = await readFile(resolve(temp, 'ca.pem'), 'utf8');
    await writeFile(
      resolve(temp, 'pebble.json'),
      JSON.stringify({
        pebble: {
          listenAddress: `127.0.0.1:${caPort}`,
          managementListenAddress: `127.0.0.1:${caMgmt}`,
          certificate: '/test/ca.pem',
          privateKey: '/test/ca-key.pem',
          httpPort,
          tlsPort,
          externalAccountBindingRequired: false,
          profiles: { default: { description: 'test', validityPeriod: 3600 } },
        },
      }),
    );
    const pebble = execFileSync(
      'docker',
      [
        'run',
        '--rm',
        '-d',
        '--network',
        'host',
        '--add-host',
        'shop.localhost:127.0.0.1',
        '-v',
        `${temp}:/test:ro`,
        '-e',
        'PEBBLE_VA_NOSLEEP=1',
        '-e',
        'PEBBLE_AUTHZREUSE=0',
        'ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199',
        '-config',
        '/test/pebble.json',
        '-strict',
      ],
      { encoding: 'utf8' },
    ).trim();
    containers.push(pebble);
    const container = (image: string, inside: number, args: string[]) => {
      const id = execFileSync(
        'docker',
        ['run', '--rm', '-d', '-p', `127.0.0.1::${inside}`, image, ...args],
        { encoding: 'utf8' },
      ).trim();
      containers.push(id);
      return execFileSync('docker', ['port', id, String(inside)], { encoding: 'utf8' }).trim();
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
    acme.axios.defaults.httpsAgent = new HTTPSAgent({ ca });
    acme.axios.defaults.httpAgent = new HTTPAgent({
      lookup: ((_name: unknown, options: any, callback: any) =>
        options.all
          ? callback(null, [{ address: '127.0.0.1', family: 4 }])
          : callback(null, '127.0.0.1', 4)) as any,
    });
    acme.axios.defaults.proxy = false;
    settings.httpChallengePort = httpPort;
    const directoryURL = `https://127.0.0.1:${caPort}/dir`,
      email = 'operator@example.test';
    await waitFor(
      async () => {
        try {
          return (await acme.axios.get(directoryURL)).status;
        } catch {
          return 0;
        }
      },
      (status) => status === 200,
    );
    await admin.db.execute(sql`CREATE DATABASE ${sql.identifier(dbName)}`);
    databaseCreated = true;
    const url = new URL(base);
    url.pathname = '/' + dbName;
    await migrateDatabase(url.toString());
    db = connect(url.toString());
    await db.db
      .insert(s.nodes)
      .values({
        id: nodeId,
        regionId: 'local-1',
        kind: 'edge',
        mgmtIp: '127.0.0.1',
        publicIp: '127.0.0.1',
        version: 'test',
        publicKeyPem: nodeKey.publicKey,
      });
    worker = await startWorker(db.db, {
      masterKey,
      redisURL: 'redis://' + redis,
      natsURL: 'nats://' + nats,
      region: 'local-1',
      lintBinary: resolve('../waf-node/bin/waf-lint'),
      queueName: 'acme-' + randomBytes(4).toString('hex'),
      acme: { directoryURL, email, termsAgreed: true },
    });
    agent = spawn(
      resolve('../waf-node/bin/waf-agent'),
      [
        '-node-id',
        nodeId,
        '-node-key',
        resolve(temp, 'node.pem'),
        '-nats',
        'nats://' + nats,
        '-listen',
        `127.0.0.1:${httpPort}`,
        '-tls-listen',
        `127.0.0.1:${tlsPort}`,
        '-management',
        `127.0.0.1:${mgmtPort}`,
      ],
      { stdio: ['ignore', 'pipe', 'pipe'] },
    );
    agent.stdout?.on('data', (b) => (logs += String(b)));
    agent.stderr?.on('data', (b) => (logs += String(b)));
    await waitFor(
      () => db!.db.select().from(s.nodes),
      (rows) => rows[0]?.status === 'online',
    );
    origin.listen(0, '127.0.0.1');
    await once(origin, 'listening');
    const address = origin.address();
    if (!address || typeof address === 'string') throw new Error('origin address');
    const txt = new Map<string, string[][]>(),
      ctx = { projectId: randomUUID(), userId: 'test', roles: ['admin'] };
    const svc = new WafService(db.db, {
      region: 'local-1',
      dnsTarget: 'edge.localhost',
      masterKey,
      resolveTxt: async (name) => txt.get(name) ?? [],
      lint: lintRaw(resolve('../waf-node/bin/waf-lint')),
    });
    const site = await svc.createSite(
      ctx,
      siteInput.parse({
        hostname: 'shop.localhost',
        tls: { source: 'acme' },
        origins: [{ address: '127.0.0.1', port: address.port, scheme: 'http' }],
      }),
    );
    const id = String(site.id),
      certId = String(site.certificate_id),
      verification = site.verification as { name: string; value: string };
    txt.set(verification.name, [[verification.value]]);
    await svc.verifySite(ctx, id);
    const certificate = async () => {
      const [c] = await db!.db.select().from(s.certificates).where(eq(s.certificates.id, certId));
      return c;
    };
    const issued = await waitFor(certificate, (c) => c.acmeStatus === 'valid', 60000);
    expect(issued.keyPemEncrypted).not.toContain('PRIVATE KEY');
    expect(issued.certPem).toContain('BEGIN CERTIFICATE');
    const root = (await acme.axios.get(`https://127.0.0.1:${caMgmt}/roots/0`)).data;
    const requestTLS = () =>
      new Promise<string>((resolve, reject) => {
        const req = httpsRequest(
          {
            hostname: '127.0.0.1',
            port: tlsPort,
            servername: 'shop.localhost',
            headers: { Host: 'shop.localhost' },
            ca: root,
            agent: false,
          },
          (res) => {
            let body = '';
            res.on('data', (b) => (body += String(b)));
            res.on('end', () =>
              res.statusCode === 200 ? resolve(body) : reject(new Error('Unexpected HTTPS status')),
            );
          },
        );
        req.on('error', reject);
        req.end();
      });
    await waitFor(
      () => svc.getSite(ctx, id),
      (v) => v.status === 'active' && v.config_revision === v.applied_revision,
    );
    expect(await requestTLS()).toBe('origin');
    // Pebble issues genuinely short-lived certificates, so renewal is due immediately.
    await svc.updateSite(ctx, id, sitePatch.parse({ http_redirect: true }));
    expect(issued.notAfter!.getTime() - Date.now()).toBeLessThan(3600000);
    const issuer = new AcmeService(db.db, {
      directoryURL,
      email,
      termsAgreed: true,
      masterKey,
      region: 'local-1',
    });
    // The certificate becomes valid before its issuance job finishes cleanup.
    // Renewal intentionally deduplicates pending jobs; wait for that completion
    // rather than racing it and waiting an hour for the next scheduled sweep.
    await waitFor(
      () => db!.db.select().from(s.jobs).where(eq(s.jobs.kind, 'cert.issue')),
      (jobs) => jobs.length > 0 && jobs.every((job) => job.status === 'done'),
    );
    await issuer.scheduleRenewals();
    const renewed = await waitFor(
      certificate,
      (c) => c.acmeStatus === 'valid' && c.certPem !== issued.certPem,
      60000,
    );
    expect(new X509Certificate(renewed.certPem!).serialNumber).not.toBe(
      new X509Certificate(issued.certPem!).serialNumber,
    );
    await waitFor(
      () => svc.getSite(ctx, id),
      (v) => v.status === 'active' && v.config_revision === v.applied_revision,
    );
    expect(await requestTLS()).toBe('origin');
    expect(await db.db.select().from(s.challenges)).toHaveLength(0);
    const accounts = await db.db.select().from(s.acmeAccounts);
    expect(accounts).toHaveLength(1);
    expect(accounts[0].keyEncrypted).not.toContain('PRIVATE KEY');
    await mkdir('../docs/validation', { recursive: true });
    await writeFile(
      '../docs/validation/acme.json',
      JSON.stringify(
        {
          recorded_at: new Date().toISOString(),
          ca: 'Pebble',
          real_http01_validation: true,
          issuance_verified: true,
          renewal_verified: true,
          certificate_lifetime_seconds: 3600,
          renewal_with_https_redirect: true,
          tls_chain_verified: true,
          challenge_cleanup_verified: true,
          public_letsencrypt_staging_tested: false,
        },
        null,
        2,
      ) + '\n',
    );
  } finally {
    if (agent && agent.exitCode === null && agent.signalCode === null) {
      agent.kill('SIGTERM');
      await Promise.race([once(agent, 'exit'), new Promise((r) => setTimeout(r, 3000))]);
      if (agent.exitCode === null && agent.signalCode === null) agent.kill('SIGKILL');
    }
    if (worker) await worker.close();
    await new Promise<void>((r) => origin.close(() => r()));
    for (const id of containers) {
      try {
        logs += execFileSync('docker', ['logs', id], {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
        });
      } catch {}
      try {
        execFileSync('docker', ['stop', '-t', '1', id], { stdio: 'ignore' });
      } catch {}
    }
    if (db) await db.close();
    if (databaseCreated)
      await admin.db.execute(sql`DROP DATABASE IF EXISTS ${sql.identifier(dbName)}`);
    await admin.close();
    acme.axios.defaults.httpAgent = oldHTTP;
    acme.axios.defaults.httpsAgent = oldHTTPS;
    acme.axios.defaults.proxy = oldProxy;
    settings.httpChallengePort = oldPort;
    await mkdir('../.local', { recursive: true });
    await writeFile('../.local/acme-test.log', logs);
    await rm(temp, { recursive: true, force: true });
  }
}, 150000);
