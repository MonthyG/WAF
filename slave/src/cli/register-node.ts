import { parseArgs } from 'node:util';
import { readFile } from 'node:fs/promises';
import { createPublicKey, randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { eq } from 'drizzle-orm';
import { connect } from '../db/index.js';
import { nodes } from '../db/schema.js';
import { uuid } from '../modules/waf/validation.js';

const { values } = parseArgs({
  options: {
    'node-id': { type: 'string' },
    'public-key': { type: 'string' },
    'public-ip': { type: 'string' },
    'mgmt-ip': { type: 'string' },
  },
});
if (
  !process.env.DATABASE_URL ||
  !values['public-key'] ||
  !values['public-ip'] ||
  !values['mgmt-ip']
)
  throw new Error('Set DATABASE_URL and provide --public-key, --public-ip, and --mgmt-ip');
if (!isIP(values['public-ip']) || !isIP(values['mgmt-ip']))
  throw new Error('Node addresses must be literal IP addresses');
const id = uuid.parse(values['node-id'] ?? randomUUID()),
  region = process.env.WAF_REGION ?? 'local-1';
const pem = await readFile(values['public-key'], 'utf8');
if (pem.includes('PRIVATE KEY')) throw new Error('Provide only the node public key');
const key = createPublicKey(pem);
if (key.asymmetricKeyType !== 'rsa' || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048)
  throw new Error('Node public key must be RSA with at least 2048 bits');
const publicKeyPem = key.export({ type: 'spki', format: 'pem' }).toString();
const conn = connect(process.env.DATABASE_URL);
try {
  const [existing] = await conn.db.select().from(nodes).where(eq(nodes.id, id));
  if (existing) {
    if (
      existing.publicKeyPem !== publicKeyPem ||
      existing.regionId !== region ||
      existing.publicIp !== values['public-ip'] ||
      existing.mgmtIp !== values['mgmt-ip']
    )
      throw new Error('Node exists with different settings; drain and replace it explicitly');
  } else
    await conn.db
      .insert(nodes)
      .values({
        id,
        regionId: region,
        kind: 'edge',
        publicIp: values['public-ip'],
        mgmtIp: values['mgmt-ip'],
        publicKeyPem,
        version: '0.1.0',
      });
  console.log(id);
} finally {
  await conn.close();
}
