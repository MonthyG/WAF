import {
  pgTable,
  uuid,
  text,
  timestamp,
  integer,
  bigint,
  boolean,
  jsonb,
  uniqueIndex,
  index,
  numeric,
} from 'drizzle-orm/pg-core';

const meta = () => ({
  id: uuid('id').primaryKey().defaultRandom(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});
const tenant = () => ({
  projectId: uuid('project_id').notNull(),
  regionId: text('region_id').notNull(),
});

export const policies = pgTable(
  'waf_policies',
  {
    ...meta(),
    ...tenant(),
    name: text('name').notNull(),
    engineMode: text('engine_mode').notNull().default('detect'),
    paranoiaLevel: integer('paranoia_level').notNull().default(1),
    inboundAnomalyThreshold: integer('inbound_anomaly_threshold').notNull().default(5),
    outboundAnomalyThreshold: integer('outbound_anomaly_threshold').notNull().default(4),
    requestBodyLimitKb: integer('request_body_limit_kb').notNull().default(1024),
    inspectResponseBody: boolean('inspect_response_body').notNull().default(false),
  },
  (t) => [index('waf_policies_project_idx').on(t.projectId)],
);

export const certificates = pgTable('waf_certificates', {
  ...meta(),
  ...tenant(),
  source: text('source').notNull(),
  domains: jsonb('domains').$type<string[]>().notNull(),
  certPem: text('cert_pem'),
  keyPemEncrypted: text('key_pem_encrypted'),
  notAfter: timestamp('not_after', { withTimezone: true }),
  acmeStatus: text('acme_status'),
  lastError: text('last_error'),
});

export const sites = pgTable(
  'waf_sites',
  {
    ...meta(),
    ...tenant(),
    hostname: text('hostname').notNull(),
    mode: text('mode').notNull().default('shared'),
    status: text('status').notNull().default('pending'),
    policyId: uuid('policy_id')
      .notNull()
      .references(() => policies.id),
    certificateId: uuid('certificate_id').references(() => certificates.id),
    httpRedirect: boolean('http_redirect').notNull().default(false),
    configRevision: bigint('config_revision', { mode: 'number' }).notNull().default(1),
    appliedRevision: bigint('applied_revision', { mode: 'number' }).notNull().default(0),
    verificationToken: text('verification_token').notNull(),
    verifiedAt: timestamp('verified_at', { withTimezone: true }),
    lastError: text('last_error'),
  },
  (t) => [
    uniqueIndex('waf_sites_hostname_region_idx').on(t.hostname, t.regionId),
    index('waf_sites_project_idx').on(t.projectId),
  ],
);

export const origins = pgTable('waf_origins', {
  ...meta(),
  ...tenant(),
  siteId: uuid('site_id')
    .notNull()
    .references(() => sites.id, { onDelete: 'cascade' }),
  address: text('address').notNull(),
  port: integer('port').notNull(),
  scheme: text('scheme').notNull(),
  weight: integer('weight').notNull().default(1),
  healthCheckPath: text('health_check_path').notNull().default('/'),
  instanceId: uuid('instance_id'),
});

export const rules = pgTable('waf_rules', {
  ...meta(),
  ...tenant(),
  policyId: uuid('policy_id')
    .notNull()
    .references(() => policies.id, { onDelete: 'cascade' }),
  priority: integer('priority').notNull(),
  type: text('type').notNull(),
  spec: jsonb('spec').$type<Record<string, unknown>>().notNull(),
  enabled: boolean('enabled').notNull().default(true),
});

export const nodes = pgTable('waf_nodes', {
  publicKeyPem: text('public_key_pem'),
  ...meta(),
  regionId: text('region_id').notNull(),
  kind: text('kind').notNull(),
  projectId: uuid('project_id'),
  novaInstanceId: uuid('nova_instance_id'),
  mgmtIp: text('mgmt_ip').notNull(),
  publicIp: text('public_ip').notNull(),
  version: text('version').notNull(),
  status: text('status').notNull().default('offline'),
  lastHeartbeatAt: timestamp('last_heartbeat_at', { withTimezone: true }),
  appliedRevisionMap: jsonb('applied_revision_map')
    .$type<Record<string, number>>()
    .notNull()
    .default({}),
});

export const siteNodes = pgTable(
  'waf_site_nodes',
  {
    ...meta(),
    siteId: uuid('site_id')
      .notNull()
      .references(() => sites.id, { onDelete: 'cascade' }),
    nodeId: uuid('node_id')
      .notNull()
      .references(() => nodes.id, { onDelete: 'cascade' }),
  },
  (t) => [uniqueIndex('waf_site_nodes_unique').on(t.siteId, t.nodeId)],
);

export const products = pgTable('cloud_waf_products', {
  ...meta(),
  regionId: text('region_id').notNull(),
  name: text('name').notNull(),
  mode: text('mode').notNull(),
  monthlyPrice: numeric('monthly_price', { precision: 12, scale: 4 }).notNull(),
  includedRequestsM: integer('included_requests_m').notNull(),
  perMillionPrice: numeric('per_million_price', { precision: 12, scale: 4 }).notNull(),
  includedSites: integer('included_sites').notNull(),
  hidden: boolean('hidden').notNull().default(false),
});

// The transactional outbox prevents a committed revision being lost if Redis is down.
export const jobs = pgTable('waf_jobs', {
  ...meta(),
  kind: text('kind').notNull(),
  siteId: uuid('site_id'),
  revision: bigint('revision', { mode: 'number' }),
  payload: jsonb('payload').$type<Record<string, unknown>>().notNull().default({}),
  status: text('status').notNull().default('pending'),
  attempts: integer('attempts').notNull().default(0),
  lastError: text('last_error'),
});

export const audit = pgTable('waf_audit', {
  ...meta(),
  ...tenant(),
  userId: text('user_id').notNull(),
  action: text('action').notNull(),
  resourceId: uuid('resource_id').notNull(),
});

export const bundles = pgTable(
  'waf_bundles',
  {
    ...meta(),
    siteId: uuid('site_id')
      .notNull()
      .references(() => sites.id, { onDelete: 'cascade' }),
    revision: bigint('revision', { mode: 'number' }).notNull(),
    payload: jsonb('payload').$type<Record<string, unknown>>().notNull(),
  },
  (t) => [uniqueIndex('waf_bundles_site_unique').on(t.siteId)],
);

export const challenges = pgTable(
  'waf_acme_challenges',
  {
    ...meta(),
    siteId: uuid('site_id')
      .notNull()
      .references(() => sites.id, { onDelete: 'cascade' }),
    token: text('token').notNull(),
    authorization: text('authorization').notNull(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  },
  (t) => [uniqueIndex('waf_acme_challenge_unique').on(t.siteId, t.token)],
);

export const acmeAccounts = pgTable(
  'waf_acme_accounts',
  {
    ...meta(),
    directory: text('directory').notNull(),
    email: text('email').notNull(),
    keyEncrypted: text('key_encrypted').notNull(),
  },
  (t) => [uniqueIndex('waf_acme_account_unique').on(t.directory, t.email)],
);

// Preserve routing provenance after site deletion so delayed telemetry can be
// attributed without trusting a node's claimed tenant or billing identity.
export const siteNodeHistory = pgTable(
  'waf_site_node_history',
  {
    ...meta(),
    ...tenant(),
    siteId: uuid('site_id').notNull(),
    nodeId: uuid('node_id').notNull(),
  },
  (t) => [uniqueIndex('waf_site_node_history_unique').on(t.siteId, t.nodeId)],
);
