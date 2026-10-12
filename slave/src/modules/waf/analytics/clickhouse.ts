import { HttpError } from '../errors.js';
export type ClickHouseOptions = {
  url: string;
  username: string;
  password: string;
  database?: string;
};
export class ClickHouse {
  readonly database: string;
  constructor(readonly options: ClickHouseOptions) {
    const url = new URL(options.url);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password)
      throw new Error('Invalid ClickHouse URL');
    this.database = options.database ?? 'waf';
    if (!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(this.database))
      throw new Error('Invalid ClickHouse database name');
  }
  async execute(
    query: string,
    params: Record<string, string | number> = {},
    data?: string,
    withoutDatabase = false,
  ) {
    const url = new URL(this.options.url);
    if (!withoutDatabase) url.searchParams.set('database', this.database);
    url.searchParams.set('query', query);
    url.searchParams.set('date_time_input_format', 'best_effort');
    url.searchParams.set('date_time_output_format', 'iso');
    url.searchParams.set('output_format_json_quote_64bit_integers', '0');
    for (const [name, value] of Object.entries(params))
      url.searchParams.set('param_' + name, String(value));
    let response: Response;
    try {
      response = await fetch(url, {
        method: 'POST',
        headers: {
          Authorization:
            'Basic ' +
            Buffer.from(`${this.options.username}:${this.options.password}`).toString('base64'),
          'Content-Type': 'text/plain',
        },
        body: data ?? '',
        signal: AbortSignal.timeout(15000),
        redirect: 'error',
      });
    } catch {
      throw new HttpError(503, 'analytics_unavailable', 'Analytics is temporarily unavailable');
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new HttpError(503, 'analytics_unavailable', 'Analytics is temporarily unavailable');
    }
    return response.text();
  }
  async rows<T>(query: string, params: Record<string, string | number> = {}) {
    return JSON.parse(await this.execute(query + ' FORMAT JSON', params)).data as T[];
  }
  async insert(table: 'waf_events' | 'waf_requests_1m', rows: unknown[]) {
    if (rows.length)
      await this.execute(
        `INSERT INTO ${table} FORMAT JSONEachRow`,
        {},
        rows.map((r) => JSON.stringify(r)).join('\n'),
      );
  }
  async migrate() {
    await this.execute(`CREATE DATABASE IF NOT EXISTS ${this.database}`, {}, undefined, true);
    await this.execute(`CREATE TABLE IF NOT EXISTS waf_events (
    project_id UUID, region_id String, site_id UUID, node_id UUID, event_id String,
    timestamp DateTime64(3,'UTC'), action LowCardinality(String), method LowCardinality(String),
    path String, client_ip String, rule_ids Array(UInt32), status UInt16, duration_ms Float64
  ) ENGINE=ReplacingMergeTree PARTITION BY toYYYYMMDD(timestamp)
  ORDER BY (project_id,region_id,site_id,event_id) TTL toDateTime(timestamp)+INTERVAL 30 DAY DELETE
  SETTINGS ttl_only_drop_parts=0`);
    await this.execute(`CREATE TABLE IF NOT EXISTS waf_requests_1m (
    project_id UUID, region_id String, site_id UUID, node_id UUID, batch_id String,
    minute DateTime('UTC'), action LowCardinality(String), requests UInt64, bytes_out UInt64, duration_ms Float64
  ) ENGINE=ReplacingMergeTree PARTITION BY toYYYYMMDD(minute)
  ORDER BY (project_id,region_id,site_id,node_id,minute,batch_id,action)
  TTL minute+INTERVAL 30 DAY DELETE SETTINGS ttl_only_drop_parts=0`);
  }
}
export function clickHouseFromEnv() {
  if (!process.env.CLICKHOUSE_URL) return undefined;
  return new ClickHouse({
    url: process.env.CLICKHOUSE_URL,
    username: process.env.CLICKHOUSE_USER ?? 'waf',
    password: process.env.CLICKHOUSE_PASSWORD ?? '',
    database: process.env.CLICKHOUSE_DATABASE ?? 'waf',
  });
}
