import { z } from 'zod';
import { ClickHouse } from './clickhouse.js';
import { HttpError } from '../errors.js';

const date = z
  .string()
  .datetime({ offset: true })
  .transform((v) => Date.parse(v));
export const rangeQuery = z.object({ from: date.optional(), to: date.optional() });
export const eventsQuery = rangeQuery.extend({
  action: z.enum(['blocked', 'detected', 'error', 'rejected']).optional(),
  rule_id: z.coerce.number().int().positive().optional(),
  ip: z.string().max(64).optional(),
  limit: z.coerce.number().int().min(1).max(1000).default(100),
  cursor: z.string().max(1024).optional(),
});
export const eventID = z.string().regex(/^[A-Za-z0-9_-]{1,128}$/);
export type Event = {
  project_id: string;
  region_id: string;
  site_id: string;
  node_id: string;
  event_id: string;
  timestamp: string;
  action: string;
  method: string;
  path: string;
  client_ip: string;
  rule_ids: number[];
  status: number;
  duration_ms: number;
};
function bounds(input: z.infer<typeof rangeQuery>) {
  const to = input.to ?? Date.now(),
    from = input.from ?? to - 86400000;
  if (from >= to || to - from > 30 * 86400000)
    throw new HttpError(422, 'invalid_range', 'Choose a time range of up to 30 days');
  return { from, to };
}
export class AnalyticsService {
  constructor(
    readonly clickhouse: ClickHouse,
    readonly region: string,
  ) {}
  async events(project: string, site: string, input: z.infer<typeof eventsQuery>) {
    const params: Record<string, string | number> = {
      project,
      site,
      region: this.region,
      ...bounds(input),
      limit: input.limit + 1,
    };
    let filters = '';
    if (input.action) {
      filters += ' AND action={action:String}';
      params.action = input.action;
    }
    if (input.rule_id) {
      filters += ' AND has(rule_ids,{rule:UInt32})';
      params.rule = input.rule_id;
    }
    if (input.ip) {
      filters += ' AND client_ip={ip:String}';
      params.ip = input.ip;
    }
    if (input.cursor) {
      try {
        const cursor = z
          .object({ time: z.number().int(), id: eventID })
          .parse(JSON.parse(Buffer.from(input.cursor, 'base64url').toString()));
        params.cursorTime = cursor.time;
        params.cursorId = cursor.id;
        filters +=
          ' AND (timestamp,event_id)<(fromUnixTimestamp64Milli({cursorTime:Int64}),{cursorId:String})';
      } catch {
        throw new HttpError(422, 'invalid_cursor', 'Invalid event cursor');
      }
    }
    const rows = await this.clickhouse.rows<Event>(
      `SELECT * FROM waf_events FINAL WHERE project_id={project:UUID} AND region_id={region:String} AND site_id={site:UUID} AND timestamp>=fromUnixTimestamp64Milli({from:Int64}) AND timestamp<fromUnixTimestamp64Milli({to:Int64}) ${filters} ORDER BY timestamp DESC,event_id DESC LIMIT {limit:UInt32}`,
      params,
    );
    const more = rows.length > input.limit;
    const events = rows.slice(0, input.limit);
    const last = events.at(-1);
    return {
      events,
      next_cursor:
        more && last
          ? Buffer.from(
              JSON.stringify({ time: Date.parse(last.timestamp), id: last.event_id }),
            ).toString('base64url')
          : null,
    };
  }
  async event(project: string, site: string, id: string) {
    const [event] = await this.clickhouse.rows<Event>(
      'SELECT * FROM waf_events FINAL WHERE project_id={project:UUID} AND region_id={region:String} AND site_id={site:UUID} AND event_id={event:String} LIMIT 1',
      { project, region: this.region, site, event: id },
    );
    if (!event) throw new HttpError(404, 'not_found', 'Event not found');
    return event;
  }
  async metrics(project: string, site: string, input: z.infer<typeof rangeQuery>) {
    const params = { project, region: this.region, site, ...bounds(input) };
    const rows = await this.clickhouse.rows<{
      minute: string;
      action: string;
      requests: number;
      bytes_out: number;
      duration_ms: number;
    }>(
      `SELECT minute,action,sum(requests) AS requests,sum(bytes_out) AS bytes_out,sum(duration_ms) AS duration_ms FROM waf_requests_1m FINAL WHERE project_id={project:UUID} AND region_id={region:String} AND site_id={site:UUID} AND minute>=toStartOfMinute(fromUnixTimestamp64Milli({from:Int64})) AND minute<fromUnixTimestamp64Milli({to:Int64}) GROUP BY minute,action ORDER BY minute,action`,
      params,
    );
    const totals = {
      requests: 0,
      blocked: 0,
      detected: 0,
      errors: 0,
      bytes_out: 0,
      average_duration_ms: 0,
    };
    let duration = 0;
    for (const row of rows) {
      totals.requests += row.requests;
      totals.bytes_out += row.bytes_out;
      duration += row.duration_ms;
      if (row.action === 'blocked') totals.blocked += row.requests;
      if (row.action === 'detected') totals.detected += row.requests;
      if (['error', 'rejected'].includes(row.action)) totals.errors += row.requests;
    }
    totals.average_duration_ms = totals.requests ? duration / totals.requests : 0;
    return {
      from: new Date(params.from).toISOString(),
      to: new Date(params.to).toISOString(),
      totals,
      series: rows,
    };
  }
  async usage(project: string, input: z.infer<typeof rangeQuery>) {
    const params = { project, region: this.region, ...bounds(input) };
    // Half-open minute-aligned intervals avoid counting a boundary minute twice.
    if (params.from % 60000 || params.to % 60000)
      throw new HttpError(
        422,
        'invalid_range',
        'Metering export boundaries must align to UTC minutes',
      );
    const sites = await this.clickhouse.rows<{
      site_id: string;
      requests: number;
      bytes_out: number;
    }>(
      `SELECT site_id,sum(requests) AS requests,sum(bytes_out) AS bytes_out FROM waf_requests_1m FINAL WHERE project_id={project:UUID} AND region_id={region:String} AND minute>=fromUnixTimestamp64Milli({from:Int64}) AND minute<fromUnixTimestamp64Milli({to:Int64}) GROUP BY site_id ORDER BY site_id`,
      params,
    );
    return {
      project_id: project,
      region_id: this.region,
      from: new Date(params.from).toISOString(),
      to: new Date(params.to).toISOString(),
      unit: 'requests',
      sites,
      requests: sites.reduce((n, s) => n + s.requests, 0),
      bytes_out: sites.reduce((n, s) => n + s.bytes_out, 0),
    };
  }
}
