import { parseArgs } from 'node:util';
import { uuid } from '../modules/waf/validation.js';
import { AnalyticsService, rangeQuery } from '../modules/waf/analytics/analytics.service.js';
import { clickHouseFromEnv } from '../modules/waf/analytics/clickhouse.js';
const { values } = parseArgs({
  options: { 'project-id': { type: 'string' }, from: { type: 'string' }, to: { type: 'string' } },
});
const ch = clickHouseFromEnv();
if (!ch) throw new Error('CLICKHOUSE_URL required');
if (!values.from || !values.to)
  throw new Error('Provide explicit --from and --to UTC minute boundaries');
const service = new AnalyticsService(ch, process.env.WAF_REGION ?? 'local-1');
console.log(
  JSON.stringify(
    await service.usage(uuid.parse(values['project-id']), rangeQuery.parse(values)),
    null,
    2,
  ),
);
