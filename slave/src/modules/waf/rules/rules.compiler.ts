import type { policies, origins, rules, sites } from '../../../db/schema.js';
import { ruleInput } from '../validation.js';

export type SiteBundle = {
  challenges?: Array<{ token: string; authorization: string; expires_at: string }>;
  site_id: string;
  revision: number;
  certificate_id: string | null;
  hostname: string;
  engine_mode: string;
  paranoia_level: number;
  origins: Array<{ url: string; weight: number }>;
  http_redirect: boolean;
  limits: { request_body_kb: number };
  inspect_response_body: boolean;
  rate_limits: unknown[];
  seclang: string;
};

export function compileBundle(
  site: typeof sites.$inferSelect,
  policy: typeof policies.$inferSelect,
  originsList: Array<typeof origins.$inferSelect>,
  ruleList: Array<typeof rules.$inferSelect>,
): SiteBundle {
  if (!site.verifiedAt) throw new Error('Domain ownership is not verified');
  if (!originsList.length) throw new Error('Site requires at least one origin');
  const mode = { detect: 'DetectionOnly', block: 'On', off: 'Off' }[policy.engineMode];
  if (!mode) throw new Error('Invalid engine mode');
  let next = 9000001;
  const used = new Set<number>();
  const list = ruleList
    .filter((r) => r.enabled)
    .sort((a, b) => a.priority - b.priority || a.id.localeCompare(b.id))
    .map((r) =>
      ruleInput.parse({ type: r.type, spec: r.spec, priority: r.priority, enabled: r.enabled }),
    );
  for (const r of list)
    if (r.type === 'raw')
      for (const m of r.spec.seclang.matchAll(/\bid\s*:\s*'?([0-9]+)/gi)) {
        if (used.has(+m[1])) throw new Error('Duplicate custom rule ID');
        used.add(+m[1]);
      }
  const id = () => {
    while (used.has(next)) next++;
    if (next > 9099999) throw new Error('Custom rule ID range exhausted');
    return next++;
  };
  const pre: string[] = [],
    post: string[] = [];
  const rank = {
    ip_allow: 0,
    ip_deny: 1,
    geo_deny: 1,
    path_exclusion: 2,
    rule_exclusion: 3,
    rate_limit: 4,
    raw: 5,
  };
  list.sort((a, b) => rank[a.type] - rank[b.type] || a.priority - b.priority);
  for (const r of list) {
    if (r.type === 'ip_allow' || r.type === 'ip_deny')
      pre.push(
        `SecRule REMOTE_ADDR "@ipMatch ${r.spec.cidrs.join(',')}" "id:${id()},phase:1,${r.type === 'ip_allow' ? 'pass,nolog,ctl:ruleEngine=Off' : "deny,status:403,log,msg:'Custom IP deny'"}"`,
      );
    else if (r.type === 'path_exclusion')
      pre.push(
        `SecRule REQUEST_URI "@beginsWith ${r.spec.path_prefix}" "id:${id()},phase:1,pass,nolog,ctl:ruleEngine=Off"`,
      );
    else if (r.type === 'rule_exclusion') {
      const actions = r.spec.rule_ids
        .flatMap((rule) =>
          r.spec.args
            ? r.spec.args.map((arg) => `ctl:ruleRemoveTargetById=${rule};ARGS:${arg}`)
            : [`ctl:ruleRemoveById=${rule}`],
        )
        .join(',');
      pre.push(
        r.spec.path_prefix
          ? `SecRule REQUEST_URI "@beginsWith ${r.spec.path_prefix}" "id:${id()},phase:1,pass,nolog,${actions}"`
          : `SecAction "id:${id()},phase:1,pass,nolog,${actions}"`,
      );
    } else if (r.type === 'raw') post.push(r.spec.seclang);
    else throw new Error(`${r.type} enforcement requires Phase 7; configuration was not published`);
  }
  const limit = policy.requestBodyLimitKb * 1024;
  const seclang = [
    `Include @coraza.conf-recommended`,
    `SecRuleEngine ${mode}`,
    `SecRequestBodyLimit ${limit}`,
    `SecRequestBodyInMemoryLimit ${Math.min(limit, 131072)}`,
    `SecRequestBodyLimitAction Reject`,
    `SecResponseBodyAccess ${policy.inspectResponseBody ? 'On' : 'Off'}`,
    `SecResponseBodyLimit 1048576`,
    `SecResponseBodyLimitAction ProcessPartial`,
    `SecAuditEngine Off`,
    `SecAction "id:9000000,phase:1,pass,nolog,setvar:tx.crs_xml_attr_inspect=1,setvar:tx.blocking_paranoia_level=${policy.paranoiaLevel},setvar:tx.inbound_anomaly_score_threshold=${policy.inboundAnomalyThreshold},setvar:tx.outbound_anomaly_score_threshold=${policy.outboundAnomalyThreshold}"`,
    `Include @crs-setup-lts.conf.example`,
    ...pre,
    `Include @owasp_crs_lts/*.conf`,
    ...post,
  ].join('\n');
  return {
    site_id: site.id,
    revision: site.configRevision,
    certificate_id: site.certificateId,
    hostname: site.hostname,
    engine_mode: policy.engineMode,
    paranoia_level: policy.paranoiaLevel,
    origins: originsList.map((o) => ({
      url: `${o.scheme}://${o.address.includes(':') ? '[' + o.address + ']' : o.address}:${o.port}`,
      weight: o.weight,
    })),
    http_redirect: site.httpRedirect,
    limits: { request_body_kb: policy.requestBodyLimitKb },
    inspect_response_body: policy.inspectResponseBody,
    rate_limits: [],
    seclang,
  };
}
