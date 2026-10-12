'use client';
import { useCallback, useEffect, useState, type FormEvent } from 'react';

type Policy = {
  id: string;
  name: string;
  engine_mode: string;
  paranoia_level: number;
  request_body_limit_kb: number;
  inspect_response_body: boolean;
};
type Origin = { id: string; address: string; port: number; scheme: string; weight: number };
type Site = {
  id: string;
  hostname: string;
  status: string;
  policy_id: string;
  certificate_id: string | null;
  http_redirect: boolean;
  config_revision: number;
  applied_revision: number;
  last_error: string | null;
  verification: { name: string; value: string };
  dns_target: { value: string };
  origins?: Origin[];
  policy?: Policy;
};
type Rule = {
  id: string;
  type: string;
  priority: number;
  enabled: boolean;
  spec: Record<string, unknown>;
};
type Cert = {
  id: string;
  domains: string[];
  source: string;
  not_after: string | null;
  acme_status: string | null;
  last_error: string | null;
};
class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}
async function api(path: string, method = 'GET', body?: unknown) {
  const response = await fetch('/api/waf/' + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = response.status === 204 ? null : await response.json();
  if (!response.ok) throw new ApiError(data?.error?.message ?? 'Request failed', response.status);
  return data;
}
const words = (value: string) => value.replaceAll('_', ' ');
function Status({ value }: { value: string }) {
  return (
    <span
      className={`badge ${value === 'active' || value === 'valid' ? 'good' : value === 'error' ? 'bad' : ''}`}
    >
      <span />
      {words(value)}
    </span>
  );
}
function Shield() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z" stroke="currentColor" strokeWidth="1.7" />
      <path d="m8 12 3 3 5-6" stroke="currentColor" strokeWidth="1.7" />
    </svg>
  );
}
function Empty({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="empty">
      <Shield />
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}

export default function WafConsole() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null),
    [sites, setSites] = useState<Site[]>([]),
    [selected, setSelected] = useState<Site | null>(null);
  const [view, setView] = useState<'sites' | 'create' | 'detail'>('sites'),
    [tab, setTab] = useState('Overview'),
    [created, setCreated] = useState<Site | null>(null);
  const [error, setError] = useState(''),
    [notice, setNotice] = useState(''),
    [busy, setBusy] = useState(false),
    [search, setSearch] = useState('');
  const loadSites = useCallback(async () => {
    const data = await api('sites');
    setSites(data.sites);
  }, []);
  const loadDetail = useCallback(async (id: string) => {
    const data = await api('sites/' + id);
    setSelected(data);
    return data as Site;
  }, []);
  const fail = useCallback((e: unknown) => {
    if (e instanceof ApiError && e.status === 401) setAuthenticated(false);
    setError(e instanceof Error ? e.message : 'Something went wrong');
  }, []);
  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await action();
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    loadSites()
      .then(() => setAuthenticated(true))
      .catch((e) => {
        if (e instanceof ApiError && e.status === 401) setAuthenticated(false);
        else {
          setAuthenticated(false);
          fail(e);
        }
      });
  }, [loadSites, fail]);
  useEffect(() => {
    if (!authenticated) return;
    const timer = setInterval(() => {
      loadSites().catch(fail);
      if (selected) loadDetail(selected.id).catch(fail);
      if (created)
        api('sites/' + created.id)
          .then(setCreated)
          .catch(fail);
    }, 3000);
    return () => clearInterval(timer);
  }, [authenticated, selected?.id, created?.id, loadSites, loadDetail, fail]);
  const openSite = (site: Site) =>
    run(async () => {
      await loadDetail(site.id);
      setTab('Overview');
      setView('detail');
    });
  async function signIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const token = String(new FormData(form).get('token'));
    await run(async () => {
      const response = await fetch('/api/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error.message);
      form.reset();
      setSelected(null);
      setCreated(null);
      setView('sites');
      await loadSites();
      setAuthenticated(true);
    });
  }
  async function createSite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await run(async () => {
      const site = await api('sites', 'POST', {
        hostname: form.get('hostname'),
        origins: [
          {
            address: form.get('address'),
            port: Number(form.get('port')),
            scheme: form.get('scheme'),
          },
        ],
        policy: { engine_mode: form.get('mode') },
        ...(form.get('tls') ? { tls: { source: 'acme' } } : {}),
      });
      setCreated(site);
      await loadSites();
    });
  }
  if (authenticated === null)
    return (
      <main className="signin">
        <Shield />
        <p>Loading your workspace…</p>
      </main>
    );
  if (!authenticated)
    return (
      <main className="signin">
        <div className="login-card">
          <div className="brand">
            <Shield />
            CloudInside
          </div>
          <span className="eyebrow">WEB APPLICATION FIREWALL</span>
          <h1>
            A safer home
            <br />
            for your applications.
          </h1>
          <p>Sign in with a project-scoped Keystone token to manage your protected sites.</p>
          <form onSubmit={signIn}>
            <label>
              Project token
              <input name="token" type="password" autoComplete="off" required maxLength={2048} />
            </label>
            <button disabled={busy}>{busy ? 'Signing in…' : 'Open console →'}</button>
          </form>
          {error && (
            <p role="alert" className="error">
              {error}
            </p>
          )}
          <small>
            Your session expires after one hour. Tokens are never stored in browser local storage.
          </small>
        </div>
      </main>
    );
  const filtered = sites.filter((s) => s.hostname.includes(search.toLowerCase()));
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <Shield />
          CloudInside
        </div>
        <span className="nav-label">CLOUD SERVICES</span>
        <button
          className="nav-active"
          onClick={() => {
            setView('sites');
            setCreated(null);
            setSelected(null);
          }}
        >
          <Shield /> Web application firewall
        </button>
        <div className="sidebar-foot">
          <span className="status-dot" /> Project workspace<p>Security that stays with you.</p>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <span>
            Services <span className="slash">/</span> WAF
          </span>
          <button
            className="text-button"
            onClick={() =>
              run(async () => {
                const res = await fetch('/api/session', { method: 'DELETE' });
                if (!res.ok) throw new Error('Sign-out failed');
                setAuthenticated(false);
                setSites([]);
                setSelected(null);
                setCreated(null);
                setView('sites');
              })
            }
          >
            Sign out
          </button>
        </header>
        <main className="content">
          {error && (
            <div role="alert" className="banner error">
              {error}
              <button className="text-button" onClick={() => setError('')}>
                Dismiss
              </button>
            </div>
          )}
          {notice && (
            <div role="status" className="banner success">
              {notice}
            </div>
          )}
          {view === 'sites' && (
            <>
              <div className="heading">
                <div>
                  <span className="eyebrow">APPLICATION SECURITY</span>
                  <h1>Web application firewall</h1>
                  <p>Protect your sites. Keep good traffic moving.</p>
                </div>
                <button
                  onClick={() => {
                    setCreated(null);
                    setView('create');
                  }}
                >
                  ＋ Protect a site
                </button>
              </div>
              <div className="stats">
                <div>
                  <span>Protected sites</span>
                  <strong>
                    {sites.filter((s) => s.status === 'active').length}
                    <small> / {sites.length} total</small>
                  </strong>
                </div>
                <div>
                  <span>Setting up</span>
                  <strong>
                    {sites.filter((s) => ['pending', 'provisioning'].includes(s.status)).length}
                  </strong>
                </div>
                <div>
                  <span>Needs attention</span>
                  <strong>{sites.filter((s) => s.status === 'error').length}</strong>
                </div>
              </div>
              <section className="panel">
                <div className="panel-heading">
                  <h2>
                    Your sites <span className="count">{sites.length}</span>
                  </h2>
                  <input
                    aria-label="Search sites"
                    placeholder="Search by domain…"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </div>
                {!sites.length ? (
                  <Empty title="Your first layer of protection starts here">
                    Add a domain, connect your origin, and verify ownership to get started.
                  </Empty>
                ) : (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Domain</th>
                          <th>Status</th>
                          <th>TLS</th>
                          <th>Configuration</th>
                          <th />
                        </tr>
                      </thead>
                      <tbody>
                        {filtered.map((site) => (
                          <tr key={site.id}>
                            <td>
                              <button className="domain-link" onClick={() => openSite(site)}>
                                {site.hostname}
                              </button>
                            </td>
                            <td>
                              <Status value={site.status} />
                            </td>
                            <td>{site.certificate_id ? 'Configured' : 'Not configured'}</td>
                            <td className="muted">
                              {site.applied_revision} / {site.config_revision} applied
                            </td>
                            <td>
                              <button
                                className="text-button"
                                aria-label={`Manage ${site.hostname}`}
                                onClick={() => openSite(site)}
                              >
                                Manage →
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {!filtered.length && <p className="pad muted">No domains match your search.</p>}
                  </div>
                )}
              </section>
              <div className="note">
                <Shield />
                <div>
                  <strong>Start with visibility, then enforce.</strong>
                  <p>
                    Detect mode records matches. Switch to Block when you’re ready to reject
                    malicious requests.
                  </p>
                </div>
              </div>
            </>
          )}
          {view === 'create' && (
            <>
              <button className="text-button" onClick={() => setView('sites')}>
                ← All sites
              </button>
              <div className="heading">
                <div>
                  <span className="eyebrow">NEW PROTECTED SITE</span>
                  <h1>Bring your site behind WAF</h1>
                  <p>A few details now. Continuous protection after.</p>
                </div>
              </div>
              <div className="steps">
                <span className={!created ? 'current' : ''}>
                  1 <b>Site & origin</b>
                </span>
                <span className={created && created.status !== 'active' ? 'current' : ''}>
                  2 <b>Verify & connect</b>
                </span>
                <span className={created?.status === 'active' ? 'current' : ''}>
                  3 <b>Protected</b>
                </span>
              </div>
              {!created ? (
                <form className="panel form-panel" onSubmit={createSite}>
                  <h2>Where should we send your traffic?</h2>
                  <label>
                    Domain
                    <input name="hostname" placeholder="shop.example.com" required />
                    <small>Enter the domain customers use to visit your site.</small>
                  </label>
                  <div className="form-grid">
                    <label>
                      Origin address
                      <input name="address" placeholder="203.0.113.10" required />
                      <small>The IP address or hostname of your web server.</small>
                    </label>
                    <label>
                      Origin port
                      <input
                        name="port"
                        type="number"
                        min="1"
                        max="65535"
                        defaultValue="80"
                        required
                      />
                    </label>
                    <label>
                      Origin connection
                      <select name="scheme" defaultValue="http">
                        <option value="http">HTTP</option>
                        <option value="https">HTTPS</option>
                      </select>
                    </label>
                    <label>
                      Protection mode
                      <select name="mode" defaultValue="detect">
                        <option value="detect">Detect — observe matches</option>
                        <option value="block">Block — reject attacks</option>
                      </select>
                    </label>
                  </div>
                  <label className="check">
                    <input type="checkbox" name="tls" defaultChecked />
                    Automatically issue and renew a TLS certificate
                  </label>
                  <p className="muted">
                    Automatic TLS requires ACME to be enabled by your cloud operator. HTTP port 80
                    must reach the WAF edge.
                  </p>
                  <div className="form-actions">
                    <button disabled={busy}>{busy ? 'Creating…' : 'Continue to DNS →'}</button>
                  </div>
                </form>
              ) : created.status === 'active' ? (
                <section className="panel done">
                  <div className="done-icon">
                    <Shield />
                  </div>
                  <span className="eyebrow">YOU’RE CONNECTED</span>
                  <h2>{created.hostname} is active</h2>
                  <p>Your configuration has reached every assigned edge node.</p>
                  <button onClick={() => openSite(created)}>Manage your site →</button>
                </section>
              ) : (
                <section className="panel form-panel">
                  <h2>Verify ownership and route traffic</h2>
                  <p>
                    Add these records with your DNS provider. DNS changes can take a few minutes to
                    appear.
                  </p>
                  <DNSRecords site={created} />
                  <div className="form-actions">
                    <button
                      disabled={busy || created.status === 'provisioning'}
                      onClick={() =>
                        run(async () => {
                          setCreated(await api(`sites/${created.id}/verify`, 'POST', {}));
                          setNotice(
                            'Ownership verified. Waiting for edge configuration and certificate issuance.',
                          );
                        })
                      }
                    >
                      {busy
                        ? 'Checking DNS…'
                        : created.status === 'provisioning'
                          ? 'Waiting for edge nodes…'
                          : 'Verify DNS records'}
                    </button>
                    <Status value={created.status} />
                  </div>
                  {created.last_error && (
                    <p role="alert" className="error">
                      {created.last_error}
                    </p>
                  )}
                  <p className="muted">
                    Only route production traffic after your origin and certificate settings are
                    ready. You can leave this page and return from the site list.
                  </p>
                </section>
              )}
            </>
          )}
          {view === 'detail' && selected && (
            <>
              <button
                className="text-button"
                onClick={() => {
                  setView('sites');
                  setSelected(null);
                }}
              >
                ← All sites
              </button>
              <div className="heading">
                <div>
                  <span className="eyebrow">PROTECTED SITE</span>
                  <h1>{selected.hostname}</h1>
                  <p>Manage how traffic reaches your application.</p>
                </div>
                <Status value={selected.status} />
              </div>
              <nav className="tabs" aria-label="Site settings">
                {['Overview', 'Policy', 'Rules', 'Certificates', 'Attack log', 'Metrics'].map(
                  (name) => (
                    <button
                      key={name}
                      className={tab === name ? 'selected' : ''}
                      onClick={() => setTab(name)}
                    >
                      {name}
                    </button>
                  ),
                )}
              </nav>
              {selected.last_error && (
                <p role="alert" className="banner error">
                  {selected.last_error}
                </p>
              )}
              {tab === 'Overview' && (
                <>
                  <section className="panel form-panel">
                    <h2>Connection details</h2>
                    <dl>
                      <dt>Configuration applied</dt>
                      <dd>
                        {selected.applied_revision} of {selected.config_revision}
                      </dd>
                      <dt>Protection mode</dt>
                      <dd>{words(selected.policy?.engine_mode ?? 'unknown')}</dd>
                      <dt>HTTPS redirect</dt>
                      <dd>{selected.http_redirect ? 'Enabled' : 'Disabled'}</dd>
                    </dl>
                    <DNSRecords site={selected} />
                    {selected.status === 'pending' && (
                      <button
                        disabled={busy}
                        onClick={() =>
                          run(async () => {
                            await api(`sites/${selected.id}/verify`, 'POST', {});
                            await loadDetail(selected.id);
                          })
                        }
                      >
                        Verify DNS records
                      </button>
                    )}
                  </section>
                  <OriginEditor
                    site={selected}
                    busy={busy}
                    run={run}
                    refresh={() => loadDetail(selected.id).then(() => {})}
                  />
                  <section className="panel danger-zone">
                    <div>
                      <h2>Delete this site</h2>
                      <p>Removes its routes from the WAF edge. Update your DNS before deleting.</p>
                    </div>
                    <button
                      className="danger-button"
                      onClick={() => {
                        if (
                          window.confirm(
                            `Delete ${selected.hostname}? Its WAF routes will be removed.`,
                          )
                        )
                          void run(async () => {
                            await api('sites/' + selected.id, 'DELETE');
                            setSelected(null);
                            setView('sites');
                            await loadSites();
                          });
                      }}
                    >
                      Delete site
                    </button>
                  </section>
                </>
              )}
              {tab === 'Policy' && selected.policy && (
                <PolicyEditor
                  key={selected.policy.id}
                  policy={selected.policy}
                  busy={busy}
                  run={run}
                  saved={async () => {
                    await loadDetail(selected.id);
                    setNotice('Policy saved. The edge will apply the new revision.');
                  }}
                />
              )}
              {tab === 'Rules' && (
                <RuleEditor policyId={selected.policy_id} busy={busy} run={run} />
              )}
              {tab === 'Certificates' && (
                <CertificateEditor
                  site={selected}
                  busy={busy}
                  run={run}
                  refresh={() => loadDetail(selected.id).then(() => {})}
                />
              )}
              {(tab === 'Attack log' || tab === 'Metrics') && (
                <Analytics key={tab + selected.id} siteId={selected.id} kind={tab} onError={fail} />
              )}
            </>
          )}
          <footer>
            CloudInside WAF <span>Protect what you build.</span>
          </footer>
        </main>
      </div>
    </div>
  );
}
function DNSRecords({ site }: { site: Site }) {
  return (
    <div className="dns-records">
      <div>
        <span>TXT · Ownership verification</span>
        <code>{site.verification.name}</code>
        <code className="record-value">{site.verification.value}</code>
      </div>
      <div>
        <span>CNAME · Traffic routing</span>
        <code>{site.hostname}</code>
        <code className="record-value">{site.dns_target.value}</code>
      </div>
      <small>
        For apex domains, use your provider’s ALIAS/ANAME support or the edge IP supplied by your
        operator.
      </small>
    </div>
  );
}
type Actions = { busy: boolean; run: (action: () => Promise<void>) => Promise<void> };
function PolicyEditor({
  policy,
  busy,
  run,
  saved,
}: Actions & { policy: Policy; saved: () => Promise<void> }) {
  return (
    <form
      className="panel form-panel"
      onSubmit={(e) => {
        e.preventDefault();
        const f = new FormData(e.currentTarget);
        void run(async () => {
          await api('policies/' + policy.id, 'PATCH', {
            name: f.get('name'),
            engine_mode: f.get('mode'),
            paranoia_level: Number(f.get('pl')),
            request_body_limit_kb: Number(f.get('limit')),
            inspect_response_body: f.has('response'),
          });
          await saved();
        });
      }}
    >
      <h2>Protection policy</h2>
      <p>Changes apply to every site using this policy.</p>
      <label>
        Policy name
        <input name="name" defaultValue={policy.name} required />
      </label>
      <div className="form-grid">
        <label>
          Engine mode
          <select name="mode" defaultValue={policy.engine_mode}>
            <option value="detect">Detect</option>
            <option value="block">Block</option>
            <option value="off">Off</option>
          </select>
        </label>
        <label>
          Paranoia level
          <select name="pl" defaultValue={policy.paranoia_level}>
            {[1, 2, 3, 4].map((n) => (
              <option key={n} value={n}>
                {n}
                {n === 1 ? ' — Recommended starting point' : ''}
              </option>
            ))}
          </select>
        </label>
        <label>
          Maximum request body (KB)
          <input
            name="limit"
            type="number"
            min="1"
            max="131072"
            defaultValue={policy.request_body_limit_kb}
            required
          />
        </label>
      </div>
      <label className="check">
        <input name="response" type="checkbox" defaultChecked={policy.inspect_response_body} />
        Inspect response bodies
      </label>
      <p className="muted">
        Higher paranoia levels detect more patterns and can increase false positives. Review your
        application before enabling stricter blocking.
      </p>
      <div className="form-actions">
        <button disabled={busy}>Save policy</button>
      </div>
    </form>
  );
}
function OriginEditor({
  site,
  busy,
  run,
  refresh,
}: Actions & { site: Site; refresh: () => Promise<void> }) {
  return (
    <section className="panel form-panel">
      <h2>Origins</h2>
      {site.origins?.map((o) => (
        <div className="row-item" key={o.id}>
          <code>
            {o.scheme}://{o.address}:{o.port}
          </code>
          <span>Weight {o.weight}</span>
          <button
            className="text-button"
            disabled={busy || (site.origins?.length ?? 0) <= 1}
            onClick={() =>
              run(async () => {
                await api(`sites/${site.id}/origins/${o.id}`, 'DELETE');
                await refresh();
              })
            }
          >
            Remove
          </button>
        </div>
      ))}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const el = e.currentTarget,
            f = new FormData(el);
          void run(async () => {
            await api(`sites/${site.id}/origins`, 'POST', {
              address: f.get('address'),
              port: Number(f.get('port')),
              scheme: f.get('scheme'),
              weight: Number(f.get('weight')),
            });
            el.reset();
            await refresh();
          });
        }}
      >
        <div className="form-grid">
          <label>
            Origin address
            <input name="address" required />
          </label>
          <label>
            Port
            <input name="port" type="number" min="1" max="65535" defaultValue="80" required />
          </label>
          <label>
            Connection
            <select name="scheme">
              <option>http</option>
              <option>https</option>
            </select>
          </label>
          <label>
            Weight
            <input name="weight" type="number" min="1" max="100" defaultValue="1" required />
          </label>
        </div>
        <button disabled={busy} className="secondary">
          Add origin
        </button>
      </form>
    </section>
  );
}
function RuleEditor({ policyId, busy, run }: Actions & { policyId: string }) {
  const [rules, setRules] = useState<Rule[]>([]),
    [type, setType] = useState('ip_deny'),
    [loadError, setLoadError] = useState('');
  const refresh = useCallback(
    async () => setRules((await api(`policies/${policyId}/rules`)).rules),
    [policyId],
  );
  useEffect(() => {
    refresh().catch((e) => setLoadError(e.message));
  }, [refresh]);
  return (
    <>
      <section className="panel">
        <div className="panel-heading">
          <h2>Custom rules</h2>
          <span className="muted">{rules.length} configured</span>
        </div>
        {loadError && (
          <p role="alert" className="error pad">
            {loadError}
          </p>
        )}
        {!rules.length ? (
          <Empty title="Protection starts with the core rules">
            Add targeted rules for your application. OWASP CRS is already included in your policy.
          </Empty>
        ) : (
          rules.map((rule) => (
            <div className="row-item pad" key={rule.id}>
              <div>
                <strong>{words(rule.type)}</strong>
                <code className="rule-spec">{JSON.stringify(rule.spec)}</code>
              </div>
              <button
                className="text-button"
                disabled={busy}
                onClick={() =>
                  run(async () => {
                    await api(`policies/${policyId}/rules/${rule.id}`, 'PATCH', {
                      enabled: !rule.enabled,
                    });
                    await refresh();
                  })
                }
              >
                {rule.enabled ? 'Disable' : 'Enable'}
              </button>
              <button
                className="text-button"
                disabled={busy}
                onClick={() =>
                  run(async () => {
                    await api(`policies/${policyId}/rules/${rule.id}`, 'DELETE');
                    await refresh();
                  })
                }
              >
                Delete
              </button>
            </div>
          ))
        )}
      </section>
      <form
        className="panel form-panel"
        onSubmit={(e) => {
          e.preventDefault();
          const el = e.currentTarget,
            f = new FormData(el);
          let spec: Record<string, unknown>;
          if (type === 'ip_allow' || type === 'ip_deny')
            spec = {
              cidrs: String(f.get('cidrs'))
                .split(/[\s,]+/)
                .filter(Boolean),
            };
          else if (type === 'path_exclusion') spec = { path_prefix: f.get('path') };
          else
            spec = {
              rule_ids: String(f.get('ids'))
                .split(/[\s,]+/)
                .filter(Boolean)
                .map(Number),
              ...(f.get('path') ? { path_prefix: f.get('path') } : {}),
            };
          void run(async () => {
            await api(`policies/${policyId}/rules`, 'POST', {
              type,
              spec,
              priority: Number(f.get('priority')),
            });
            el.reset();
            await refresh();
          });
        }}
      >
        <h2>Add a rule</h2>
        <label>
          Rule type
          <select value={type} onChange={(e) => setType(e.target.value)}>
            <option value="ip_deny">Deny IP addresses</option>
            <option value="ip_allow">Allow IP addresses</option>
            <option value="path_exclusion">Exclude a path from inspection</option>
            <option value="rule_exclusion">Exclude specific CRS rules</option>
          </select>
        </label>
        {type.startsWith('ip_') ? (
          <label>
            IP addresses or CIDRs
            <textarea name="cidrs" placeholder="198.51.100.0/24" required />
          </label>
        ) : (
          <>
            <label>
              Path prefix
              <input name="path" placeholder="/api/webhook" required={type === 'path_exclusion'} />
            </label>
            {type === 'rule_exclusion' && (
              <label>
                CRS rule IDs
                <input name="ids" placeholder="942100, 941100" required />
              </label>
            )}
          </>
        )}
        <label>
          Priority
          <input name="priority" type="number" min="0" max="99999" defaultValue="100" required />
        </label>
        {type === 'ip_allow' || type === 'path_exclusion' ? (
          <p className="warning">
            Matching traffic bypasses WAF inspection. Keep this exception as narrow as possible.
          </p>
        ) : null}
        <button disabled={busy}>Add rule</button>
        <p className="muted">
          Geo and rate-limit rules will be available when edge enforcement is implemented.
        </p>
      </form>
    </>
  );
}
function CertificateEditor({
  site,
  busy,
  run,
  refresh,
}: Actions & { site: Site; refresh: () => Promise<void> }) {
  const [certs, setCerts] = useState<Cert[]>([]),
    [loadError, setLoadError] = useState('');
  const load = useCallback(async () => setCerts((await api('certificates')).certificates), []);
  useEffect(() => {
    load().catch((e) => setLoadError(e.message));
  }, [load]);
  const current = certs.find((c) => c.id === site.certificate_id);
  return (
    <>
      <section className="panel form-panel">
        <h2>HTTPS certificate</h2>
        {loadError && (
          <p role="alert" className="error">
            {loadError}
          </p>
        )}
        {current ? (
          <>
            <p>
              {current.domains.join(', ')} · {current.source}
            </p>
            <Status value={current.acme_status ?? 'valid'} />
            <p className="muted">
              Expires:{' '}
              {current.not_after
                ? new Date(current.not_after).toLocaleString()
                : 'Waiting for issuance'}
            </p>
            {current.last_error && <p className="error">{current.last_error}</p>}
          </>
        ) : (
          <p>No certificate is attached to this site.</p>
        )}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            void run(async () => {
              await api('sites/' + site.id, 'PATCH', {
                certificate_id: f.get('certificate') || null,
                http_redirect: f.has('redirect'),
              });
              await refresh();
            });
          }}
        >
          <label>
            Attach a certificate
            <select name="certificate" defaultValue={site.certificate_id ?? ''}>
              <option value="">No certificate</option>
              {certs.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.domains.join(', ')} ({c.source})
                </option>
              ))}
            </select>
          </label>
          <label className="check">
            <input name="redirect" type="checkbox" defaultChecked={site.http_redirect} />
            Redirect HTTP traffic to HTTPS
          </label>
          <button disabled={busy}>Save HTTPS settings</button>
        </form>
      </section>
      <form
        className="panel form-panel"
        onSubmit={(e) => {
          e.preventDefault();
          const el = e.currentTarget,
            f = new FormData(el);
          void run(async () => {
            const c = await api('certificates', 'POST', {
              source: 'upload',
              domains: [site.hostname],
              cert_pem: f.get('cert'),
              key_pem: f.get('key'),
            });
            await api('sites/' + site.id, 'PATCH', { certificate_id: c.id });
            el.reset();
            await load();
            await refresh();
          });
        }}
      >
        <h2>Upload and attach a certificate</h2>
        <p>Use a current certificate covering {site.hostname}, with its matching private key.</p>
        <label>
          Certificate chain (PEM)
          <textarea name="cert" required rows={5} spellCheck={false} />
        </label>
        <label>
          Private key (PEM)
          <textarea name="key" required rows={5} spellCheck={false} autoComplete="off" />
        </label>
        <button disabled={busy}>Upload certificate</button>
      </form>
    </>
  );
}
type AttackEvent = {
  event_id: string;
  timestamp: string;
  action: string;
  method: string;
  path: string;
  client_ip: string;
  rule_ids: number[];
  status: number;
};
type Traffic = {
  from: string;
  to: string;
  totals: {
    requests: number;
    blocked: number;
    detected: number;
    errors: number;
    bytes_out: number;
    average_duration_ms: number;
  };
  series: Array<{ minute: string; action: string; requests: number }>;
};
function Analytics({
  siteId,
  kind,
  onError,
}: {
  siteId: string;
  kind: string;
  onError: (error: unknown) => void;
}) {
  const [hours, setHours] = useState('24'),
    [action, setAction] = useState(''),
    [ip, setIP] = useState(''),
    [rule, setRule] = useState('');
  const [events, setEvents] = useState<AttackEvent[]>([]),
    [cursor, setCursor] = useState<string | null>(null),
    [traffic, setTraffic] = useState<Traffic | null>(null);
  const [loading, setLoading] = useState(true),
    [unavailable, setUnavailable] = useState(false),
    [failed, setFailed] = useState(false),
    [excluding, setExcluding] = useState(''),
    [message, setMessage] = useState('');
  const [range, setRange] = useState({ from: '', to: '' });
  const load = useCallback(
    async (more = false) => {
      setLoading(true);
      setFailed(false);
      setMessage('');
      const current = more
        ? range
        : {
            from: new Date(Date.now() - Number(hours) * 3600000).toISOString(),
            to: new Date().toISOString(),
          };
      if (!more) setRange(current);
      const query = new URLSearchParams(current);
      if (action) query.set('action', action);
      if (ip) query.set('ip', ip);
      if (rule) query.set('rule_id', rule);
      if (more && cursor) query.set('cursor', cursor);
      try {
        const value = await api(
          `sites/${siteId}/${kind === 'Metrics' ? 'metrics' : 'events'}?${query}`,
        );
        setUnavailable(false);
        if (kind === 'Metrics') setTraffic(value);
        else {
          setEvents((previous) => (more ? [...previous, ...value.events] : value.events));
          setCursor(value.next_cursor);
        }
      } catch (e) {
        setFailed(true);
        if (e instanceof ApiError && e.status === 501) setUnavailable(true);
        else onError(e);
      } finally {
        setLoading(false);
      }
    },
    [siteId, kind, hours, action, ip, rule, range, cursor, onError],
  );
  useEffect(() => {
    void load();
  }, [siteId, kind, hours, action]);
  async function exclude(event: AttackEvent) {
    const ids = event.rule_ids.filter(
      (id) => (id >= 900000 && id < 949000) || (id >= 950000 && id < 959000),
    );
    if (
      !window.confirm(
        `Exclude rules ${ids.join(', ')} for path prefix ${event.path}? This changes every site using this policy.`,
      )
    )
      return;
    setExcluding(event.event_id);
    setMessage('');
    try {
      await api(`sites/${siteId}/events/${event.event_id}/exclude`, 'POST', {
        rule_ids: ids,
        path_prefix: event.path,
      });
      setMessage('Exclusion saved. Review it in Rules; the edge will apply the new revision.');
    } catch (e) {
      onError(e);
    } finally {
      setExcluding('');
    }
  }
  const format = (n: number) => new Intl.NumberFormat().format(n);
  return (
    <>
      <section className="panel">
        <div className="panel-heading">
          <h2>{kind === 'Metrics' ? 'Traffic overview' : 'Attack log'}</h2>
          <div className="analytics-controls">
            <select
              aria-label="Time range"
              value={hours}
              onChange={(e) => setHours(e.target.value)}
            >
              <option value="1">Last hour</option>
              <option value="24">Last 24 hours</option>
              <option value="168">Last 7 days</option>
            </select>
            <button className="secondary" disabled={loading} onClick={() => load()}>
              Refresh
            </button>
          </div>
        </div>
        {kind === 'Attack log' && (
          <form
            className="analytics-filters"
            onSubmit={(e) => {
              e.preventDefault();
              void load();
            }}
          >
            <label>
              Action
              <select value={action} onChange={(e) => setAction(e.target.value)}>
                <option value="">All actions</option>
                <option value="blocked">Blocked</option>
                <option value="detected">Detected</option>
              </select>
            </label>
            <label>
              Client IP
              <input
                value={ip}
                onChange={(e) => setIP(e.target.value)}
                placeholder="Any IP address"
              />
            </label>
            <label>
              Rule ID
              <input
                value={rule}
                onChange={(e) => setRule(e.target.value)}
                placeholder="Any rule"
                inputMode="numeric"
              />
            </label>
            <button className="secondary" disabled={loading}>
              Apply filters
            </button>
          </form>
        )}
        {message && (
          <p role="status" className="banner success">
            {message}
          </p>
        )}
        {loading ? (
          <Empty title="Loading analytics…">Reading traffic from your WAF edge.</Empty>
        ) : unavailable ? (
          <Empty title="Analytics is not available yet">
            Your cloud operator has not configured traffic collection. Your WAF rules remain active.
          </Empty>
        ) : failed ? (
          <Empty title="Unable to load analytics">
            The analytics service could not be reached. Retry to refresh the data.
          </Empty>
        ) : kind === 'Metrics' && traffic ? (
          <>
            <div className="traffic-totals">
              <div>
                <span>Requests</span>
                <strong>{format(traffic.totals.requests)}</strong>
              </div>
              <div>
                <span>Blocked</span>
                <strong>
                  {format(traffic.totals.blocked)}
                  <small>
                    {' '}
                    {traffic.totals.requests
                      ? ((traffic.totals.blocked / traffic.totals.requests) * 100).toFixed(2)
                      : '0'}
                    %
                  </small>
                </strong>
              </div>
              <div>
                <span>Detected</span>
                <strong>{format(traffic.totals.detected)}</strong>
              </div>
              <div>
                <span>Average request time</span>
                <strong>
                  {traffic.totals.average_duration_ms.toFixed(1)}
                  <small> ms</small>
                </strong>
              </div>
            </div>
            <TrafficChart traffic={traffic} />
            <p className="pad muted">
              Counts include completed inspected requests, with one-minute resolution. HTTP
              redirects and certificate challenges are excluded. Collection is asynchronous; recent
              requests may take a few seconds to appear.
            </p>
          </>
        ) : kind === 'Attack log' && !events.length ? (
          <Empty title="No recorded attacks in this period">
            No matching security events were recorded for the selected filters.
          </Empty>
        ) : kind === 'Attack log' ? (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Action</th>
                    <th>Request</th>
                    <th>Client IP</th>
                    <th>Rules</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {events.map((event) => (
                    <tr key={event.event_id}>
                      <td>{new Date(event.timestamp).toLocaleString()}</td>
                      <td>
                        <Status value={event.action} />
                      </td>
                      <td>
                        <code>
                          {event.method} {event.path}
                        </code>
                      </td>
                      <td>{event.client_ip}</td>
                      <td>
                        <code>{event.rule_ids.join(', ')}</code>
                      </td>
                      <td>
                        <button
                          className="text-button"
                          disabled={
                            !!excluding ||
                            !event.path ||
                            event.path.length >= 2048 ||
                            !event.rule_ids.some(
                              (id) =>
                                (id >= 900000 && id < 949000) || (id >= 950000 && id < 959000),
                            )
                          }
                          onClick={() => exclude(event)}
                        >
                          {excluding === event.event_id ? 'Saving…' : 'Exclude for this path'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {cursor && (
              <div className="pad">
                <button className="secondary" disabled={loading} onClick={() => load(true)}>
                  Load more events
                </button>
              </div>
            )}
          </>
        ) : null}
      </section>
    </>
  );
}
function TrafficChart({ traffic }: { traffic: Traffic }) {
  const from = Date.parse(traffic.from),
    to = Date.parse(traffic.to),
    width = (to - from) / 60;
  const bins = Array.from({ length: 60 }, (_, i) => ({
    time: from + i * width,
    total: 0,
    blocked: 0,
  }));
  for (const row of traffic.series) {
    const index = Math.max(0, Math.min(59, Math.floor((Date.parse(row.minute) - from) / width)));
    bins[index].total += row.requests;
    if (row.action === 'blocked') bins[index].blocked += row.requests;
  }
  const max = Math.max(1, ...bins.map((b) => b.total));
  return (
    <div className="traffic-chart">
      <div className="chart-legend">
        <span>● Requests</span>
        <span>● Blocked</span>
      </div>
      <svg
        viewBox="0 0 820 210"
        role="img"
        aria-label="Request and blocked request counts over the selected period"
      >
        <line x1="40" y1="180" x2="800" y2="180" stroke="#dce6df" />
        <text x="0" y="23" fill="#718577" fontSize="11">
          {max}
        </text>
        <text x="15" y="180" fill="#718577" fontSize="11">
          0
        </text>
        {bins.map((b, i) => (
          <g key={i}>
            <title>
              {new Date(b.time).toLocaleString()}: {b.total} requests, {b.blocked} blocked
            </title>
            <rect
              x={40 + i * 12.6}
              y={180 - (b.total / max) * 155}
              width="10"
              height={(b.total / max) * 155}
              rx="2"
              fill="#399879"
            />
            <rect
              x={40 + i * 12.6}
              y={180 - (b.blocked / max) * 155}
              width="10"
              height={(b.blocked / max) * 155}
              fill="#d79372"
            />
          </g>
        ))}
      </svg>
      <div className="chart-axis">
        <span>{new Date(from).toLocaleString()}</span>
        <span>{new Date(to).toLocaleString()}</span>
      </div>
    </div>
  );
}
