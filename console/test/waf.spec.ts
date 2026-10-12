import { test, expect } from '@playwright/test';
import { request as httpRequest } from 'node:http';
import { mkdir, writeFile } from 'node:fs/promises';

async function edge(path: string) {
  return new Promise<number>((resolve, reject) => {
    const r = httpRequest(
      { hostname: '127.0.0.1', port: 19980, path, headers: { Host: 'shop.localhost' } },
      (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode!));
      },
    );
    r.on('error', reject);
    r.end();
  });
}

test('protect a domain, enforce its policy, manage rules, and isolate sessions', async ({
  page,
  request,
  browser,
}) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto('/console/services/waf');
  await page.getByLabel('Project token').fill('invalid');
  await page.getByRole('button', { name: 'Open console' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'invalid or expired' })).toBeVisible();
  await page.getByLabel('Project token').fill('console-e2e-project-token');
  await page.getByRole('button', { name: 'Open console' }).click();
  await expect(page.getByRole('heading', { name: 'Web application firewall' })).toBeVisible();
  const started = Date.now();
  await page.getByRole('button', { name: 'Protect a site' }).click();
  await page.getByLabel(/^Domain/).fill('shop.localhost');
  await page.getByLabel('Origin address').fill('127.0.0.1');
  await page.getByLabel('Origin port').fill('19903');
  await page.getByLabel('Protection mode').selectOption('block');
  await page.getByLabel('Automatically issue').uncheck();
  await page.getByRole('button', { name: 'Continue to DNS' }).click();
  await expect(
    page.getByRole('heading', { name: 'Verify ownership and route traffic' }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Verify DNS records' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'does not match' })).toBeVisible();
  const name = await page.locator('.dns-records>div').first().locator('code').first().innerText();
  const value = await page.locator('.dns-records>div').first().locator('.record-value').innerText();
  await request.post('http://127.0.0.1:19902/test/dns', { data: { name, value } });
  await page.getByRole('button', { name: 'Verify DNS records' }).click();
  await expect(page.getByRole('heading', { name: 'shop.localhost is active' })).toBeVisible({
    timeout: 15000,
  });
  const elapsed = Date.now() - started;
  expect(elapsed).toBeLessThan(300000);
  expect(await edge('/')).toBe(200);
  expect(await edge('/?q=' + encodeURIComponent('<script>alert(1)</script>'))).toBe(403);
  await page.getByRole('button', { name: 'Manage your site' }).click();
  await page.getByRole('button', { name: 'Policy', exact: true }).click();
  await page.getByLabel('Engine mode').selectOption('detect');
  await page.getByRole('button', { name: 'Save policy' }).click();
  await expect(page.getByRole('status')).toContainText('Policy saved');
  await expect.poll(() => edge('/?q=' + encodeURIComponent('<script>alert(1)</script>'))).toBe(200);
  await page.getByRole('button', { name: 'Rules', exact: true }).click();
  await page.getByLabel('IP addresses or CIDRs').fill('198.51.100.0/24');
  await page.getByRole('button', { name: 'Add rule', exact: true }).click();
  await expect(page.locator('.rule-spec')).toContainText('198.51.100.0/24');
  await page.getByRole('button', { name: 'Disable', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Enable', exact: true })).toBeVisible();
  const sites = await page.request.get('/api/waf/sites');
  const id = (await sites.json()).sites[0].id;
  await expect
    .poll(
      async () => {
        const response = await page.request.get(`/api/waf/sites/${id}/events`);
        return (await response.json()).events?.length ?? 0;
      },
      { timeout: 15000 },
    )
    .toBeGreaterThan(0);
  await page.getByRole('button', { name: 'Attack log', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Exclude for this path' }).first()).toBeVisible();
  page.once('dialog', (dialog) => dialog.accept());
  await page.getByRole('button', { name: 'Exclude for this path' }).first().click();
  await expect(page.getByRole('status')).toContainText('Exclusion saved');
  await page.getByRole('button', { name: 'Metrics', exact: true }).click();
  await expect(page.locator('.traffic-totals')).toContainText('Requests');
  await expect(page.locator('.traffic-totals strong').first()).not.toHaveText('0');
  const other = await browser.newContext();
  const otherPage = await other.newPage();
  await otherPage.goto('http://127.0.0.1:19900');
  await otherPage.getByLabel('Project token').fill('console-e2e-other-token');
  await otherPage.getByRole('button', { name: 'Open console' }).click();
  await expect(
    otherPage.getByRole('heading', { name: 'Your first layer of protection starts here' }),
  ).toBeVisible();
  expect((await other.request.get(`http://127.0.0.1:19900/api/waf/sites/${id}`)).status()).toBe(
    404,
  );
  await other.close();
  expect(
    (
      await page.request.post('/api/waf/sites', {
        headers: { Origin: 'https://foreign.example' },
        data: {},
      })
    ).status(),
  ).toBe(403);
  const cookies = await page.context().cookies();
  const session = cookies.find((c) => c.name === 'waf_session');
  expect(session?.httpOnly).toBe(true);
  expect(session?.sameSite).toBe('Strict');
  expect(session?.value).not.toContain('console-e2e-project-token');
  expect(await page.evaluate(() => localStorage.length)).toBe(0);
  await page.getByRole('button', { name: 'All sites' }).click();
  await expect(page.getByRole('button', { name: 'shop.localhost', exact: true })).toBeVisible();
  await mkdir('../.local', { recursive: true });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.screenshot({ path: '../.local/console-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  await page.screenshot({ path: '../.local/console-mobile.png', fullPage: true });
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByLabel('Project token')).toBeVisible();
  expect((await page.request.get('/api/waf/sites')).status()).toBe(401);
  expect(errors).toEqual([]);
  await mkdir('../docs/validation', { recursive: true });
  await writeFile(
    '../docs/validation/console.json',
    JSON.stringify(
      {
        recorded_at: new Date().toISOString(),
        browser: 'Chromium',
        protect_site_ms: elapsed,
        real_api_and_edge: true,
        dns_provider_simulated: true,
        blocking_verified: true,
        policy_update_verified: true,
        rule_management_verified: true,
        cross_project_404: true,
        csrf_rejected: true,
        http_only_session: true,
        mobile_no_overflow: true,
        real_analytics_verified: true,
        event_exclusion_verified: true,
        public_domain_tested: false,
      },
      null,
      2,
    ) + '\n',
  );
});
