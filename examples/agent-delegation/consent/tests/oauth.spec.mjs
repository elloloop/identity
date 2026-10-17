import { test, expect } from '@playwright/test';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
let origin;
test.beforeAll(() => { origin = process.env.IDENTITY_BROWSER_FIXTURE_ORIGIN; });
test.beforeEach(async ({ page }) => {
 await page.route('https://challenges.cloudflare.com/turnstile/v0/api.js?*', route => route.fulfill({ contentType: 'application/javascript', body: `window.turnstile={render(element,options){element.dataset.ready='true';queueMicrotask(()=>options.callback('offline-browser-captcha-proof'));return 1;},reset(){}};` }));
});
async function start(page) {
 const response = await fetch(origin + '/fixture/request');
 expect(response.ok).toBeTruthy(); const info = await response.json(); await page.goto(info.url); return info;
}
async function provider(page) {
 await page.getByRole('button', { name: 'Continue with Google' }).click();
 await expect(page.getByRole('heading', { name: 'Synthetic provider' })).toBeVisible();
}
async function google(page) {
 await provider(page); await page.getByRole('link', { name: 'Use example account' }).click();
 await expect(page.getByRole('heading', { name: 'Authorize access to files' })).toBeVisible();
 await expect(page.getByRole('button', { name: 'Allow selected agent' })).toBeDisabled();
}
test('served hosted provider and one-time redemption require explicit agent and Allow', async ({ page }) => {
 const info = await start(page); let returned, redeems = 0;
 page.on('request', request => {
  const url = new URL(request.url());
  if (url.pathname === '/auth/agent-consent' && url.searchParams.has('code')) returned = request.url();
  if (url.pathname.endsWith('/RedeemOAuthCode')) redeems++;
 });
 await google(page); expect(redeems).toBe(1);
 expect(new URL(page.url()).searchParams.has('code')).toBe(false);
 expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
 await page.getByRole('radio', { name: 'Example product engineer' }).check();
 let callback;
 await page.route('http://127.0.0.1:31821/callback?*', route => { callback = new URL(route.request().url()); return route.fulfill({ status: 200, body: 'Native callback' }); });
 await page.getByRole('button', { name: 'Allow selected agent' }).click(); await expect(page.getByText('Native callback', { exact: true })).toBeVisible();
 const response = await fetch(origin + '/oauth/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'desktop-client', redirect_uri: 'http://127.0.0.1:31821/callback', resource: 'https://files.example.test', code: callback.searchParams.get('code'), code_verifier: info.verifier }) });
 expect(response.ok).toBe(true); const issued = await response.json();
 const introspection = await fetch(origin + '/oauth/introspect', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: 'Basic ' + Buffer.from('files-resource:offline-resource-test-secret').toString('base64') }, body: new URLSearchParams({ token: issued.access_token }) });
 const principal = await introspection.json(); expect(principal.active).toBe(true); expect(principal.sub).toBe(info.agent);
 await page.goto(returned); await expect(page.getByRole('alert')).toContainText('does not match'); expect(redeems).toBe(1);
});
test('provider cancellation safely returns to exact request without sign-in or approval', async ({ page }) => {
 const info = await start(page); let redeems = 0;
 page.on('request', request => { if (request.url().includes('/RedeemOAuthCode')) redeems++; });
 await provider(page); await page.getByRole('link', { name: 'Cancel sign-in' }).click();
 await expect(page.getByRole('alert')).toContainText('canceled or refused');
 expect(new URL(page.url()).searchParams.get('request_id')).toBe(new URL(info.url).searchParams.get('request_id'));
 expect(new URL(page.url()).searchParams.has('error')).toBe(false); expect(redeems).toBe(0);
 await expect(page.getByRole('button', { name: 'Allow selected agent' })).toBeHidden();
 expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
});
test('signed-in provider user can explicitly deny without agent selection', async ({ page }) => {
 await start(page); await google(page);
 let callback;
 await page.route('http://127.0.0.1:31821/callback?*', route => { callback = new URL(route.request().url()); return route.fulfill({ status: 200, body: 'Native denial' }); });
 await page.getByRole('button', { name: 'Don’t allow' }).click(); await expect(page.getByText('Native denial', { exact: true })).toBeVisible();
 expect(callback.searchParams.get('error')).toBe('access_denied'); expect(callback.searchParams.has('code')).toBe(false);
});
for (const kind of ['unsolicited', 'state', 'request', 'duplicate-request', 'duplicate-project', 'duplicate-code', 'expired']) {
 test('refuses unbound hosted return: ' + kind, async ({ page }) => {
  const info = await start(page); let destination, redeems = 0;
  await page.route('**/oauth/start/google?*', route => { destination = new URL(route.request().url()).searchParams.get('return_to'); return route.fulfill({ status: 200, body: 'Held synthetic provider start' }); });
  await page.getByRole('button', { name: 'Continue with Google' }).click(); await expect(page.getByText('Held synthetic provider start')).toBeVisible();
  const target = new URL(destination); target.searchParams.set('code', 'synthetic-untrusted-code');
  if (kind === 'unsolicited') await page.evaluate(() => sessionStorage.clear());
  if (kind === 'state') target.searchParams.set('login_state', '0'.repeat(64));
  if (kind === 'request') target.searchParams.set('request_id', 'other-request');
  if (kind === 'duplicate-request') target.searchParams.append('request_id', new URL(info.url).searchParams.get('request_id'));
  if (kind === 'duplicate-project') { target.searchParams.append('project_key', ''); target.searchParams.append('project_key', ''); }
  if (kind === 'duplicate-code') target.searchParams.append('code', 'other-code');
  if (kind === 'expired') await page.evaluate(() => { const key = 'identity.agent-consent.login.v1'; const state = JSON.parse(sessionStorage.getItem(key)); state.expires = Date.now() - 1; sessionStorage.setItem(key, JSON.stringify(state)); });
  page.on('request', request => { if (request.url().includes('/RedeemOAuthCode')) redeems++; });
  await page.goto(target.href); await expect(page.getByRole('alert')).toContainText(kind.startsWith('duplicate-') && kind !== 'duplicate-code' ? 'incomplete' : 'does not match');
  expect(redeems).toBe(0); expect(new URL(page.url()).searchParams.has('code')).toBe(false);
  expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
 });
}
for (const mode of [{ name: 'light-phone', width: 390, height: 844, colorScheme: 'light' }, { name: 'dark-desktop', width: 1180, height: 1000, colorScheme: 'dark' }]) {
 test('provider sign-in remains usable in ' + mode.name, async ({ page }) => {
  await page.setViewportSize({ width: mode.width, height: mode.height }); await page.emulateMedia({ colorScheme: mode.colorScheme });
  await start(page); await expect(page.getByRole('button', { name: 'Continue with Google' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: join(tmpdir(), 'identity-agent-oauth-' + mode.name + '.png'), fullPage: true });
  await google(page);
 });
}

async function projectedConfig(page, change) {
 await page.route('**/auth/agent-consent?*', async route => {
  const response = await route.fetch(); const body = await response.text();
  const modified = body.replace(/(<script[^>]*id="agent-config"[^>]*>)([\s\S]*?)(<\/script>)/, (_, before, raw, after) => before + JSON.stringify(change(JSON.parse(raw))) + after);
  await route.fulfill({ response, body: modified });
 });
}
test('server-projected OAuth-only sign-in needs no password', async ({ page }) => {
 await projectedConfig(page, config => ({ ...config, passwordLoginEnabled: false, captchaEnforceLogin: false }));
 await start(page); await expect(page.getByRole('button', { name: 'Sign in to review' })).toBeHidden(); await google(page);
});
for (const missing of ['provider', 'return-policy']) {
 test('server-projected missing ' + missing + ' explains unavailable sign-in', async ({ page }) => {
  await projectedConfig(page, config => ({ ...config, passwordLoginEnabled: false, captchaEnforceLogin: false, ...(missing === 'provider' ? { oauthProviders: [] } : { hostedOAuthEnabled: false }) }));
  await start(page); await expect(page.getByRole('button', { name: 'Continue with Google' })).toBeHidden();
  await expect(page.locator('#no-login')).toContainText(missing === 'provider' ? 'No supported sign-in method' : 'allowed return policy');
 });
}
test('revoked served provider session cannot enter review or approve', async ({ page }) => {
 await start(page);
 await page.route('**/identity.v1.IdentityService/RedeemOAuthCode', async route => {
  const response = await route.fetch(); const tokens = await response.json();
  expect(response.ok()).toBe(true);
  const logout = await fetch(origin + '/identity.v1.IdentityService/Logout', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Connect-Protocol-Version': '1' }, body: JSON.stringify({ refreshToken: tokens.refreshToken }) });
  expect(logout.ok).toBe(true); await route.fulfill({ response });
 });
 await provider(page); await page.getByRole('link', { name: 'Use example account' }).click();
 await expect(page.getByRole('alert')).toContainText('sign in again');
 await expect(page.getByRole('button', { name: 'Allow selected agent' })).toBeHidden();
 expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
});

test('server-projected borrowed provider requires its original project routing key', async ({ page }) => {
 await projectedConfig(page, config => ({ ...config, passwordLoginEnabled: false, captchaEnforceLogin: false, oauthProviders: [{ key: 'google', startOrigin: 'https://hub.example.test', needsProjectKey: true }] }));
 await start(page); await expect(page.getByRole('button', { name: 'Continue with Google' })).toBeHidden();
 await expect(page.locator('#no-login')).toContainText('project-scoped request link');
});
test('server-projected borrowed provider preserves exact hub origin and public routing key', async ({ page }) => {
 const response = await fetch(origin + '/fixture/request'); const info = await response.json();
 const key = 'pk_' + 'a'.repeat(32); const scoped = new URL(info.url); scoped.searchParams.set('project_key', key);
 await page.route('**/auth/agent-consent?*', async route => {
  // This case checks browser wiring from trusted server configuration. The
  // existing server tests independently exercise actual hub project resolution.
  const response = await route.fetch({ url: info.url }); const html = await response.text();
  const body = html.replace(/(<script[^>]*id="agent-config"[^>]*>)([\s\S]*?)(<\/script>)/, (_, before, raw, after) => before + JSON.stringify({ ...JSON.parse(raw), captchaEnforceLogin: false, oauthProviders: [{ key: 'google', startOrigin: 'https://hub.example.test', needsProjectKey: true }] }) + after);
  await route.fulfill({ response, body });
 });
 let startURL;
 await page.route('https://hub.example.test/oauth/start/google?*', route => { startURL = new URL(route.request().url()); return route.fulfill({ status: 200, body: 'Held hub start' }); });
 await page.goto(scoped.href); await page.getByRole('button', { name: 'Continue with Google' }).click();
 await expect(page.getByText('Held hub start', { exact: true })).toBeVisible();
 expect(startURL.origin).toBe('https://hub.example.test'); expect(startURL.searchParams.get('project_key')).toBe(key);
 const returned = new URL(startURL.searchParams.get('return_to'));
 expect(returned.origin).toBe(origin); expect(returned.searchParams.get('project_key')).toBe(key);
 expect(returned.searchParams.get('request_id')).toBe(scoped.searchParams.get('request_id'));
});

test('returning provider must remain renderable even if another provider is available', async ({ page }) => {
 await start(page); let returned, redeems = 0;
 await page.route('**/oauth/start/google?*', route => { returned = new URL(route.request().url()).searchParams.get('return_to'); return route.fulfill({ status: 200, body: 'Held original sign-in' }); });
 await page.getByRole('button', { name: 'Continue with Google' }).click(); await expect(page.getByText('Held original sign-in')).toBeVisible();
 await projectedConfig(page, config => ({ ...config, captchaEnforceLogin: false, oauthProviders: [{ key: 'google', needsProjectKey: true, startOrigin: 'https://hub.example.test' }, { key: 'github' }] }));
 const target = new URL(returned); target.searchParams.set('code', 'untrusted-synthetic-code');
 page.on('request', request => { if (request.url().includes('/RedeemOAuthCode')) redeems++; });
 await page.goto(target.href); await expect(page.getByRole('alert')).toContainText('does not match'); expect(redeems).toBe(0);
 expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
});
