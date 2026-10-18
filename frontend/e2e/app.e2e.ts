/**
 * REAL-BROWSER end-to-end tests: Chromium -> built frontend (served with the production CSP) -> real backend (real tesseract OCR).
 * Mocked: the auth server (GoTrue-like mock). Not exercised: real Supabase, real AI providers, real payments.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { chromium } from 'playwright';
import type { Browser, BrowserContext, Page } from 'playwright';
import { bootBackend } from '../tests/helpers/backend.ts';
import { bootMockAuth } from '../tests/helpers/mock-auth.ts';
import { serveDist } from './helpers.ts';
import { apk, manifest, dexWith } from '../../backend/tests/helpers/apk-fixture.ts';

process.env.PLAYWRIGHT_BROWSERS_PATH ??= '/opt/pw-browsers';
const API = 18090, AUTH = 18091, WEB = 18092;
const ROOT = new URL('..', import.meta.url).pathname;
const fx = (n: string) => readFileSync(new URL(`../../backend/tests/fixtures/${n}`, import.meta.url));
const PW = 'correct-horse-1';
const USERS: Record<string, { password: string; sub: string }> = Object.fromEntries(
  ['alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'grace', 'heidi', 'ivan', 'judy', 'root'].map((n) => [`${n}@example.com`, { password: PW, sub: n === 'root' ? 'root-admin' : `e2e-${n}` }]));

let browser: Browser; let backend: Awaited<ReturnType<typeof bootBackend>>; let auth: Awaited<ReturnType<typeof bootMockAuth>>; let web: Awaited<ReturnType<typeof serveDist>>;
const origins = new Set<string>();

before(async () => {
  execFileSync('node', ['build.mjs'], { cwd: ROOT, stdio: 'pipe', env: { PATH: process.env.PATH, TRUSION_API_BASE_URL: `http://127.0.0.1:${API}`, TRUSION_AUTH_URL: `http://127.0.0.1:${AUTH}/auth/v1`, TRUSION_AUTH_PUBLIC_KEY: 'public-anon-key-for-tests', TRUSION_ALLOW_INSECURE_DEV: "1" } as never });
  auth = await bootMockAuth(USERS, { port: AUTH });
  backend = await bootBackend({ port: API, corsOrigins: [`http://127.0.0.1:${WEB}`], admins: ['root-admin'] });
  web = await serveDist(ROOT + 'dist', WEB);
  browser = await chromium.launch({ args: ['--no-sandbox'] });
});
after(async () => { await browser?.close(); await web?.close(); await backend?.close(); await auth?.close(); });

interface Ctx { page: Page; ctx: BrowserContext; errors: string[]; csp: () => Promise<string[]> }
async function open(opts: { width?: number; height?: number } = {}): Promise<Ctx> {
  const ctx = await browser.newContext({ viewport: { width: opts.width ?? 1280, height: opts.height ?? 900 } });
  ctx.on('request', (r) => origins.add(new URL(r.url()).origin));
  const page = await ctx.newPage(); const errors: string[] = [];
  page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
  page.on('console', (m) => { if (m.type() === 'error') errors.push('console: ' + m.text()); });
  page.on('dialog', async (d) => { errors.push('DIALOG: ' + d.message()); await d.dismiss(); });
  await page.addInitScript(() => { (window as any).__csp = []; document.addEventListener('securitypolicyviolation', (e) => (window as any).__csp.push(e.violatedDirective + ' ' + e.blockedURI)); });
  await page.goto(web.url + '/');
  return { page, ctx, errors, csp: () => page.evaluate(() => (window as any).__csp as string[]) };
}
async function login(page: Page, name: string, grant?: 'pro' | 'starter') {
  if (grant) backend.store.grantPlan(USERS[`${name}@example.com`].sub, grant, { source: 'e2e' });
  await page.locator('#email').fill(`${name}@example.com`); await page.locator('#password').fill(PW);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.locator('h1', { hasText: 'Dashboard' }).waitFor({ timeout: 10000 });
}
const go = async (page: Page, hash: string) => { await page.evaluate((h) => { window.location.hash = h; }, hash); };
const result = (page: Page) => page.locator('article[aria-label="Analysis result"]');
const storageEmpty = (page: Page) => page.evaluate(() => [localStorage.length, sessionStorage.length, document.cookie]);

const hostileApk = () => apk({ manifestBuf: manifest({ pkg: '"><img src=x onerror=window.__xss=1>', perms: ['<script>window.__xss=2</script>', 'READ_SMS', 'RECEIVE_SMS', 'INTERNET'] }), dex: dexWith('http://185.1.2.3/<svg onload=window.__xss=3>') });

test('anonymous visit: sign-in only, no API traffic, nothing in storage, no CSP violations, zoom not disabled', { timeout: 60000 }, async () => {
  const before = backend.hits.filter((h) => h.includes('/v1/')).length;
  const { page, ctx, errors, csp } = await open();
  try {
    await page.locator('h1', { hasText: 'TRUSION' }).waitFor();
    assert.equal(await page.locator('html').getAttribute('lang'), 'en');
    assert.deepEqual(await storageEmpty(page), [0, 0, '']);
    assert.equal(backend.hits.filter((h) => h.includes('/v1/')).length, before, 'no backend calls before sign-in');
    assert.match(await page.locator('text=no guest mode').first().innerText(), /no guest mode/);
    assert.deepEqual(await csp(), []); assert.deepEqual(errors, []);
  } finally { await ctx.close(); }
});

test('sign-in: wrong password shows a generic error; success shows server-derived plan; token is NOT persisted anywhere', { timeout: 60000 }, async () => {
  const { page, ctx, errors, csp } = await open();
  try {
    await page.locator('#email').fill('alice@example.com'); await page.locator('#password').fill('nope-nope-1');
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await page.locator('[role=alert]', { hasText: 'Email or password is incorrect.' }).waitFor();
    await login(page, 'alice');
    await page.locator('text=Plan: free').waitFor(); await page.locator('text=0 of 20').waitFor();
    assert.deepEqual(await storageEmpty(page), [0, 0, '']);
    await page.reload();                                           // memory-only session: reload signs out
    await page.locator('#email').waitFor();
    assert.deepEqual(await csp(), []); assert.deepEqual(errors.filter((e) => !/401|400/.test(e)), []);
  } finally { await ctx.close(); }
});

test('message analysis: findings explained; AI consent disabled when AI is not configured; double-click charges ONCE', { timeout: 60000 }, async () => {
  const { page, ctx, errors, csp } = await open();
  try {
    await login(page, 'bob', 'pro'); await go(page, '#/message');
    await page.locator('#msg').fill('[BRI] Kartu ATM Anda diblokir. Balas dengan KODE OTP segera dan install aplikasi Cek-Resi.apk');
    assert.equal(await page.getByRole('checkbox').isDisabled(), true);
    await page.locator('text=AI interpretation is not configured').waitFor();
    await page.getByRole('button', { name: 'Analyse message' }).dblclick();
    await result(page).waitFor({ timeout: 15000 });
    const txt = await result(page).innerText();
    assert.match(txt, /credential_request/); assert.match(txt, /apk_install_lure/); assert.match(txt, /High-risk indicators found|Suspicious indicators found/);
    assert.match(txt, /Rule-based/); assert.match(txt, /AI interpretation was not used/);
    assert.equal(backend.store.usage('e2e-bob').used, 1, 'double click must not double-charge');
    assert.deepEqual(await csp(), []); assert.deepEqual(errors, []);
  } finally { await ctx.close(); }
});

test('XSS (reflected + persisted): hostile package/permission names from an APK are inert TEXT in the result AND after reload from history', { timeout: 90000 }, async () => {
  const { page, ctx, errors, csp } = await open();
  try {
    await login(page, 'carol', 'pro'); await go(page, '#/apk');
    await page.locator('#apk').setInputFiles({ name: 'holiday.jpg', mimeType: 'image/jpeg', buffer: hostileApk() });
    await page.getByRole('button', { name: 'Analyse APK' }).click();
    await result(page).waitFor({ timeout: 15000 });
    const check = async (label: string) => {
      assert.equal(await page.evaluate(() => (window as any).__xss), undefined, `${label}: payload executed`);
      assert.equal(await page.locator('main img, main svg, main iframe').count(), 0, `${label}: injected element`);
      assert.equal(await page.locator('script').count(), 1, `${label}: only the app bundle script exists`);
      const t = await result(page).innerText();
      assert.ok(t.includes('<img src=x onerror=window.__xss=1>'), `${label}: payload visible as literal text`);
      assert.ok(t.includes('<script>window.__xss=2</script>'), `${label}: script payload visible as literal text`);
    };
    await check('fresh result');
    await page.locator('a', { hasText: 'History' }).click();
    await page.locator('table a', { hasText: 'apk' }).first().click();
    await result(page).waitFor(); await check('persisted record');
    assert.deepEqual(await csp(), []); assert.deepEqual(errors, []);
  } finally { await ctx.close(); }
});

test('CSP is really enforced by the browser (negative controls): inline script and eval are blocked', { timeout: 60000 }, async () => {
  const { page, ctx, csp } = await open();
  try {
    await page.evaluate(() => { const s = document.createElement('script'); s.textContent = 'window.__bypass = 1'; document.body.appendChild(s); });
    await page.waitForTimeout(150);
    assert.equal(await page.evaluate(() => (window as any).__bypass), undefined, 'inline script must not run');
    // NOTE: eval() inside page.evaluate is NOT a valid probe (CDP evaluation is exempt from unsafe-eval checks),
    // so use a string-timeout, which the browser itself checks against CSP.
    await page.evaluate(() => { setTimeout('window.__evalRan = 1', 0); });
    await page.waitForTimeout(200);
    assert.equal(await page.evaluate(() => (window as any).__evalRan), undefined, 'string-eval must not run');
    const v = await csp();
    assert.ok(v.some((x) => x.startsWith('script-src')), 'expected a script-src violation report, got ' + JSON.stringify(v));
    assert.ok(v.some((x) => /eval/.test(x)), 'expected an eval violation report, got ' + JSON.stringify(v));
  } finally { await ctx.close(); }
});

test('link scanner: javascript: URL is rejected with a friendly error and cannot run; scam link is flagged and shown as inert text', { timeout: 60000 }, async () => {
  const { page, ctx, errors } = await open();
  try {
    await login(page, 'dave', 'pro'); await go(page, '#/url');
    await page.locator('#url').fill('javascript:window.__xss=1'); await page.getByRole('button', { name: 'Scan link' }).click();
    await page.locator('text=Enter a valid http or https URL.').waitFor();
    assert.equal(await result(page).count(), 0); assert.equal(await page.evaluate(() => (window as any).__xss), undefined);
    await page.locator('#url').fill('http://bca-verifikasi-akun.xyz/Cek-Resi.apk'); await page.getByRole('button', { name: 'Scan link' }).click();
    await result(page).waitFor();
    const t = await result(page).innerText(); assert.match(t, /brand_lookalike/); assert.match(t, /apk_download_link/); assert.match(t, /High-risk indicators found/);
    assert.match(t, /does not look up domain age|Domain age\/registrar \(WHOIS\) and TLS certificate were NOT checked/);
    assert.equal(await page.locator('main a[href*="bca-verifikasi"]').count(), 0, 'scanned link must not be clickable');
    assert.deepEqual(errors.filter((e) => !/400/.test(e)), []);
  } finally { await ctx.close(); }
});

test('APK page: non-APK is refused locally (server never called); extension is irrelevant', { timeout: 60000 }, async () => {
  const { page, ctx } = await open();
  try {
    await login(page, 'erin', 'pro'); await go(page, '#/apk');
    const n = backend.hits.filter((h) => h.includes('/v1/analyze/apk')).length;
    await page.locator('#apk').setInputFiles({ name: 'totally-an-app.apk', mimeType: 'application/vnd.android.package-archive', buffer: Buffer.from('this is just text') });
    await page.locator('text=does not look like an APK').waitFor();
    assert.equal(await page.getByRole('button', { name: 'Analyse APK' }).isDisabled(), true);
    assert.equal(backend.hits.filter((h) => h.includes('/v1/analyze/apk')).length, n);
  } finally { await ctx.close(); }
});

test('screenshot: real OCR of the uploaded pixels is shown; GIF refused locally; filename is irrelevant', { timeout: 90000 }, async () => {
  const { page, ctx, errors, csp } = await open();
  try {
    await login(page, 'frank', 'pro'); await go(page, '#/screenshot');
    await page.locator('#shot').setInputFiles({ name: 'cat-photo.png', mimeType: 'image/png', buffer: fx('scam.png') });
    await page.getByRole('button', { name: 'Analyse screenshot' }).click();
    await result(page).waitFor({ timeout: 40000 });
    const t = await result(page).innerText();
    assert.match(t, /Text read from the image/); assert.match(t, /OTP/); assert.match(t, /bca-verifikasi-akun\.xyz/i); assert.match(t, /credential_request/); assert.match(t, /OCR/);
    await page.locator('#shot').setInputFiles({ name: 'x.png', mimeType: 'image/png', buffer: Buffer.concat([Buffer.from('GIF89a'), Buffer.alloc(64)]) });
    await page.locator('text=Only PNG and JPEG images are supported').waitFor();
    assert.deepEqual(await csp(), []); assert.deepEqual(errors, []);
  } finally { await ctx.close(); }
});

test('unavailable / removed features: honest explanation, NO run controls, no backend calls', { timeout: 60000 }, async () => {
  const { page, ctx } = await open();
  try {
    await login(page, 'grace', 'pro');
    await page.locator('text=Plan: pro').waitFor(); await page.waitForLoadState('networkidle');
    const n = backend.hits.length;
    for (const id of ['breach-checker', 'riskradar', 'verification-center', 'deepfake-center', 'voice-fraud-intelligence', 'qr-scanner']) {
      await go(page, `#/n/${id}`);
      await page.locator('.banner').waitFor();
      assert.equal(await page.locator('main button, main input, main textarea, main form').count(), 0, id);
    }
    await go(page, '#/n/breach-checker'); assert.match(await page.locator('main').innerText(), /Status: Removed[\s\S]*not from any breach database/);
    await go(page, '#/n/riskradar'); assert.match(await page.locator('main').innerText(), /hard-coded sample entries/);
    await page.locator('summary', { hasText: 'Not available yet' }).click();
    assert.ok((await page.locator('details.more li').count()) >= 19);
    assert.equal(backend.hits.length, n + 0, 'unavailable pages must not call the backend');
  } finally { await ctx.close(); }
});

test('quota exhaustion: UI explains it, says nothing was charged, and backend usage is exact', { timeout: 60000 }, async () => {
  const { page, ctx } = await open();
  try {
    backend.store.grantPlan('e2e-heidi', 'starter', { source: 'e2e' });
    const pre = backend.store.reserve('e2e-heidi', 'pre', 299, 300); if (pre.ok) backend.store.commit(pre.reservationId, 299);
    await login(page, 'heidi'); await go(page, '#/message');
    await page.locator('#msg').fill('halo apa kabar'); await page.getByRole('button', { name: 'Analyse message' }).click(); await result(page).waitFor();
    await page.locator('#msg').fill('pesan kedua'); await page.getByRole('button', { name: 'Analyse message' }).click();
    await page.locator('.banner', { hasText: 'Monthly allowance used up' }).waitFor();
    assert.match(await page.locator('.banner').innerText(), /not charged/);
    assert.equal(backend.store.usage('e2e-heidi').used, 300);
  } finally { await ctx.close(); }
});

test('admin: ordinary users see no Admin link and get a server 403 on the URL; the allowlisted admin sees the overview', { timeout: 60000 }, async () => {
  const a = await open();
  try {
    await login(a.page, 'ivan', 'pro');
    assert.equal(await a.page.locator('nav a', { hasText: 'Admin' }).count(), 0);
    await go(a.page, '#/admin'); await a.page.locator('.banner', { hasText: 'Not permitted' }).waitFor();
  } finally { await a.ctx.close(); }
  const b = await open();
  try {
    await login(b.page, 'root', 'pro'); await b.page.locator('nav a', { hasText: 'Admin' }).waitFor();
    await go(b.page, '#/admin'); await b.page.locator('h1', { hasText: 'Administration' }).waitFor();
    await b.page.locator('text=No AI models are configured').waitFor();
  } finally { await b.ctx.close(); }
});

test('session expiry: when refresh is refused the user is returned to sign-in with a notice, and nothing stays in storage', { timeout: 60000 }, async () => {
  const { page, ctx } = await open();
  try {
    auth.state.ttl = 4; auth.state.refreshOk = false;
    await login(page, 'judy', 'pro');
    await page.locator('#email').waitFor({ timeout: 15000 });
    await page.locator('text=Your session expired. Please sign in again.').waitFor();
    assert.deepEqual(await storageEmpty(page), [0, 0, '']);
  } finally { auth.state.ttl = 3600; auth.state.refreshOk = true; await ctx.close(); }
});

test('responsive: no horizontal overflow at 375px and 1280px even with long hostile strings; screenshots captured', { timeout: 90000 }, async () => {
  for (const [w, h, tag] of [[375, 812, 'mobile'], [1280, 900, 'desktop']] as const) {
    const { page, ctx } = await open({ width: w, height: h });
    try {
      await login(page, 'alice', 'pro');
      const over = () => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      assert.ok((await over()) <= 1, `${tag} dashboard overflow ${await over()}`);
      await page.locator('text=Plan: pro').waitFor(); await page.waitForLoadState('networkidle');
      await page.screenshot({ path: `e2e/artifacts/${tag}-dashboard.png` });
      await go(page, '#/apk');
      await page.locator('#apk').setInputFiles({ name: 'a.apk', mimeType: 'application/octet-stream', buffer: hostileApk() });
      await page.getByRole('button', { name: 'Analyse APK' }).click(); await result(page).waitFor({ timeout: 15000 });
      assert.ok((await over()) <= 1, `${tag} result overflow ${await over()}`);
      await page.screenshot({ path: `e2e/artifacts/${tag}-apk-result.png`, fullPage: true });
      const nav = await page.locator('nav a').first().boundingBox(); assert.ok(nav && nav.height >= 24);
    } finally { await ctx.close(); }
  }
});

test('backend outage: the UI shows an error and NO result is fabricated', { timeout: 60000 }, async () => {
  const { page, ctx } = await open();
  try {
    await login(page, 'bob', 'pro'); await go(page, '#/message');
    await page.locator('#msg').fill('Balas dengan KODE OTP segera');
    await backend.close();
    await page.getByRole('button', { name: 'Analyse message' }).click();
    await page.locator('.banner', { hasText: 'Cannot reach the server' }).waitFor({ timeout: 15000 });
    assert.equal(await result(page).count(), 0, 'no result may be shown after a failed request');
    assert.match(await page.locator('.banner').innerText(), /No result was produced/);
  } finally { await ctx.close(); backend = await bootBackend({ port: API, corsOrigins: [`http://127.0.0.1:${WEB}`], admins: ['root-admin'] }); }
});

test('network audit: the browser only ever talked to the app, the TRUSION API and the auth server — never an AI provider', async () => {
  const allowed = new Set([`http://127.0.0.1:${WEB}`, `http://127.0.0.1:${API}`, `http://127.0.0.1:${AUTH}`]);
  const extra = [...origins].filter((o) => !allowed.has(o) && !o.startsWith('about') && !o.startsWith('data') && !o.startsWith('chrome'));
  assert.deepEqual(extra, []);
  writeFileSync('e2e/artifacts/network-origins.json', JSON.stringify([...origins].sort(), null, 2));
});
