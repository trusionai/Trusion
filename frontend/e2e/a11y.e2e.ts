/**
 * Automated accessibility checks in real Chromium. axe-core was NOT available offline, so these are our own
 * WCAG-derived checks (names, headings, landmarks, computed contrast, keyboard order, visible focus, reflow).
 * They are a floor, not a full audit: no screen-reader testing, no manual review.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { Page } from 'playwright';
import { startHarness, signIn, PW } from './harness.ts';
import { apk, manifest, dexWith } from '../../backend/tests/helpers/apk-fixture.ts';

void PW;
const fx = (n: string) => readFileSync(new URL(`../../backend/tests/fixtures/${n}`, import.meta.url));
const USERS = Object.fromEntries(['axa', 'axb', 'axc', 'root'].map((n) => [`${n}@example.com`, { password: PW, sub: n === 'root' ? 'root-admin' : `ax-${n}` }]));
let h: Awaited<ReturnType<typeof startHarness>>;
before(async () => { h = await startHarness(USERS, ['root-admin']); });
after(async () => { await h?.stop(); });

/** Runs inside the page. Returns human-readable problems. */
const AUDIT = () => {
  const problems: string[] = [];
  const vis = (e: Element) => { const r = (e as HTMLElement).getBoundingClientRect(); const cs = getComputedStyle(e); return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none'; };
  const nameOf = (e: Element): string => {
    const aria = e.getAttribute('aria-label'); if (aria) return aria.trim();
    const lb = e.getAttribute('aria-labelledby'); if (lb) return lb.split(/\s+/).map((id) => document.getElementById(id)?.textContent ?? '').join(' ').trim();
    const labels = (e as HTMLInputElement).labels; if (labels && labels.length) return Array.from(labels).map((l) => l.textContent ?? '').join(' ').trim();
    return (e.textContent ?? '').trim() || (e.getAttribute('title') ?? '').trim();
  };
  for (const e of Array.from(document.querySelectorAll('a[href],button,input,select,textarea,summary,[role=tab]'))) {
    if (!vis(e) || (e instanceof HTMLInputElement && e.type === 'hidden')) continue;
    if (!nameOf(e)) problems.push(`no accessible name: <${e.tagName.toLowerCase()}${e.id ? '#' + e.id : ''}>`);
  }
  const hs = Array.from(document.querySelectorAll('h1,h2,h3,h4')).filter(vis).map((x) => Number(x.tagName[1]));
  if (hs.filter((x) => x === 1).length !== 1) problems.push(`expected exactly one h1, found ${hs.filter((x) => x === 1).length}`);
  for (let i = 1; i < hs.length; i++) if (hs[i] - hs[i - 1] > 1) problems.push(`heading level jumps h${hs[i - 1]} -> h${hs[i]}`);
  if (document.querySelectorAll('main').length !== 1) problems.push('page must have exactly one <main>');
  const dupIds = Array.from(document.querySelectorAll('[id]')).map((e) => e.id).filter((id, i, a) => a.indexOf(id) !== i); if (dupIds.length) problems.push('duplicate ids: ' + dupIds.join(','));
  for (const img of Array.from(document.querySelectorAll('img'))) if (!img.hasAttribute('alt')) problems.push('img without alt');
  // ---- WCAG contrast from computed styles
  type C = { r: number; g: number; b: number; a: number };
  const parse = (c: string): C => { const m = c.match(/rgba?\(([^)]+)\)/); if (!m) return { r: 0, g: 0, b: 0, a: 0 }; const p = m[1].split(/[ ,/]+/).filter(Boolean).map(parseFloat); return { r: p[0], g: p[1], b: p[2], a: p[3] ?? 1 }; };
  const over = (top: C, bot: C): C => ({ r: top.r * top.a + bot.r * (1 - top.a), g: top.g * top.a + bot.g * (1 - top.a), b: top.b * top.a + bot.b * (1 - top.a), a: 1 });
  const lum = (c: C) => { const f = (v: number) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  const bgOf = (e: Element): C => { const layers: C[] = []; let cur: Element | null = e; while (cur) { const c = parse(getComputedStyle(cur).backgroundColor); if (c.a > 0) layers.push(c); if (c.a >= 1) break; cur = cur.parentElement; } let base: C = { r: 255, g: 255, b: 255, a: 1 }; for (const l of layers.reverse()) base = over(l, base); return base; };
  const seen = new Set<Element>();
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let n: Node | null; let checked = 0;
  while ((n = walker.nextNode())) {
    const el = n.parentElement; if (!el || seen.has(el) || !(n.textContent ?? '').trim() || !vis(el)) continue; seen.add(el);
    if (el.closest('[disabled],[aria-disabled=true]') || ['SCRIPT', 'STYLE', 'NOSCRIPT', 'OPTION'].includes(el.tagName)) continue;
    const cs = getComputedStyle(el); const bg = bgOf(el); const fg = over(parse(cs.color), bg);
    const L1 = lum(fg), L2 = lum(bg); const ratio = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);
    const px = parseFloat(cs.fontSize); const bold = parseInt(cs.fontWeight, 10) >= 700; const large = px >= 24 || (px >= 18.66 && bold);
    checked++; if (ratio < (large ? 3 : 4.5)) problems.push(`low contrast ${ratio.toFixed(2)}:1 (<${large ? 3 : 4.5}) "${(n.textContent ?? '').trim().slice(0, 30)}" in <${el.tagName.toLowerCase()} class="${el.className}"> fg=${cs.color} bg=rgb(${Math.round(bg.r)},${Math.round(bg.g)},${Math.round(bg.b)})`);
  }
  if (checked < 5) problems.push(`contrast audit looked at only ${checked} text elements`);
  return problems;
};
const NAME_SHIM = 'window.__name = (f) => f;';   // tsx/esbuild keepNames helper referenced by serialised page functions
const audit = (p: Page, label: string) => p.evaluate(AUDIT).then((x) => x.map((m) => `[${label}] ${m}`));
const go = (p: Page, hash: string) => p.evaluate((x) => { window.location.hash = x; }, hash);
const result = (p: Page) => p.locator('article[aria-label="Analysis result"]');

test('login page and every signed-in page pass the automated accessibility floor (names, headings, landmarks, contrast)', { timeout: 120000 }, async () => {
  const ctx = await h.browser.newContext({ viewport: { width: 1280, height: 900 } }); await ctx.addInitScript(NAME_SHIM); const page = await ctx.newPage();
  const problems: string[] = [];
  try {
    await page.goto(h.web.url + '/'); await page.locator('#email').waitFor(); problems.push(...await audit(page, 'login'));
    await page.getByRole('tab', { name: 'Create account' }).click(); problems.push(...await audit(page, 'login:create-account'));
    await page.getByRole('tab', { name: 'Sign in' }).click();
    h.backend.store.grantPlan('ax-axa', 'pro', { source: 'e2e' }); await signIn(page, 'axa');
    problems.push(...await audit(page, 'dashboard'));
    await go(page, '#/message'); await page.locator('#msg').fill('[BRI] Kartu diblokir. Balas dengan KODE OTP segera, install Cek-Resi.apk di http://bca-verifikasi-akun.xyz'); await page.getByRole('button', { name: 'Analyse message' }).click(); await result(page).waitFor();
    problems.push(...await audit(page, 'message+result'));
    await go(page, '#/url'); await page.locator('#url').fill('http://bca-verifikasi-akun.xyz/Cek.apk'); await page.getByRole('button', { name: 'Scan link' }).click(); await result(page).waitFor();
    problems.push(...await audit(page, 'url+result'));
    await go(page, '#/apk'); await page.locator('#apk').setInputFiles({ name: 'a.apk', mimeType: 'application/octet-stream', buffer: apk({ manifestBuf: manifest({ perms: ['READ_SMS', 'RECEIVE_SMS', 'INTERNET'] }), dex: dexWith('http://185.1.2.3/c2') }) });
    await page.getByRole('button', { name: 'Analyse APK' }).click(); await result(page).waitFor({ timeout: 15000 });
    problems.push(...await audit(page, 'apk+result'));
    await go(page, '#/screenshot'); await page.locator('#shot').setInputFiles({ name: 's.png', mimeType: 'image/png', buffer: fx('scam.png') });
    await page.getByRole('button', { name: 'Analyse screenshot' }).click(); await result(page).waitFor({ timeout: 40000 });
    problems.push(...await audit(page, 'screenshot+result'));
    await go(page, '#/history'); await page.locator('table').waitFor(); problems.push(...await audit(page, 'history'));
    await go(page, '#/account'); await page.locator('text=Billing is not available yet').waitFor(); problems.push(...await audit(page, 'account'));
    await go(page, '#/n/riskradar'); await page.locator('.banner').waitFor(); problems.push(...await audit(page, 'unavailable'));
  } finally { await ctx.close(); }
  assert.deepEqual(problems, []);
});

test('admin page passes the same floor', { timeout: 60000 }, async () => {
  const ctx = await h.browser.newContext(); await ctx.addInitScript(NAME_SHIM); const page = await ctx.newPage();
  try {
    h.backend.store.grantPlan('root-admin', 'pro', { source: 'e2e' }); await page.goto(h.web.url + '/'); await signIn(page, 'root');
    await go(page, '#/admin'); await page.locator('h1', { hasText: 'Administration' }).waitFor(); await page.locator('table').waitFor();
    assert.deepEqual(await audit(page, 'admin'), []);
  } finally { await ctx.close(); }
});

test('keyboard: logical Tab order, visible focus on every stop, skip link works, focus moves to content on navigation, form usable without a mouse', { timeout: 90000 }, async () => {
  const ctx = await h.browser.newContext(); await ctx.addInitScript(NAME_SHIM); const page = await ctx.newPage();
  try {
    h.backend.store.grantPlan('ax-axb', 'pro', { source: 'e2e' }); await page.goto(h.web.url + '/'); await signIn(page, 'axb');
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
    const stops: string[] = [];
    for (let i = 0; i < 10; i++) {
      await page.keyboard.press('Tab');
      stops.push(await page.evaluate(() => {
        const e = document.activeElement as HTMLElement; const cs = getComputedStyle(e);
        const outlineOk = cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) >= 2;
        return `${(e.textContent ?? '').trim().slice(0, 28)}|${outlineOk ? 'focus-ok' : 'NO-FOCUS-INDICATOR'}`;
      }));
    }
    assert.deepEqual(stops.map((s) => s.split('|')[0]).slice(0, 9), ['Skip to main content', 'Dashboard', 'Messages', 'Links', 'APK files', 'Screenshots', 'History', 'Account', 'Not available yet']);
    assert.deepEqual(stops.filter((s) => s.endsWith('NO-FOCUS-INDICATOR')), [], 'every focused element must show a visible focus indicator');
    await page.locator('.skip').focus(); await page.keyboard.press('Enter');
    assert.equal(await page.evaluate(() => document.activeElement?.id), 'main', 'skip link focuses main');
    await page.locator('nav a', { hasText: 'Messages' }).click();
    await page.waitForFunction(() => document.activeElement?.id === 'main', undefined, { timeout: 3000 });   // effect runs after hashchange (async)
    assert.equal(await page.evaluate(() => document.activeElement?.id), 'main', 'navigation moves focus to the content');
    assert.equal(await page.locator('h1', { hasText: 'Message analysis' }).count(), 1);
    // complete a whole analysis with the keyboard only
    await page.locator('#msg').focus(); await page.keyboard.type('Balas dengan KODE OTP segera');
    await page.keyboard.press('Tab');                                   // checkbox is disabled (AI not configured) so focus goes to the submit button
    assert.equal(await page.evaluate(() => (document.activeElement as HTMLElement).textContent), 'Analyse message');
    await page.keyboard.press('Enter'); await result(page).waitFor();
    assert.match(await result(page).innerText(), /credential_request/);
  } finally { await ctx.close(); }
});

test('reflow: usable at 320 CSS px with text enlarged to 200% (no horizontal scroll, nothing clipped off-screen)', { timeout: 90000 }, async () => {
  const ctx = await h.browser.newContext({ viewport: { width: 320, height: 640 } }); await ctx.addInitScript(NAME_SHIM); const page = await ctx.newPage();
  try {
    h.backend.store.grantPlan('ax-axc', 'pro', { source: 'e2e' }); await page.goto(h.web.url + '/'); await signIn(page, 'axc');
    await page.evaluate(() => { document.documentElement.style.fontSize = '200%'; });          // CSSOM: allowed by the strict CSP
    for (const hash of ['#/dashboard', '#/message', '#/apk', '#/account', '#/n/breach-checker']) {
      await go(page, hash); await page.locator('h1').first().waitFor(); await page.waitForTimeout(150);
      const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      assert.ok(over <= 1, `${hash}: horizontal overflow ${over}px at 320px/200%`);
    }
  } finally { await ctx.close(); }
});
