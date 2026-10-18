import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';

const CANARY = 'CANARY-SERVER-SECRET-must-never-reach-the-browser-0042';
let html = ''; let headers = ''; const assets: Record<string, string> = {};
before(() => {
  execFileSync('node', ['build.mjs'], { cwd: new URL('..', import.meta.url).pathname, stdio: 'pipe', env: {
    PATH: process.env.PATH, TRUSION_API_BASE_URL: 'https://api.trusion.test', TRUSION_AUTH_URL: 'https://auth.trusion.test/auth/v1', TRUSION_AUTH_PUBLIC_KEY: 'public-anon-key-for-tests',
    // server-only secrets present in the build environment must not be bundled:
    SUPABASE_JWT_SECRET: CANARY, ANTHROPIC_API_KEY: CANARY, OPENROUTER_API_KEY: CANARY, SERVICE_ROLE_KEY: CANARY } });
  const dist = new URL('../dist/', import.meta.url);
  html = readFileSync(new URL('index.html', dist), 'utf8'); headers = readFileSync(new URL('_headers', dist), 'utf8');
  for (const f of readdirSync(new URL('assets/', dist))) assets[f] = readFileSync(new URL(`assets/${f}`, dist), 'utf8');
});

test('built index.html has no inline script, inline style, or event-handler attributes (so CSP needs no unsafe-inline)', () => {
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) { assert.match(m[1], /\bsrc="\/assets\//); assert.equal(m[2].trim(), '', 'script has inline body'); }
  assert.ok(!/<style\b/i.test(html)); assert.ok(!/\sstyle\s*=/i.test(html)); assert.ok(!/\son[a-z]+\s*=/i.test(html));
  assert.match(html, /<html lang="en">/); assert.ok(!/user-scalable|maximum-scale/.test(html), 'zoom must not be disabled');
});

test('CSP header: strict, no unsafe-inline / unsafe-eval / wildcards; connect-src limited to API + auth origins', () => {
  const csp = /Content-Security-Policy: (.*)/.exec(headers)![1];
  assert.match(csp, /default-src 'none'/); assert.match(csp, /script-src 'self'(;|$)/); assert.match(csp, /style-src 'self'(;|$)/);
  assert.match(csp, /frame-ancestors 'none'/); assert.match(csp, /object-src 'none'/); assert.match(csp, /base-uri 'none'/);
  assert.ok(!/unsafe-inline|unsafe-eval|\*|data:(?!.*img)/.test(csp.replace("img-src 'self' data:", '')), csp);
  assert.match(csp, /connect-src 'self' https:\/\/api\.trusion\.test https:\/\/auth\.trusion\.test(;|$)/);
  for (const h of ['X-Content-Type-Options: nosniff', 'X-Frame-Options: DENY', 'Referrer-Policy: no-referrer', 'Strict-Transport-Security']) assert.ok(headers.includes(h), h);
});

test('bundle contains NO provider endpoints/keys and none of the server-side secrets that were present in the build environment', () => {
  const all = Object.values(assets).join('\n');
  assert.ok(!all.includes(CANARY), 'a build-environment secret leaked into the bundle');
  for (const re of [/api\.anthropic\.com/i, /x-api-key/i, /anthropic-version/i, /sk-ant-/i, /service_role/i, /BEGIN [A-Z ]*PRIVATE KEY/, /openrouter\.ai/i, /api\.groq\.com/i, /SUPABASE_JWT_SECRET/]) assert.ok(!re.test(all), String(re));
  assert.ok(all.includes('https://api.trusion.test'), 'public API URL was injected');
  assert.ok(all.includes('public-anon-key-for-tests'), 'public key was injected');
});

test('bundle does not reference persistent browser storage', () => {
  const all = Object.values(assets).join('\n');
  assert.ok(!/localStorage|sessionStorage|indexedDB|document\.cookie/.test(all));
});

test('bundle has no eval / new Function (CSP-compatible)', () => {
  const js = Object.entries(assets).filter(([k]) => k.endsWith('.js')).map(([, v]) => v).join('\n');
  assert.ok(!/[^.\w]eval\(/.test(js)); assert.ok(!/new Function\(/.test(js));
});
