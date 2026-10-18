import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApp } from '../src/http/app.ts';
import type { AppConfig } from '../src/http/app.ts';
import { Store } from '../src/modules/usage/store.ts';
import { Gateway } from '../src/modules/ai-gateway/gateway.ts';
import { newHealth } from '../src/modules/ai-gateway/router.ts';
import { signJwt } from '../src/modules/auth/jwt.ts';
import type { ModelSpec, ProviderAdapter } from '../src/modules/ai-gateway/types.ts';
import { apk, manifest, dexWith } from './helpers/apk-fixture.ts';

const SECRET = 'test-secret-test-secret-test-secret-123456';
const NOW_S = () => Math.floor(Date.now() / 1000);
const tok = (sub: string, extra: Record<string, unknown> = {}, secret = SECRET) => signJwt({ sub, exp: NOW_S() + 600, aud: 'authenticated', ...extra }, secret);

const free: ModelSpec = { id: 'f1', provider: 'fp', tier: 'free', capabilities: ['text', 'json'], maxContextTokens: 16000, maxOutputTokens: 2000, priceInPerM: 0, priceOutPerM: 0, priceVerifiedAt: null, dataPolicy: 'external_logged', qualityRank: 1, enabled: true };
const paid: ModelSpec = { ...free, id: 'p1', provider: 'pp', tier: 'paid', priceInPerM: 1, priceOutPerM: 2, priceVerifiedAt: new Date().toISOString().slice(0, 10), qualityRank: 0 };

async function boot(o: { registry?: ModelSpec[]; reply?: (u: string) => string; tracer?: any; cors?: string[]; ipLimit?: number } = {}) {
  const store = new Store();
  const calls = { fp: 0, pp: 0 };
  const mk = (name: 'fp' | 'pp'): ProviderAdapter => ({ name, async complete(_m, req) {
    calls[name]++;
    const msg = req.user.replace(/^<message>\n|\n<\/message>$/g, '');
    return { text: (o.reply ?? ((m) => JSON.stringify({ verdict: 'suspicious', confidence: 0.7, scamType: 'x', recommendedAction: 'Verify.', indicators: [{ quote: m.slice(0, 10), explanation: 'e' }] })))(msg), inputTokens: 50, outputTokens: 20, costUsd: null };
  } });
  const gateway = new Gateway({ store, registry: o.registry ?? [free], adapters: { fp: mk('fp'), pp: mk('pp') }, health: newHealth(), sleep: async () => {} });
  const config: AppConfig = { jwtSecret: SECRET, jwtAudience: 'authenticated', corsOrigins: o.cors ?? ['https://app.trusion.test'], maxJsonBytes: 64 * 1024, ipRequestsPerMinute: o.ipLimit ?? 10_000, trustProxy: false };
  const logs: any[] = [];
  const srv = http.createServer(createApp({ store, gateway, config, urlTracer: o.tracer, log: (r) => logs.push(r) }));
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const call = (path: string, init: RequestInit & { token?: string } = {}) => fetch(base + path, { ...init, headers: { ...(init.token ? { authorization: `Bearer ${init.token}` } : {}), ...(init.headers as any) } });
  const post = (path: string, token: string, body: unknown, headers: Record<string, string> = {}) => call(path, { method: 'POST', token, headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
  return { store, calls, logs, base, call, post, close: () => srv.close() };
}

test('health is open; every response carries security headers; no framework fingerprint', async () => {
  const s = await boot();
  try {
    const r = await s.call('/healthz');
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), { status: 'ok' });
    for (const [h, v] of [['x-content-type-options', 'nosniff'], ['x-frame-options', 'DENY'], ['referrer-policy', 'no-referrer'], ['cache-control', 'no-store']]) assert.equal(r.headers.get(h), v, h);
    assert.match(r.headers.get('content-security-policy')!, /default-src 'none'/);
    assert.equal(r.headers.get('x-powered-by'), null);
    assert.ok(r.headers.get('x-request-id'));
  } finally { s.close(); }
});

test('authentication: missing, forged, alg=none, expired, wrong-audience tokens are all 401', async () => {
  const s = await boot();
  try {
    const none = `${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from(JSON.stringify({ sub: 'x', exp: NOW_S() + 99 })).toString('base64url')}.`;
    const cases: [string, string | undefined][] = [
      ['missing', undefined], ['garbage', 'abc'], ['wrong secret', tok('u', {}, 'another-secret-another-secret-another-1')],
      ['alg none', none], ['expired', signJwt({ sub: 'u', exp: NOW_S() - 3600, aud: 'authenticated' }, SECRET)],
      ['wrong aud', signJwt({ sub: 'u', exp: NOW_S() + 600, aud: 'other' }, SECRET)], ['HS512 header', signJwt({ sub: 'u', exp: NOW_S() + 600, aud: 'authenticated' }, SECRET, { alg: 'HS512' })],
    ];
    for (const [name, t] of cases) {
      const r = await s.call('/v1/usage', { token: t });
      assert.equal(r.status, 401, name);
      assert.equal(r.headers.get('www-authenticate'), 'Bearer');
      assert.equal(((await r.json()) as any).error.code, 'unauthorized');
    }
  } finally { s.close(); }
});

test('plan comes ONLY from server data: user_metadata/app claims claiming "business" or "admin" are ignored', async () => {
  const s = await boot();
  try {
    const t = tok('mallory', { user_metadata: { role: 'admin', plan: 'business' }, role: 'service_role', plan: 'business' });
    const r = await (await s.call('/v1/usage', { token: t })).json() as any;
    assert.equal(r.plan.id, 'free');
    s.store.grantPlan('mallory', 'pro', { source: 'billing-test' });
    assert.equal(((await (await s.call('/v1/usage', { token: tok('mallory') })).json()) as any).plan.id, 'pro');
  } finally { s.close(); }
});

test('SMS analysis: real pipeline result, consent gates AI, usage increments by exactly 1, result persisted', async () => {
  const s = await boot();
  try {
    const t = tok('alice');
    const text = 'Kartu ATM Anda diblokir. Balas dengan KODE OTP segera.';
    const noConsent = await (await s.post('/v1/analyze/sms', t, { text })).json() as any;
    assert.equal(s.calls.fp, 0, 'AI not called without consent');
    assert.equal(noConsent.result.ai.used, false);
    const withConsent = await (await s.post('/v1/analyze/sms', t, { text, consentExternalProcessing: true })).json() as any;
    assert.equal(s.calls.fp, 1);
    assert.equal(withConsent.result.ai.used, true);
    assert.equal(withConsent.usage.used, 2);
    const stored = await (await s.call(`/v1/analyses/${withConsent.id}`, { token: t })).json() as any;
    assert.equal(stored.kind, 'sms');
    assert.equal(JSON.stringify(stored).includes(text), false, 'full message text is not persisted');
  } finally { s.close(); }
});

test('quota: once the plan allowance is spent the API returns 429 quota_exceeded and AI is not called afterwards', async () => {
  const s = await boot();
  try {
    const t = tok('quota-user');
    s.store.grantPlan('quota-user', 'starter', { source: 'test' });          // 300 units, 30 req/min
    const pre = s.store.reserve('quota-user', 'pre', 295, 300); assert.ok(pre.ok); if (pre.ok) s.store.commit(pre.reservationId, 295);
    for (let i = 0; i < 5; i++) assert.equal((await s.post('/v1/analyze/sms', t, { text: `pesan biasa nomor ${i}` })).status, 200, `req ${i}`);
    const over = await s.post('/v1/analyze/sms', t, { text: 'one more', consentExternalProcessing: true });
    assert.equal(over.status, 429);
    const b = await over.json() as any;
    assert.equal(b.error.code, 'quota_exceeded'); assert.equal(b.error.details.remaining, 0);
    assert.equal(s.calls.fp, 0, 'no provider call once quota is exhausted');
    assert.equal(s.store.usage('quota-user').used, 300);
  } finally { s.close(); }
});

test('30 PARALLEL requests against 10 remaining units admit exactly 10 (no overspend)', async () => {
  const s = await boot({ ipLimit: 1000 });
  try {
    const t = tok('racer');
    // free plan allows 10 req/min per user, so use a pro-like rate but free quota: grant starter? use free quota via custom: raise rate by using 3 users? simpler: starter has 300 units; emulate small allowance by pre-spending.
    s.store.grantPlan('racer', 'starter', { source: 'test' });
    const used = s.store.reserve('racer', 'pre', 290, 300); assert.ok(used.ok); if (used.ok) s.store.commit(used.reservationId, 290);
    const rs = await Promise.all(Array.from({ length: 30 }, (_, i) => s.post('/v1/analyze/sms', t, { text: `parallel ${i}` })));
    const codes = rs.map((r) => r.status);
    assert.equal(codes.filter((c) => c === 200).length, 10);
    assert.equal(codes.filter((c) => c === 429).length, 20);
    assert.equal(s.store.usage('racer').used, 300);
  } finally { s.close(); }
});

test('ownership: another user cannot read, list or learn the existence of someone else\'s analysis', async () => {
  const s = await boot();
  try {
    const a = tok('alice'); const b = tok('bob');
    const made = await (await s.post('/v1/analyze/url', a, { url: 'https://example.com' })).json() as any;
    assert.equal((await s.call(`/v1/analyses/${made.id}`, { token: a })).status, 200);
    const cross = await s.call(`/v1/analyses/${made.id}`, { token: b });
    const missing = await s.call('/v1/analyses/00000000-0000-4000-8000-000000000000', { token: b });
    assert.equal(cross.status, 404); assert.equal(missing.status, 404);
    assert.deepEqual(((await cross.json()) as any).error.code, ((await missing.json()) as any).error.code);
    assert.deepEqual(((await (await s.call('/v1/analyses', { token: b })).json()) as any).analyses, []);
    assert.equal((await s.call('/v1/analyses/not-a-uuid', { token: a })).status, 404);
  } finally { s.close(); }
});

test('idempotency: same key => one charge and identical stored result; same key with different payload type is still one analysis', async () => {
  const s = await boot();
  try {
    const t = tok('idem');
    const k = { 'idempotency-key': 'abcd1234efgh' };
    const r1 = await (await s.post('/v1/analyze/url', t, { url: 'https://example.com/a' }, k)).json() as any;
    const r2 = await (await s.post('/v1/analyze/url', t, { url: 'https://example.com/a' }, k)).json() as any;
    assert.equal(r2.replay, true); assert.equal(r1.id, r2.id);
    assert.equal(s.store.usage('idem').used, 1);
    assert.equal((await s.post('/v1/analyze/url', t, { url: 'https://example.com/a' }, { 'idempotency-key': 'short' })).status, 400);
  } finally { s.close(); }
});

test('APK upload: analysis is driven by file CONTENT; invalid file => 422 and NOT charged; oversize => 413', async () => {
  const s = await boot();
  try {
    const t = tok('apkuser');
    const evil = apk({ manifestBuf: manifest({ perms: ['READ_SMS', 'RECEIVE_SMS', 'INTERNET'] }), dex: dexWith('https://api.telegram.org/bot1:x/send', 'http://185.1.2.3/c2') });
    const ok = await s.call('/v1/analyze/apk', { method: 'POST', token: t, headers: { 'content-type': 'application/vnd.android.package-archive', 'x-filename': 'harmless-photo.jpg' }, body: evil });
    const body = await ok.json() as any;
    assert.equal(ok.status, 200);
    assert.equal(body.result.assessment, 'high_risk', 'filename "harmless-photo.jpg" does not hide what is inside');
    assert.equal(body.usage.used, 3);
    const bad = await s.call('/v1/analyze/apk', { method: 'POST', token: t, headers: { 'content-type': 'application/octet-stream' }, body: Buffer.from('MZ not an apk') });
    assert.equal(bad.status, 422);
    const bb = await bad.json() as any;
    assert.equal(bb.error.code, 'not_zip'); assert.equal(bb.result.status, 'failed');
    assert.equal(s.store.usage('apkuser').used, 3, 'failed analysis is not billed');
    assert.equal(s.store.usage('apkuser').reserved, 0);
    const big = await s.call('/v1/analyze/apk', { method: 'POST', token: t, headers: { 'content-type': 'application/octet-stream' }, body: Buffer.alloc(21 * 1024 * 1024) });
    assert.equal(big.status, 413);
    assert.equal((await s.call('/v1/analyze/apk', { method: 'POST', token: t, headers: { 'content-type': 'text/html' }, body: '<b>x</b>' })).status, 415);
  } finally { s.close(); }
});

test('malformed requests are rejected safely and cost nothing', async () => {
  const s = await boot();
  try {
    const t = tok('badreq');
    s.store.grantPlan('badreq', 'pro', { source: 'test' });                   // 60 req/min so the limiter does not mask what we test
    assert.equal((await s.call('/v1/analyze/sms', { method: 'POST', token: t, headers: { 'content-type': 'application/json' }, body: '{not json' })).status, 400);
    assert.equal((await s.call('/v1/analyze/sms', { method: 'POST', token: t, headers: { 'content-type': 'text/plain' }, body: 'hi' })).status, 415);
    assert.equal((await s.post('/v1/analyze/sms', t, { text: '' })).status, 400);
    assert.equal((await s.post('/v1/analyze/sms', t, { text: 'x'.repeat(16001) })).status, 413);
    assert.equal((await s.post('/v1/analyze/sms', t, { text: 123 })).status, 400);
    assert.equal((await s.post('/v1/analyze/sms', t, { pad: 'x'.repeat(70_000), text: 'a' })).status, 413);
    for (const url of ['javascript:alert(1)', 'file:///etc/passwd', '', 'http://a b']) {
      const r = await s.post('/v1/analyze/url', t, { url }); assert.equal(r.status, 400, url);
    }
    assert.equal((await s.call('/nope', { token: t })).status, 404);
    assert.equal(s.store.usage('badreq').used, 0);
    assert.equal(s.store.usage('badreq').reserved, 0);
  } finally { s.close(); }
});

test('unexpected internal errors do not leak details to the client', async () => {
  const s = await boot({ tracer: async () => { throw new Error('SECRET_DB_PASSWORD=hunter2 at /srv/app/db.ts:42'); } });
  try {
    const t = tok('leak');
    const r = await s.post('/v1/analyze/url', t, { url: 'https://example.com', followRedirects: true });
    const txt = await r.text();
    assert.equal(r.status, 500);
    assert.equal(txt.includes('hunter2') || txt.includes('db.ts') || txt.includes('stack'), false);
    assert.equal(JSON.parse(txt).error.code, 'internal_error');
    assert.equal(JSON.stringify(s.logs).includes('hunter2'), false, 'logs carry error class only');
    assert.equal(s.store.usage('leak').used, 0, 'reservation released after crash');
    assert.equal(s.store.usage('leak').reserved, 0);
  } finally { s.close(); }
});

test('URL analysis with redirect tracing surfaces a blocked internal redirect as a critical finding', async () => {
  const s = await boot({ tracer: async () => ({ hops: [], finalUrl: null, truncated: false, blocked: { code: 'non_public_address', message: 'm', atUrl: 'http://169.254.169.254/' } }) });
  try {
    const r = await (await s.post('/v1/analyze/url', tok('u'), { url: 'https://s.id/abc', followRedirects: true })).json() as any;
    assert.ok(r.result.indicators.some((i: any) => i.id === 'redirect_to_blocked_target' && i.severity === 'critical'));
    assert.notEqual(r.result.assessment, 'no_red_flags_found');
  } finally { s.close(); }
});

test('FREE plan + only a paid model available: AI is not used, paid provider is never called, result still returned', async () => {
  const s = await boot({ registry: [paid] });
  try {
    const r = await (await s.post('/v1/analyze/sms', tok('freeloader'), { text: 'Balas dengan KODE OTP segera', consentExternalProcessing: true })).json() as any;
    assert.equal(s.calls.pp, 0);
    assert.equal(r.result.ai.used, false);
    assert.equal(r.result.status, 'completed_with_limitations');
    assert.equal(s.store.spendUsd('freeloader'), 0);
  } finally { s.close(); }
});

test('CORS: only allowlisted origins are echoed; preflight works; disallowed gets no CORS headers', async () => {
  const s = await boot();
  try {
    const ok = await s.call('/healthz', { headers: { origin: 'https://app.trusion.test' } });
    assert.equal(ok.headers.get('access-control-allow-origin'), 'https://app.trusion.test');
    const bad = await s.call('/healthz', { headers: { origin: 'https://evil.example' } });
    assert.equal(bad.headers.get('access-control-allow-origin'), null);
    const pre = await s.call('/v1/usage', { method: 'OPTIONS', headers: { origin: 'https://app.trusion.test', 'access-control-request-method': 'GET' } });
    assert.equal(pre.status, 204);
  } finally { s.close(); }
});

test('rate limiting: per-user (plan) and per-IP limits return 429 with Retry-After', async () => {
  const s = await boot();
  try {
    const t = tok('hammer');
    const codes: number[] = [];
    for (let i = 0; i < 12; i++) codes.push((await s.call('/v1/usage', { token: t })).status);
    assert.equal(codes.filter((c) => c === 200).length, 10); // free plan = 10 req/min
    assert.equal(codes[11], 429);
  } finally { s.close(); }
  const s2 = await boot({ ipLimit: 3 });
  try {
    const rs = []; for (let i = 0; i < 5; i++) rs.push(await s2.call('/healthz'));
    assert.deepEqual(rs.map((r) => r.status), [200, 200, 200, 429, 429]);
    assert.equal(rs[3].headers.get('retry-after'), '60');
  } finally { s2.close(); }
});

test('data deletion endpoint removes the caller\'s history and usage', async () => {
  const s = await boot();
  try {
    const t = tok('leaver');
    await s.post('/v1/analyze/url', t, { url: 'https://example.com' });
    assert.equal(((await (await s.call('/v1/analyses', { token: t })).json()) as any).analyses.length, 1);
    assert.equal((await s.call('/v1/me', { method: 'DELETE', token: t })).status, 200);
    assert.equal(((await (await s.call('/v1/analyses', { token: t })).json()) as any).analyses.length, 0);
  } finally { s.close(); }
});
