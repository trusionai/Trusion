import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createApp } from '../src/http/app.ts';
import type { AppConfig } from '../src/http/app.ts';
import { Store } from '../src/modules/usage/store.ts';
import { Gateway } from '../src/modules/ai-gateway/gateway.ts';
import { newHealth } from '../src/modules/ai-gateway/router.ts';
import { signJwt } from '../src/modules/auth/jwt.ts';
import { jwksVerifier } from '../src/modules/auth/verifier.ts';
import { tesseractEngine } from '../src/modules/file-analysis/ocr.ts';
import type { OcrEngine } from '../src/modules/file-analysis/ocr.ts';
import type { ModelSpec, ProviderAdapter } from '../src/modules/ai-gateway/types.ts';

const SECRET = 'test-secret-test-secret-test-secret-123456';
const fx = (n: string) => readFileSync(new URL(`./fixtures/${n}`, import.meta.url));
const nowS = () => Math.floor(Date.now() / 1000);
const tok = (sub: string, extra: Record<string, unknown> = {}) => signJwt({ sub, exp: nowS() + 600, aud: 'authenticated', ...extra }, SECRET);
const model: ModelSpec = { id: 'f1', provider: 'fp', tier: 'free', capabilities: ['text', 'json'], maxContextTokens: 16000, maxOutputTokens: 2000, priceInPerM: 0, priceOutPerM: 0, priceVerifiedAt: null, dataPolicy: 'external_logged', qualityRank: 1, enabled: true };

async function boot(o: { ocr?: OcrEngine | null; admins?: string[]; registry?: ModelSpec[]; config?: Partial<AppConfig>; reply?: (m: string) => string } = {}) {
  const store = new Store();
  let aiCalls = 0;
  const adapter: ProviderAdapter = { name: 'fp', async complete(_m, req) { aiCalls++; const msg = req.user.replace(/^<message>\n|\n<\/message>$/g, ''); return { text: (o.reply ?? (() => JSON.stringify({ verdict: 'unclear', confidence: 0.4, scamType: 'x', recommendedAction: 'Verify.', indicators: [] })))(msg), inputTokens: 5, outputTokens: 5, costUsd: null }; } };
  const gateway = new Gateway({ store, registry: o.registry ?? [], adapters: { fp: adapter }, health: newHealth(), sleep: async () => {} });
  const base: AppConfig = { jwtSecret: SECRET, jwtAudience: 'authenticated', corsOrigins: [], maxJsonBytes: 65536, ipRequestsPerMinute: 100000, trustProxy: false, adminUserIds: o.admins, ...o.config };
  const ocr = o.ocr === undefined ? tesseractEngine() : o.ocr ?? undefined;
  const srv = http.createServer(createApp({ store, gateway, config: base, ocr, log: () => {} }));
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const call = (path: string, init: RequestInit & { token?: string } = {}) => fetch(url + path, { ...init, headers: { ...(init.token ? { authorization: `Bearer ${init.token}` } : {}), ...(init.headers as any) } });
  const shot = (token: string, body: Buffer | string, headers: Record<string, string> = { 'content-type': 'image/png' }) => call('/v1/analyze/screenshot', { method: 'POST', token, headers, body });
  return { store, call, shot, aiCalls: () => aiCalls, close: () => srv.close() };
}
const pro = (s: { store: Store }, id: string) => s.store.grantPlan(id, 'pro', { source: 'test' });

test('capabilities is public, honest about OCR/AI availability, and leaks no provider names or secrets', async () => {
  const s = await boot({ registry: [model] });
  try {
    const c = await (await s.call('/v1/capabilities')).json() as any;
    assert.equal(c.features.screenshot.state, 'available');
    assert.equal(c.features.ai_interpretation.state, 'available');     // registry has an enabled model AND an adapter
    assert.equal(JSON.stringify(c).includes('fp'), false);
  } finally { s.close(); }
  const s2 = await boot({ ocr: null });
  try {
    const c = await (await s2.call('/v1/capabilities')).json() as any;
    assert.equal(c.features.screenshot.state, 'unavailable');
    assert.equal(c.features.ai_interpretation.state, 'unavailable');
  } finally { s2.close(); }
});

test('screenshot with NO OCR engine: 503 ocr_unavailable, nothing simulated, quota untouched', async () => {
  const s = await boot({ ocr: null });
  try {
    const r = await s.shot(tok('u'), fx('scam.png'));
    assert.equal(r.status, 503);
    assert.equal(((await r.json()) as any).error.code, 'ocr_unavailable');
    assert.equal(s.store.usage('u').used + s.store.usage('u').reserved, 0);
  } finally { s.close(); }
});

test('REAL OCR: result is derived from the pixels — scam screenshot is flagged with extracted evidence, 2 units charged', async () => {
  const s = await boot();
  try {
    const r = await s.shot(tok('ocr1'), fx('scam.png'));
    const b = await r.json() as any;
    assert.equal(r.status, 200);
    assert.match(b.result.ocr.textPreview, /OTP/);
    assert.match(b.result.ocr.textPreview, /bca-verifikasi-akun\.xyz/i);
    assert.equal(b.result.source, 'screenshot_ocr');
    assert.ok(['high_risk', 'suspicious'].includes(b.result.assessment), b.result.assessment);
    assert.ok(b.result.heuristic.indicators.some((i: any) => i.id === 'credential_request'));
    assert.ok(b.result.urls[0].assessment === 'high_risk');
    assert.equal(b.status, 'completed_with_limitations');            // OCR-derived results are never "completed"
    assert.ok(b.result.limitations.some((l: string) => /OCR/.test(l)));
    assert.equal(b.usage.used, 2);
    assert.equal(b.result.image.type, 'png'); assert.equal(b.result.image.width, 1100);
  } finally { s.close(); }
});

test('REAL OCR: JPEG works; benign screenshot gets NO scam findings and is never called "safe"', async () => {
  const s = await boot();
  try {
    const j = await (await s.shot(tok('ocr2'), fx('scam.jpg'), { 'content-type': 'image/jpeg' })).json() as any;
    assert.ok(j.result.heuristic.indicators.some((i: any) => i.id === 'apk_install_lure'));
    const b = await (await s.shot(tok('ocr2'), fx('benign.png'))).json() as any;
    assert.deepEqual(b.result.heuristic.indicators, []);
    assert.equal(b.status, 'inconclusive');
    assert.equal(JSON.stringify(b).includes('"safe"'), false);
  } finally { s.close(); }
});

test('FILENAME IS IRRELEVANT: a blank image named like a scam yields no_text_found/inconclusive with zero indicators', async () => {
  const s = await boot();
  try {
    const r = await (await s.shot(tok('ocr3'), fx('blank.png'), { 'content-type': 'image/png', 'x-filename': 'BCA-OTP-diblokir-scam.png' })).json() as any;
    assert.equal(r.status, 'inconclusive'); assert.equal(r.result.assessment, 'no_text_found');
    assert.deepEqual(r.result.heuristic.indicators, []);
    assert.equal(r.result.ocr.textLength, 0);
  } finally { s.close(); }
});

test('screenshot + consent: AI sees OCR text only; its quotes are verified against the OCR text', async () => {
  const s = await boot({ registry: [model], reply: () => JSON.stringify({ verdict: 'likely_scam', confidence: 0.9, scamType: 'otp phishing', recommendedAction: 'Do not reply.', indicators: [{ quote: 'KODE OTP', explanation: 'asks for OTP' }] }) });
  try {
    const none = await (await s.shot(tok('c1'), fx('scam.png'))).json() as any;
    assert.equal(none.result.ai.used, false); assert.equal(s.aiCalls(), 0, 'no consent => no external call');
    const yes = await (await s.shot(tok('c1'), fx('scam.png'), { 'content-type': 'image/png', 'x-consent-external-processing': 'true' })).json() as any;
    assert.equal(yes.result.ai.used, true); assert.equal(s.aiCalls(), 1);
  } finally { s.close(); }
});

test('hostile images: wrong type, GIF, dimension bomb (never reaches OCR), truncated PNG, empty, oversize', async () => {
  let ocrCalls = 0; const real = tesseractEngine();
  const spy: OcrEngine = { name: 'tesseract', probe: () => real.probe(), recognize: (b) => { ocrCalls++; return real.recognize(b); } };
  const s = await boot({ ocr: spy });
  try {
    const t = tok('hostile');
    assert.equal((await s.shot(t, 'x', { 'content-type': 'text/html' })).status, 415);
    assert.equal((await s.shot(t, Buffer.alloc(0))).status, 400);
    const gif = Buffer.concat([Buffer.from('GIF89a'), Buffer.alloc(100)]);
    const g = await s.shot(t, gif); assert.equal(g.status, 422); assert.equal(((await g.json()) as any).error.code, 'unsupported_image_type');
    const bomb = Buffer.from(fx('scam.png').subarray(0, 64)); bomb.writeUInt32BE(100000, 16); bomb.writeUInt32BE(100000, 20);
    const bm = await s.shot(t, bomb); assert.equal(bm.status, 422); assert.equal(((await bm.json()) as any).error.code, 'image_too_large_dimensions');
    assert.equal(ocrCalls, 0, 'dimension bomb rejected from the header; decoder never ran');
    const trunc = await s.shot(t, fx('scam.png').subarray(0, 200));
    assert.equal(trunc.status, 502); assert.equal(((await trunc.json()) as any).error.code, 'ocr_failed');
    const big = await s.shot(t, Buffer.concat([fx('scam.png'), Buffer.alloc(6 * 1024 * 1024)]));
    assert.equal(big.status, 413);
    assert.equal(s.store.usage('hostile').used, 0, 'rejected/failed work is never billed');
    assert.equal(s.store.usage('hostile').reserved, 0);
  } finally { s.close(); }
});

test('ADMIN: ordinary users get 403 even with admin-looking claims; unauthenticated 401; allowlisted admin 200; no secrets in payload', async () => {
  const s = await boot({ admins: ['root-admin'], registry: [model] });
  try {
    assert.equal((await s.call('/v1/admin/overview')).status, 401);
    for (const t of [tok('mallory'), tok('mallory', { role: 'admin', is_admin: true, app_metadata: { role: 'admin' }, user_metadata: { role: 'admin', plan: 'business' } })]) {
      assert.equal((await s.call('/v1/admin/overview', { token: t })).status, 403);
      assert.equal(((await (await s.call('/v1/me', { token: t })).json()) as any).isAdmin, false);
    }
    const ok = await s.call('/v1/admin/overview', { token: tok('root-admin') });
    assert.equal(ok.status, 200);
    const body = await ok.json() as any; assert.equal(body.models[0].adapterConfigured, true);
    assert.equal(/key|secret|token/i.test(JSON.stringify(body)), false);
    assert.equal(((await (await s.call('/v1/me', { token: tok('root-admin') })).json()) as any).isAdmin, true);
    assert.equal((await s.call('/v1/admin/nope', { token: tok('root-admin') })).status, 404);
  } finally { s.close(); }
});

test('JWKS mode end-to-end over HTTP: ES256 accepted; forged HS256-with-public-key, wrong issuer, expired and tampered-plan tokens rejected', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = { ...(publicKey.export({ format: 'jwk' }) as object), kid: 'k1', use: 'sig', alg: 'ES256' };
  const ISS = 'https://proj.example/auth/v1';
  const verifier = jwksVerifier({ jwksUrl: 'https://proj.example/jwks', issuer: ISS, audience: 'authenticated', fetchJwks: async () => ({ keys: [jwk] as never }) });
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const es = (c: object) => { const h = enc({ alg: 'ES256', kid: 'k1' }), p = enc(c); return `${h}.${p}.${sign('sha256', Buffer.from(`${h}.${p}`), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`; };
  const cl = (o: object = {}) => ({ sub: 'jw-user', iss: ISS, aud: 'authenticated', exp: nowS() + 300, ...o });
  const s = await boot({ config: { verifier } });
  try {
    const good = await (await s.call('/v1/usage', { token: es(cl({ user_metadata: { plan: 'business', role: 'admin' } })) })).json() as any;
    assert.equal(good.plan.id, 'free', 'tampered plan metadata ignored');
    assert.equal((await s.call('/v1/usage', { token: es(cl({ iss: 'https://evil.example' })) })).status, 401);
    assert.equal((await s.call('/v1/usage', { token: es(cl({ exp: nowS() - 999 })) })).status, 401);
    assert.equal((await s.call('/v1/usage', { token: tok('jw-user') })).status, 401, 'HS256 token not accepted in JWKS mode');
    assert.equal((await s.call('/v1/usage', { token: es(cl({ aud: 'x' })) })).status, 401);
  } finally { s.close(); }
});

test('screenshot quota: costs 2 units; exhaustion returns 429 and OCR is not run', async () => {
  let ocrCalls = 0; const real = tesseractEngine();
  const spy: OcrEngine = { name: 'tesseract', probe: () => real.probe(), recognize: (b) => { ocrCalls++; return real.recognize(b); } };
  const s = await boot({ ocr: spy });
  try {
    pro(s, 'q'); const pre = s.store.reserve('q', 'pre', 1499, 1500); assert.ok(pre.ok); if (pre.ok) s.store.commit(pre.reservationId, 1499);
    const r = await s.shot(tok('q'), fx('scam.png'));
    assert.equal(r.status, 429); assert.equal(((await r.json()) as any).error.code, 'quota_exceeded');
    assert.equal(ocrCalls, 0);
  } finally { s.close(); }
});
