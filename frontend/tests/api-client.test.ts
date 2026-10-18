import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { createApiClient, newIdempotencyKey } from '../src/api/client.ts';
import { ApiError, describeError } from '../src/api/errors.ts';
import { parseIndicator, parseEnvelope, toViewModel } from '../src/api/schemas.ts';
import { bootBackend, token } from './helpers/backend.ts';
import { apk, manifest, dexWith } from '../../backend/tests/helpers/apk-fixture.ts';

const fx = (n: string) => readFileSync(new URL(`../../backend/tests/fixtures/${n}`, import.meta.url));
const mk = (url: string, tok: string | null, extra: Record<string, unknown> = {}) => {
  let unauthorized = 0;
  const c = createApiClient({ baseUrl: url, getToken: () => tok, onUnauthorized: () => { unauthorized++; }, ...extra });
  return { c, unauthorized: () => unauthorized };
};
const blob = (b: Buffer) => new Blob([new Uint8Array(b)]);

test('REAL BACKEND contract: me/usage/capabilities/history parse and match server truth', async () => {
  const b = await bootBackend();
  try {
    const { c } = mk(b.url, token('alice'));
    assert.equal((await c.me()).isAdmin, false);
    const u = await c.usage(); assert.equal(u.plan.id, 'free'); assert.equal(u.usage.limit, 20);
    const caps = await c.capabilities(); assert.equal(caps.features.screenshot.state, 'available'); assert.equal(caps.features.ai_interpretation.state, 'unavailable');
    assert.deepEqual(await c.history(), []);
  } finally { await b.close(); }
});

test('REAL BACKEND: sms/url/apk/screenshot envelopes validate; idempotent replay returns same id, charges once; history/detail round-trip', async () => {
  const b = await bootBackend();
  try {
    const { c } = mk(b.url, token('alice'));
    const k = newIdempotencyKey();
    const sms = await c.analyzeSms({ text: 'Balas dengan KODE OTP segera', consentExternalProcessing: false, idempotencyKey: k });
    assert.equal(sms.kind, 'sms'); assert.ok(sms.vm.indicators.some((i) => i.id === 'credential_request')); assert.equal(sms.usage?.used, 1);
    const again = await c.analyzeSms({ text: 'Balas dengan KODE OTP segera', consentExternalProcessing: false, idempotencyKey: k });
    assert.equal(again.replay, true); assert.equal(again.id, sms.id); assert.equal(b.store.usage('alice').used, 1);
    const url = await c.analyzeUrl({ url: 'http://bca-verifikasi-akun.xyz/Cek.apk', followRedirects: false, idempotencyKey: newIdempotencyKey() });
    assert.equal(url.vm.assessment, 'high_risk'); assert.equal(url.vm.normalizedUrl?.host, 'bca-verifikasi-akun.xyz');
    const a = await c.analyzeApk({ file: blob(apk({ manifestBuf: manifest({ perms: ['READ_SMS', 'RECEIVE_SMS', 'INTERNET'] }), dex: dexWith('http://185.1.2.3/c2') })), idempotencyKey: newIdempotencyKey() });
    assert.equal(a.vm.assessment, 'suspicious'); assert.ok(a.vm.indicators.some((i) => i.id === 'sms_interception_capability')); assert.ok(a.vm.apk!.permissions.some((p) => p.name === 'READ_SMS'));
    const s = await c.analyzeScreenshot({ file: blob(fx('scam.png')), contentType: 'image/png', consentExternalProcessing: false, idempotencyKey: newIdempotencyKey() });
    assert.match(s.vm.ocr!.textPreview, /OTP/); assert.equal(s.vm.image!.type, 'png');
    const h = await c.history(); assert.equal(h.length, 4);
    const d = await c.analysis(sms.id); assert.equal(d.vm.kind, 'sms'); assert.equal(d.id, sms.id);
    await assert.rejects(mk(b.url, token('bob')).c.analysis(sms.id), (e: any) => e.kind === 'not_found');
  } finally { await b.close(); }
});

test('auth: without a token NO request is made; expired/forged token => 401 => onUnauthorized once', async () => {
  const b = await bootBackend();
  try {
    const n0 = b.hits.length;
    const none = mk(b.url, null);
    await assert.rejects(none.c.usage(), (e: any) => e.kind === 'unauthenticated');
    assert.equal(b.hits.length, n0, 'no request left the client'); assert.equal(none.unauthorized(), 1);
    const expired = mk(b.url, token('alice', -100));
    await assert.rejects(expired.c.usage(), (e: any) => e.kind === 'unauthenticated'); assert.equal(expired.unauthorized(), 1);
    const forged = mk(b.url, 'aaa.bbb.ccc');
    await assert.rejects(forged.c.me(), (e: any) => e.kind === 'unauthenticated');
    const nonAdmin = mk(b.url, token('mallory', 3600, { role: 'admin', user_metadata: { role: 'admin' } }));
    await assert.rejects(nonAdmin.c.adminOverview(), (e: any) => e.kind === 'forbidden');
  } finally { await b.close(); }
});

test('error mapping against the real backend: 429 quota, 413, 422 (+not billed), 503 OCR unavailable, 400 invalid url', async () => {
  const b = await bootBackend({ ocr: null });
  try {
    const { c } = mk(b.url, token('q'));
    b.store.grantPlan('q', 'starter', { source: 't' }); const pre = b.store.reserve('q', 'pre', 299, 300); if (pre.ok) b.store.commit(pre.reservationId, 299);
    await c.analyzeSms({ text: 'halo', consentExternalProcessing: false, idempotencyKey: newIdempotencyKey() });
    await assert.rejects(c.analyzeSms({ text: 'halo lagi', consentExternalProcessing: false, idempotencyKey: newIdempotencyKey() }), (e: any) => e.kind === 'quota' && /not charged/.test(describeError(e).detail));
    const f = mk(b.url, token('f')).c;
    await assert.rejects(f.analyzeApk({ file: blob(Buffer.from('MZ nope')), idempotencyKey: newIdempotencyKey() }), (e: any) => e.kind === 'unprocessable' && e.code === 'not_zip');
    await assert.rejects(f.analyzeApk({ file: blob(Buffer.alloc(21 * 1024 * 1024)), idempotencyKey: newIdempotencyKey() }), (e: any) => e.kind === 'too_large');
    await assert.rejects(f.analyzeScreenshot({ file: blob(fx('scam.png')), contentType: 'image/png', consentExternalProcessing: false, idempotencyKey: newIdempotencyKey() }), (e: any) => e.kind === 'unavailable');
    await assert.rejects(f.analyzeUrl({ url: 'javascript:alert(1)', followRedirects: false, idempotencyKey: newIdempotencyKey() }), (e: any) => e.kind === 'bad_request');
    assert.equal(b.store.usage('f').used, 0);
  } finally { await b.close(); }
});

test('network failure, timeout, and NO automatic retry of a POST (server sees exactly one hit)', async () => {
  const dead = mk('http://127.0.0.1:1', token('x'));
  await assert.rejects(dead.c.usage(), (e: any) => e.kind === 'network');
  let hits = 0;
  const srv = http.createServer(() => { hits++; /* never answer */ });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const { c } = mk(`http://127.0.0.1:${(srv.address() as AddressInfo).port}`, token('x'), { timeoutMs: 150 });
    await assert.rejects(c.analyzeSms({ text: 'hi', consentExternalProcessing: false, idempotencyKey: 'k'.repeat(16) }), (e: any) => e.kind === 'timeout');
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(hits, 1);
  } finally { srv.closeAllConnections?.(); srv.close(); }
});

test('malformed server responses are rejected as invalid_response (nothing is rendered or fabricated)', async () => {
  const bodies = ['<html>oops</html>', '{"id":1,"kind":"sms","status":"completed","result":{}}', JSON.stringify({ id: 'x', kind: 'sms', status: 'completed', result: { assessment: 'high_risk', heuristic: { score: 1, indicators: [{ id: 'a', severity: 'EXTREME', source: 'heuristic', description: 'd' }] }, urls: [], ai: { used: false }, limitations: [] } }), JSON.stringify({ id: 'x', kind: 'sms', status: 'SAFE', result: {} })];
  let i = 0;
  const srv = http.createServer((_q, r) => { r.setHeader('content-type', 'application/json'); r.end(bodies[i++ % bodies.length]); });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const { c } = mk(`http://127.0.0.1:${(srv.address() as AddressInfo).port}`, token('x'));
    for (let n = 0; n < bodies.length; n++) await assert.rejects(c.analyzeSms({ text: 'hi', consentExternalProcessing: false, idempotencyKey: newIdempotencyKey() }), (e: any) => e instanceof ApiError && e.kind === 'invalid_response', `body ${n}`);
  } finally { srv.close(); }
});

test('schema validators reject wrong types instead of coercing', () => {
  assert.throws(() => parseIndicator({ id: 1, severity: 'low', source: 'heuristic', description: 'd' }));
  assert.throws(() => parseIndicator({ id: 'a', severity: 'low', source: 'oracle', description: 'd' }));
  assert.throws(() => parseEnvelope({ id: 'a', kind: 'sms', status: 'completed', result: 'str' }));
  assert.throws(() => toViewModel('url', 'completed', { assessment: 5, indicators: [], normalized: {} }));
  assert.equal(parseIndicator({ id: 'a', severity: 'low', source: 'heuristic', description: 'd' }).evidence, undefined);
});

test('generated idempotency keys satisfy the backend format and are unique', () => {
  const a = newIdempotencyKey(), b = newIdempotencyKey();
  assert.match(a, /^[A-Za-z0-9_-]{8,64}$/); assert.notEqual(a, b);
});
