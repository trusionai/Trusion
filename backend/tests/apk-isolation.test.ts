import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApp } from '../src/http/app.ts';
import { Store } from '../src/modules/usage/store.ts';
import { Gateway } from '../src/modules/ai-gateway/gateway.ts';
import { newHealth } from '../src/modules/ai-gateway/router.ts';
import { signJwt } from '../src/modules/auth/jwt.ts';
import { analyzeApk } from '../src/modules/file-analysis/apk-analyzer.ts';
import { createApkPool } from '../src/modules/file-analysis/apk-pool.ts';
import type { ApkRunner } from '../src/modules/file-analysis/apk-pool.ts';
import { apk, manifest, dexWith } from './helpers/apk-fixture.ts';

const SECRET = 'iso-secret-iso-secret-iso-secret-1234567';
const tok = (sub: string) => signJwt({ sub, aud: 'authenticated', exp: Math.floor(Date.now() / 1000) + 600 }, SECRET);

/** Heavy but LEGITIMATE-looking: ~40 MB of URL-rich DEX text that compresses only a few-fold (so the bomb guard does not apply). */
function heavyApk(megabytes = 40): Buffer {
  let x = 123456789; const rnd = () => (x = (x * 1664525 + 1013904223) >>> 0);
  const words = Array.from({ length: 4096 }, (_, i) => 'w' + (i * 2654435761 >>> 0).toString(36));
  const parts: string[] = []; let size = 0;
  while (size < megabytes * 1e6) { const w = `http://${words[rnd() % 4096]}.example.com/${words[rnd() % 4096]}/${words[rnd() % 4096]}?q=${rnd()} `; parts.push(w); size += w.length; }
  return apk({ manifestBuf: manifest({ perms: ['INTERNET'] }), dex: Buffer.concat([Buffer.from('dex\n035\0'), Buffer.from(parts.join(''))]) });
}

async function boot(runner: ApkRunner, plan: 'free' | 'pro' = 'pro') {
  const store = new Store(); store.grantPlan('u', plan, { source: 't' });
  const gateway = new Gateway({ store, registry: [], adapters: {}, health: newHealth() });
  const srv = http.createServer(createApp({ store, gateway, apkRunner: runner, log: () => {}, config: { jwtSecret: SECRET, jwtAudience: 'authenticated', corsOrigins: [], maxJsonBytes: 65536, ipRequestsPerMinute: 1e6, trustProxy: false } }));
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const post = (b: Buffer) => fetch(url + '/v1/analyze/apk', { method: 'POST', headers: { authorization: `Bearer ${tok('u')}`, 'content-type': 'application/octet-stream' }, body: b });
  return { store, url, post, close: () => { srv.closeAllConnections?.(); srv.close(); } };
}
const gapMonitor = () => { let max = 0, last = Date.now(); const t = setInterval(() => { const n = Date.now(); max = Math.max(max, n - last); last = n; }, 5); return { stop: () => { clearInterval(t); return max; } }; };

test('BASELINE FACT: analysing a heavy legitimate APK on the main thread stalls the event loop (this is why the pool exists)', () => {
  const b = heavyApk();
  const t0 = Date.now(); analyzeApk(b); const ms = Date.now() - t0;
  assert.ok(ms > 150, `heavy fixture too cheap to demonstrate blocking (${ms} ms)`);
});

test('through the isolated pool the server stays responsive while a heavy APK is analysed', { timeout: 60000 }, async () => {
  const b = heavyApk(); const s = await boot(createApkPool());
  try {
    const t0 = Date.now(); analyzeApk(b); const direct = Date.now() - t0;              // what blocking would cost on the main thread
    const m = gapMonitor(); const t1 = Date.now();
    const res = await s.post(b); const wall = Date.now() - t1;
    const gap = m.stop();
    assert.equal(res.status, 200); assert.equal(((await res.json()) as any).status, 'completed_with_limitations');
    assert.ok(wall > direct * 0.5, 'analysis really ran for a comparable time');
    assert.ok(gap < Math.max(120, direct / 3), `event loop was blocked ${gap} ms (direct analysis would block ~${direct} ms)`);
  } finally { s.close(); }
});

test('hard timeout: analysis is cut off (504), the reservation is released (not billed), and the pool recovers', { timeout: 60000 }, async () => {
  const pool = createApkPool({ timeoutMs: 40 }); const s = await boot(pool);
  try {
    const r = await s.post(heavyApk(30)); assert.equal(r.status, 504); assert.equal(((await r.json()) as any).error.code, 'analysis_timeout');
    assert.deepEqual([s.store.usage('u').used, s.store.usage('u').reserved], [0, 0]);
    assert.deepEqual(pool.stats(), { running: 0, queued: 0 }, 'no leaked slot after a timeout');
    const fast = createApkPool({ timeoutMs: 10_000 }); const s2 = await boot(fast);
    try { assert.equal((await s2.post(apk())).status, 200); } finally { s2.close(); }
  } finally { s.close(); }
});

test('bounded concurrency: with 1 slot and no queue a second simultaneous job gets 503 busy + Retry-After and is not billed', { timeout: 60000 }, async () => {
  const pool = createApkPool({ maxConcurrent: 1, maxQueue: 0 }); const s = await boot(pool);
  try {
    const big = heavyApk(30);
    const first = s.post(big); await new Promise((r) => setTimeout(r, 150));
    const second = await s.post(apk());
    assert.equal(second.status, 503); assert.equal(second.headers.get('retry-after'), '5'); assert.equal(((await second.json()) as any).error.code, 'busy');
    assert.equal((await first).status, 200);
    assert.equal(s.store.usage('u').used, 3, 'only the job that ran was billed');
    assert.deepEqual(pool.stats(), { running: 0, queued: 0 });
  } finally { s.close(); }
});

test('queue: with 1 slot and a queue of 2, three simultaneous requests all complete in order without leaking slots', { timeout: 60000 }, async () => {
  const pool = createApkPool({ maxConcurrent: 1, maxQueue: 2 }); const s = await boot(pool);
  try {
    const rs = await Promise.all([s.post(apk()), s.post(apk()), s.post(apk())]);
    assert.deepEqual(rs.map((r) => r.status), [200, 200, 200]);
    assert.deepEqual(pool.stats(), { running: 0, queued: 0 });
  } finally { s.close(); }
});

test('memory cap: a job that needs more heap than allowed is stopped (422 file_too_complex), not billed, process survives', { timeout: 60000 }, async () => {
  const pool = createApkPool({ memoryMb: 8 }); const s = await boot(pool);
  try {
    const r = await s.post(heavyApk(30)); assert.equal(r.status, 422); assert.equal(((await r.json()) as any).error.code, 'file_too_complex');
    assert.deepEqual([s.store.usage('u').used, s.store.usage('u').reserved], [0, 0]);
    assert.equal((await fetch(s.url + '/healthz')).status, 200, 'server still healthy');
  } finally { s.close(); }
});

test('decompression bomb (175 KB on the wire) is answered in milliseconds with an honest INCONCLUSIVE, never a clean verdict', { timeout: 30000 }, async () => {
  const chunk = 'http://example.com/a/b/c?x=1&y=2 ';
  const bomb = apk({ manifestBuf: manifest({ perms: ['INTERNET'] }), dex: Buffer.concat([Buffer.from('dex\n035\0'), Buffer.from(chunk.repeat(Math.floor(60e6 / chunk.length)))]) });
  assert.ok(bomb.length < 400_000);
  const s = await boot(createApkPool());
  try {
    const t0 = Date.now(); const r = await s.post(bomb); const ms = Date.now() - t0; const b = await r.json() as any;
    assert.equal(r.status, 200); assert.equal(b.status, 'inconclusive'); assert.equal(b.result.assessment, null);
    assert.ok(b.result.limitations.some((l: string) => /NOT scanned.*compression ratio/.test(l)));
    assert.ok(b.result.indicators.some((i: any) => i.id === 'zip_extreme_compression'));
    assert.ok(ms < 1500, `took ${ms} ms`);
  } finally { s.close(); }
});

test('asset payload sniffing reads prefixes only: 200 large compressed assets are checked quickly and a hidden DEX is still found', () => {
  const extra = Array.from({ length: 150 }, (_, i) => ({ name: `assets/blob${i}.bin`, data: Buffer.alloc(4 * 1024 * 1024, i % 251) }));
  extra.push({ name: 'assets/payload.dat', data: Buffer.concat([dexWith('x'), Buffer.alloc(4096)]) });
  const b = apk({ extra }); const t0 = Date.now(); const r = analyzeApk(b); const ms = Date.now() - t0;
  assert.ok(r.embedded.payloadFiles.some((f) => f.startsWith('assets/payload.dat')));
  assert.ok(ms < 3000, `prefix sniffing took ${ms} ms`);
});
