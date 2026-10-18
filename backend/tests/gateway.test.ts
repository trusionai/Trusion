import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { Store } from '../src/modules/usage/store.ts';
import { Gateway } from '../src/modules/ai-gateway/gateway.ts';
import { newHealth } from '../src/modules/ai-gateway/router.ts';
import { parseRegistry } from '../src/modules/ai-gateway/registry.ts';
import { ProviderError } from '../src/modules/ai-gateway/types.ts';
import type { ModelSpec, ProviderAdapter, CompletionResult } from '../src/modules/ai-gateway/types.ts';
import { OpenAICompatAdapter } from '../src/modules/ai-gateway/providers/openai-compat.ts';
import { PLANS } from '../src/modules/entitlements/plans.ts';

const NOW = new Date('2026-10-16T10:00:00Z');
const model = (o: Partial<ModelSpec> & { id: string }): ModelSpec => ({
  provider: 'prov', tier: 'free', capabilities: ['text', 'json'], maxContextTokens: 32000, maxOutputTokens: 2000,
  priceInPerM: 0, priceOutPerM: 0, priceVerifiedAt: null, dataPolicy: 'external_logged', qualityRank: 1, enabled: true, ...o,
});
const OK = (text = '{"ok":true}', extra: Partial<CompletionResult> = {}): CompletionResult => ({ text, inputTokens: 100, outputTokens: 20, costUsd: null, ...extra });

type Step = CompletionResult | ProviderError;
function scripted(name: string, plan: Record<string, Step[]>): ProviderAdapter & { calls: string[] } {
  const calls: string[] = [];
  return { name, calls, async complete(m) {
    calls.push(m.id);
    const q = plan[m.id] ?? [OK()];
    const s = q.length > 1 ? q.shift()! : q[0];
    if (s instanceof ProviderError) throw s;
    return s;
  } };
}
const validJson = (t: string) => { try { const v = JSON.parse(t); return v && v.ok ? { ok: true as const, value: v } : { ok: false as const, reason: 'no ok' }; } catch { return { ok: false as const, reason: 'not json' }; } };

function setup(registry: ModelSpec[], adapters: Record<string, ProviderAdapter>) {
  const store = new Store();
  const health = newHealth();
  const gw = new Gateway({ store, registry, adapters, health, now: () => NOW, sleep: async () => {}, rng: () => 0.5 });
  const run = (plan = PLANS.free, over: any = {}) => {
    const { route, ...rest } = over;
    return gw.run({
      requestId: 'req-' + Math.random(), userId: 'u1', task: 'sms_classification',
      route: { plan, needs: ['text', 'json'], inputTokensEstimate: 500, maxOutputTokens: 500, allowExternal: true, ...(route ?? {}) },
      request: { system: 's', user: 'u', maxOutputTokens: 500, json: true }, validate: validJson, ...rest,
    });
  };
  return { store, health, gw, run };
}

test('free model success is recorded with zero estimated cost', async () => {
  const a = scripted('prov', {});
  const { run, store } = setup([model({ id: 'f1' })], { prov: a });
  const r = await run();
  assert.ok(r.ok && r.model === 'f1' && r.tier === 'free');
  const row = store.db.prepare('SELECT status, cost_usd, cost_basis, input_tokens FROM ai_attempts').get() as any;
  assert.deepEqual([row.status, row.cost_usd, row.cost_basis, row.input_tokens], ['success', 0, 'estimated', 100]);
});

test('429 on first free model: rotate to next free model, cool the first one down for later requests', async () => {
  const a = scripted('prov', { f1: [new ProviderError('rate_limit', '429', 60_000)] });
  const { run, health } = setup([model({ id: 'f1', qualityRank: 1 }), model({ id: 'f2', qualityRank: 2 })], { prov: a });
  const r = await run();
  assert.ok(r.ok && r.model === 'f2');
  assert.ok((health.modelCooldownUntil.get('prov|f1') ?? 0) > NOW.getTime());
  a.calls.length = 0;
  await run();
  assert.deepEqual(a.calls, ['f2'], 'cooled-down model is not retried');
});

test('provider outage: one backoff retry on same model, then fallback to another provider', async () => {
  const down = scripted('p1', { m1: [new ProviderError('server', '503')] });
  const up = scripted('p2', {});
  const { run, store } = setup([model({ id: 'm1', provider: 'p1' }), model({ id: 'm2', provider: 'p2', qualityRank: 2 })], { p1: down, p2: up });
  const r = await run();
  assert.ok(r.ok && r.provider === 'p2');
  assert.deepEqual(down.calls, ['m1', 'm1']);
  const rows = store.db.prepare('SELECT status FROM ai_attempts ORDER BY id').all().map((x: any) => x.status);
  assert.deepEqual(rows, ['server_error', 'server_error', 'success']);
});

test('invalid model output is rejected, tokens still accounted, next model is used', async () => {
  const a = scripted('prov', { f1: [OK('this is not json at all')], f2: [OK('{"ok":true}')] });
  const { run, store } = setup([model({ id: 'f1' }), model({ id: 'f2', qualityRank: 2 })], { prov: a });
  const r = await run();
  assert.ok(r.ok && r.model === 'f2');
  const bad = store.db.prepare(`SELECT input_tokens, status, reason FROM ai_attempts WHERE status='invalid_output'`).get() as any;
  assert.equal(bad.input_tokens, 100); assert.equal(bad.reason, 'not json');
});

test('vision request is never routed to a text-only model', async () => {
  const a = scripted('prov', {});
  const { run } = setup([model({ id: 'textonly' })], { prov: a });
  const r = await run(PLANS.free, { route: { needs: ['text', 'vision'] } });
  assert.ok(!r.ok && r.code === 'no_eligible_provider');
  assert.ok(r.rejected.some((x) => x.reason === 'missing_capability'));
  assert.equal(a.calls.length, 0);
});

test('FREE user is never silently charged: paid model is not even called when free models fail', async () => {
  const free = scripted('freeprov', { f1: [new ProviderError('rate_limit', '429')] });
  const paid = scripted('paidprov', {});
  const { run } = setup([
    model({ id: 'f1', provider: 'freeprov' }),
    model({ id: 'p1', provider: 'paidprov', tier: 'paid', priceInPerM: 1, priceOutPerM: 2, priceVerifiedAt: '2026-10-01', qualityRank: 0 }),
  ], { freeprov: free, paidprov: paid });
  const r = await run(PLANS.free);
  assert.ok(!r.ok);
  assert.equal(paid.calls.length, 0);
  assert.ok(r.rejected.some((x) => x.reason === 'plan_forbids_paid_inference'));
});

test('paid fallback allowed for a plan that permits it, only after free options are exhausted', async () => {
  const free = scripted('freeprov', { f1: [new ProviderError('rate_limit', '429')] });
  const paid = scripted('paidprov', { p1: [OK('{"ok":true}', { inputTokens: 1000, outputTokens: 100 })] });
  const { run, store } = setup([
    model({ id: 'f1', provider: 'freeprov' }),
    model({ id: 'p1', provider: 'paidprov', tier: 'paid', priceInPerM: 1, priceOutPerM: 2, priceVerifiedAt: '2026-10-01', qualityRank: 0 }),
  ], { freeprov: free, paidprov: paid });
  const r = await run(PLANS.starter);
  assert.ok(r.ok && r.tier === 'paid');
  assert.deepEqual(free.calls, ['f1']);                      // free tried FIRST even though paid has better rank
  const c = store.db.prepare(`SELECT cost_usd, cost_basis FROM ai_attempts WHERE status='success'`).get() as any;
  assert.ok(Math.abs(c.cost_usd - 0.0012) < 1e-9); assert.equal(c.cost_basis, 'estimated');
});

test('stale or unknown prices exclude paid models; budget and per-request caps are enforced', async () => {
  const paidSpec = (o: Partial<ModelSpec> = {}) => model({ id: 'p1', provider: 'paidprov', tier: 'paid', priceInPerM: 1, priceOutPerM: 2, priceVerifiedAt: '2026-10-01', ...o });
  const reasons = async (m: ModelSpec, plan = PLANS.pro, spent = 0) => {
    const { run, store } = setup([m], { paidprov: scripted('paidprov', {}) });
    if (spent) store.recordAttempt({ requestId: 'x', userId: 'u1', attemptNo: 1, provider: 'a', model: 'b', task: 't', inputTokens: 1, outputTokens: 1, costUsd: spent, costBasis: 'confirmed', latencyMs: 1, status: 'success' }, NOW);
    const r = await run(plan);
    return r.ok ? ['ok'] : r.rejected.map((x) => x.reason);
  };
  assert.deepEqual(await reasons(paidSpec({ priceVerifiedAt: '2026-05-01' })), ['price_unverified_or_stale']);
  assert.deepEqual(await reasons(paidSpec({ priceVerifiedAt: null })), ['price_unverified_or_stale']);
  assert.deepEqual(await reasons(paidSpec({ priceInPerM: 5000, priceOutPerM: 5000 })), ['exceeds_request_cost_cap']);
  assert.deepEqual(await reasons(paidSpec(), PLANS.starter, 0.9999999), ['monthly_budget_exhausted']);
  assert.throws(() => parseRegistry([{ ...paidSpec(), priceInPerM: null }]), /explicit prices/);
});

test('timeout after dispatch is AMBIGUOUS: cost is retained as an estimate and counts toward spend', async () => {
  const p = scripted('paidprov', { p1: [new ProviderError('ambiguous_timeout', 'timed out')] });
  const { run, store } = setup([model({ id: 'p1', provider: 'paidprov', tier: 'paid', priceInPerM: 1, priceOutPerM: 2, priceVerifiedAt: '2026-10-01' })], { paidprov: p });
  const r = await run(PLANS.starter);
  assert.ok(!r.ok && r.sawAmbiguous);
  const a = store.db.prepare(`SELECT cost_usd, cost_basis, status FROM ai_attempts`).get() as any;
  assert.equal(a.status, 'ambiguous_timeout'); assert.equal(a.cost_basis, 'ambiguous_estimate'); assert.ok(a.cost_usd > 0);
  assert.ok(store.spendUsd('u1', NOW) > 0, 'possible charge is not forgotten');
});

test('invalid provider credentials disable that provider (no hammering) and fall back elsewhere', async () => {
  const bad = scripted('p1', { m1: [new ProviderError('auth', '401')] });
  const good = scripted('p2', {});
  const { run, health } = setup([model({ id: 'm1', provider: 'p1' }), model({ id: 'm2', provider: 'p2', qualityRank: 2 })], { p1: bad, p2: good });
  assert.ok((await run()).ok);
  assert.ok((health.providerDisabledUntil.get('p1') ?? 0) > NOW.getTime());
  await run(); assert.equal(bad.calls.length, 1);
});

test('no provider available / external processing not permitted / registry empty => explicit failure, nothing called', async () => {
  const a = scripted('prov', {});
  assert.ok(!(await setup([], { prov: a }).run()).ok);
  const r = await setup([model({ id: 'f1' })], { prov: a }).run(PLANS.free, { route: { allowExternal: false } });
  assert.ok(!r.ok && r.code === 'no_eligible_provider' && r.rejected[0].reason === 'external_processing_not_permitted');
  const local = scripted('ollama', {});
  const r2 = await setup([model({ id: 'l1', provider: 'ollama', tier: 'local', dataPolicy: 'local' })], { ollama: local }).run(PLANS.free, { route: { allowExternal: false } });
  assert.ok(r2.ok, 'local model allowed without external consent');
});

test('bounded: never exceeds maxAttempts even if every model keeps failing', async () => {
  const a = scripted('prov', { f1: [OK('bad')], f2: [OK('bad')], f3: [OK('bad')], f4: [OK('bad')], f5: [OK('bad')] });
  const { run } = setup(['f1', 'f2', 'f3', 'f4', 'f5'].map((id, i) => model({ id, qualityRank: i })), { prov: a });
  const r = await run(PLANS.free, { maxAttempts: 3 });
  assert.ok(!r.ok && r.attempts === 3 && a.calls.length === 3);
});

test('registry parser rejects malformed operator config', () => {
  assert.throws(() => parseRegistry([{ id: 'x' }]), /provider required/);
  assert.throws(() => parseRegistry({}), /array/);
  assert.equal(parseRegistry([]).length, 0);
});

// ---------------------------------------------------------------- adapter vs LOCAL MOCK server (not a real provider)
async function mock(handler: http.RequestListener) {
  const srv = http.createServer(handler);
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}/v1`, close: () => srv.close() };
}
const spec = model({ id: 'm' });
const req = { system: 's', user: 'hello', maxOutputTokens: 50, json: true };

test('adapter: success parses content/usage; sends bearer key; request body shape', async () => {
  let seen: any = {};
  const m = await mock((q, r) => { let b = ''; q.on('data', (c) => (b += c)); q.on('end', () => { seen = { auth: q.headers.authorization, url: q.url, body: JSON.parse(b) }; r.setHeader('content-type', 'application/json'); r.end(JSON.stringify({ choices: [{ message: { content: '{"ok":true}' } }], usage: { prompt_tokens: 7, completion_tokens: 3, cost: 0.0001 } })); }); });
  try {
    const out = await new OpenAICompatAdapter({ name: 'x', baseUrl: m.url, apiKey: 'k' }).complete(spec, req, { signal: new AbortController().signal });
    assert.deepEqual(out, { text: '{"ok":true}', inputTokens: 7, outputTokens: 3, costUsd: 0.0001 });
    assert.equal(seen.auth, 'Bearer k'); assert.equal(seen.url, '/v1/chat/completions');
    assert.equal(seen.body.model, 'm'); assert.equal(seen.body.messages[1].content, 'hello'); assert.equal(seen.body.max_tokens, 50);
  } finally { m.close(); }
});

test('adapter: HTTP errors map to the right ProviderError kinds; missing usage stays null (never invented)', async () => {
  const kinds: [number, string][] = [[429, 'rate_limit'], [401, 'auth'], [403, 'auth'], [500, 'server'], [503, 'server'], [400, 'bad_request'], [404, 'bad_request']];
  for (const [status, kind] of kinds) {
    const m = await mock((_q, r) => { r.statusCode = status; if (status === 429) r.setHeader('retry-after', '7'); r.end('{}'); });
    try {
      await assert.rejects(new OpenAICompatAdapter({ name: 'x', baseUrl: m.url }).complete(spec, req, { signal: new AbortController().signal }),
        (e: any) => e instanceof ProviderError && e.kind === kind && (status !== 429 || e.retryAfterMs === 7000), `${status}`);
    } finally { m.close(); }
  }
  const m = await mock((_q, r) => r.end(JSON.stringify({ choices: [{ message: { content: 'hi' } }] })));
  try {
    const out = await new OpenAICompatAdapter({ name: 'x', baseUrl: m.url }).complete(spec, req, { signal: new AbortController().signal });
    assert.deepEqual([out.inputTokens, out.outputTokens, out.costUsd], [null, null, null]);
  } finally { m.close(); }
});

test('adapter: slow server => ambiguous_timeout; closed port => network (not ambiguous); garbage body => server', async () => {
  const slow = await mock(() => { /* never respond */ });
  try {
    const ac = new AbortController(); setTimeout(() => ac.abort(), 80);
    await assert.rejects(new OpenAICompatAdapter({ name: 'x', baseUrl: slow.url }).complete(spec, req, { signal: ac.signal }), (e: any) => e.kind === 'ambiguous_timeout');
  } finally { slow.close(); }
  await assert.rejects(new OpenAICompatAdapter({ name: 'x', baseUrl: 'http://127.0.0.1:1/v1' }).complete(spec, req, { signal: new AbortController().signal }), (e: any) => e.kind === 'network');
  const bad = await mock((_q, r) => r.end('<html>oops</html>'));
  try { await assert.rejects(new OpenAICompatAdapter({ name: 'x', baseUrl: bad.url }).complete(spec, req, { signal: new AbortController().signal }), (e: any) => e.kind === 'server'); } finally { bad.close(); }
});
