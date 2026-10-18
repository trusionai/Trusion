import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Store, periodOf } from '../src/modules/usage/store.ts';
import { PLANS } from '../src/modules/entitlements/plans.ts';

const T0 = new Date('2026-10-16T10:00:00Z');

test('unknown user is on free plan; plan comes only from server entitlement', () => {
  const s = new Store();
  assert.equal(s.getPlan('u1', T0).id, 'free');
  s.grantPlan('u1', 'pro', { source: 'test', now: T0 });
  assert.equal(s.getPlan('u1', T0).id, 'pro');
});

test('expired and revoked entitlements fall back to free', () => {
  const s = new Store();
  s.grantPlan('u1', 'pro', { validUntil: new Date('2026-10-01T00:00:00Z'), source: 'test', now: T0 });
  assert.equal(s.getPlan('u1', T0).id, 'free', 'expired');
  s.grantPlan('u2', 'business', { source: 'test', now: T0 });
  s.revokePlan('u2', 'refund', T0);
  assert.equal(s.getPlan('u2', T0).id, 'free', 'revoked');
});

test('reserve/commit/release keep allowance consistent', () => {
  const s = new Store();
  const r = s.reserve('u1', 'k1', 3, 10, T0);
  assert.ok(r.ok);
  assert.deepEqual(s.usage('u1', T0), { period: '2026-10', used: 0, reserved: 3 });
  if (r.ok) s.commit(r.reservationId, 2); // actual lower than reserved -> only 2 charged
  assert.deepEqual(s.usage('u1', T0), { period: '2026-10', used: 2, reserved: 0 });
  const r2 = s.reserve('u1', 'k2', 4, 10, T0);
  assert.ok(r2.ok);
  if (r2.ok) s.release(r2.reservationId);
  assert.deepEqual(s.usage('u1', T0), { period: '2026-10', used: 2, reserved: 0 });
});

test('commit cannot charge more than reserved, and double-commit/release are no-ops', () => {
  const s = new Store();
  const r = s.reserve('u1', 'k1', 2, 10, T0);
  assert.ok(r.ok && r.reservationId);
  if (!r.ok) return;
  s.commit(r.reservationId, 99);
  s.commit(r.reservationId, 99);
  s.release(r.reservationId);
  assert.equal(s.usage('u1', T0).used, 2);
  assert.equal(s.usage('u1', T0).reserved, 0);
});

test('quota is enforced including in-flight reservations (no overspend)', () => {
  const s = new Store();
  const results = Array.from({ length: 50 }, (_, i) => s.reserve('u1', `k${i}`, 1, 20, T0));
  assert.equal(results.filter((r) => r.ok).length, 20);
  const denied = results.find((r) => !r.ok);
  assert.ok(denied && !denied.ok && denied.reason === 'quota_exceeded');
  assert.equal(s.usage('u1', T0).reserved, 20);
});

test('idempotent reserve: same key replays, different units conflicts, no double charge', () => {
  const s = new Store();
  const a = s.reserve('u1', 'same', 1, 5, T0);
  const b = s.reserve('u1', 'same', 1, 5, T0);
  assert.ok(a.ok && b.ok && b.replay && a.reservationId === b.reservationId);
  assert.equal(s.usage('u1', T0).reserved, 1);
  const c = s.reserve('u1', 'same', 3, 5, T0);
  assert.ok(!c.ok && c.reason === 'idempotency_conflict');
});

test('users are isolated from each other and months roll over', () => {
  const s = new Store();
  s.reserve('u1', 'k', 5, 5, T0);
  assert.ok(s.reserve('u2', 'k', 5, 5, T0).ok, 'u2 unaffected by u1');
  assert.ok(!s.reserve('u1', 'k2', 1, 5, T0).ok);
  const nextMonth = new Date('2026-11-01T00:00:01Z');
  assert.equal(periodOf(nextMonth), '2026-11');
  assert.ok(s.reserve('u1', 'k3', 1, 5, nextMonth).ok, 'new period has fresh allowance');
});

test('stale reservations from a crashed request are reclaimed', () => {
  const s = new Store();
  s.reserve('u1', 'k', 4, 10, T0);
  assert.equal(s.releaseStale(60_000, new Date(T0.getTime() + 30_000)), 0);
  assert.equal(s.releaseStale(60_000, new Date(T0.getTime() + 120_000)), 1);
  assert.equal(s.usage('u1', T0).reserved, 0);
});

test('analyses are only readable by their owner; missing and foreign look identical', () => {
  const s = new Store();
  const id = s.saveAnalysis({ userId: 'alice', kind: 'sms', status: 'completed', result: { secret: 1 } });
  assert.ok(s.getAnalysis('alice', id));
  assert.equal(s.getAnalysis('bob', id), null);
  assert.equal(s.getAnalysis('bob', 'does-not-exist'), null);
  assert.equal(s.listAnalyses('bob').length, 0);
});

test('retention purge and user-data deletion work', () => {
  const s = new Store();
  s.saveAnalysis({ userId: 'u1', kind: 'sms', status: 'completed', result: {}, now: new Date('2026-01-01T00:00:00Z') });
  s.saveAnalysis({ userId: 'u1', kind: 'sms', status: 'completed', result: {}, now: T0 });
  assert.equal(s.purgeAnalysesOlderThan(30, T0), 1);
  s.deleteUserData('u1');
  assert.equal(s.listAnalyses('u1').length, 0);
});

test('provider spend counts confirmed+estimated+ambiguous, ignores unknown-cost rows', () => {
  const s = new Store();
  const base = { requestId: 'r', userId: 'u1', attemptNo: 1, provider: 'p', model: 'm', task: 'sms', inputTokens: 1, outputTokens: 1, latencyMs: 1, status: 'success' };
  s.recordAttempt({ ...base, costUsd: 0.01, costBasis: 'confirmed' }, T0);
  s.recordAttempt({ ...base, attemptNo: 2, costUsd: 0.02, costBasis: 'ambiguous_estimate', status: 'ambiguous_timeout' }, T0);
  s.recordAttempt({ ...base, attemptNo: 3, costUsd: null, costBasis: 'unknown' }, T0);
  assert.ok(Math.abs(s.spendUsd('u1', T0) - 0.03) < 1e-9);
  assert.equal(PLANS.free.allowPaidInference, false);
});

test('retry with the same key after a released (failed) request re-reserves instead of replaying a dead reservation', () => {
  const s = new Store();
  const a = s.reserve('u1', 'retry-key', 2, 5, T0);
  assert.ok(a.ok);
  if (a.ok) s.release(a.reservationId);
  assert.equal(s.usage('u1', T0).reserved, 0);
  const b = s.reserve('u1', 'retry-key', 2, 5, T0);
  assert.ok(b.ok && !b.replay && b.state === 'reserved' && b.reservationId === (a.ok ? a.reservationId : ''));
  assert.equal(s.usage('u1', T0).reserved, 2);
  if (b.ok) s.commit(b.reservationId, 2);
  const c = s.reserve('u1', 'retry-key', 2, 5, T0);
  assert.ok(c.ok && c.replay && c.state === 'committed', 'completed work is replayed, never charged twice');
  assert.equal(s.usage('u1', T0).used, 2);
});
