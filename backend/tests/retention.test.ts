import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../src/modules/usage/store.ts';
import { runRetention } from '../src/modules/usage/retention.ts';

const NOW = new Date('2026-10-18T00:00:00Z'); const days = (n: number) => new Date(NOW.getTime() - n * 86_400_000);
const att = (n: string) => ({ requestId: n, userId: 'u', attemptNo: 1, provider: 'p', model: 'm', task: 't', inputTokens: 1, outputTokens: 1, costUsd: 0, costBasis: 'estimated' as const, latencyMs: 1, status: 'success' });

test('retention removes only expired rows, releases stale reservations, and is idempotent', () => {
  const s = new Store();
  const old = s.saveAnalysis({ userId: 'u', kind: 'sms', status: 'completed', result: {}, now: days(120) });
  const fresh = s.saveAnalysis({ userId: 'u', kind: 'sms', status: 'completed', result: {}, now: days(10) });
  s.recordAttempt(att('old'), days(500)); s.recordAttempt(att('new'), days(5));
  s.reserve('u', 'stuck', 2, 10, new Date(NOW.getTime() - 3_600_000));
  const r1 = runRetention(s, { analysisDays: 90, attemptDays: 400, staleReservationMs: 300_000 }, NOW);
  assert.deepEqual(r1, { analysesDeleted: 1, attemptsDeleted: 1, reservationsReleased: 1 });
  assert.equal(s.getAnalysis('u', old), null); assert.ok(s.getAnalysis('u', fresh));
  assert.equal(s.attemptsFor('new').length, 1); assert.equal(s.attemptsFor('old').length, 0);
  assert.equal(s.usage('u', NOW).reserved, 0);
  assert.deepEqual(runRetention(s, { analysisDays: 90, attemptDays: 400, staleReservationMs: 300_000 }, NOW), { analysesDeleted: 0, attemptsDeleted: 0, reservationsReleased: 0 });
});

test('nonsensical policies are refused (a typo cannot wipe all data or release live reservations)', () => {
  const s = new Store(); s.saveAnalysis({ userId: 'u', kind: 'sms', status: 'completed', result: {}, now: NOW });
  for (const p of [{ analysisDays: 0, attemptDays: 400, staleReservationMs: 300_000 }, { analysisDays: -5, attemptDays: 400, staleReservationMs: 300_000 }, { analysisDays: 90, attemptDays: NaN, staleReservationMs: 300_000 }, { analysisDays: 90, attemptDays: 400, staleReservationMs: 10 }]) assert.throws(() => runRetention(s, p, NOW), /invalid retention policy/);
  assert.equal(s.listAnalyses('u').length, 1);
});
