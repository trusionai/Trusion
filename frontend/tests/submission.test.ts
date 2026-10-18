import { test } from 'node:test';
import assert from 'node:assert/strict';
import { submissionReducer as red } from '../src/state/submission.ts';
import type { Submission } from '../src/state/submission.ts';

let n = 0; const nk = () => `key-${++n}`;
test('double submit while in flight is ignored (no second key, no second request)', () => {
  let s: Submission<string> = { phase: 'idle' };
  s = red(s, { type: 'submit', newKey: nk }); const k = (s as { key: string }).key;
  const again = red(s, { type: 'submit', newKey: nk });
  assert.equal(again, s); assert.equal((again as { key: string }).key, k);
});
test('error then retry REUSES the idempotency key; success then new submit gets a NEW key', () => {
  let s: Submission<string> = red({ phase: 'idle' }, { type: 'submit', newKey: nk });
  const k1 = (s as { key: string }).key;
  s = red(s, { type: 'reject', key: k1, error: new Error('timeout') });
  assert.equal(s.phase, 'error');
  s = red(s, { type: 'submit', newKey: nk }); assert.equal((s as { key: string }).key, k1, 'retry keeps key');
  s = red(s, { type: 'resolve', key: k1, result: 'ok' }); assert.equal(s.phase, 'success');
  s = red(s, { type: 'submit', newKey: nk }); assert.notEqual((s as { key: string }).key, k1);
});
test('editing input after an error discards the key; editing during flight is ignored', () => {
  let s: Submission<string> = red({ phase: 'idle' }, { type: 'submit', newKey: nk });
  const k = (s as { key: string }).key;
  assert.equal(red(s, { type: 'edit' }), s);
  s = red(s, { type: 'reject', key: k, error: 1 });
  s = red(s, { type: 'edit' }); assert.equal(s.phase, 'idle');
  assert.notEqual((red(s, { type: 'submit', newKey: nk }) as { key: string }).key, k);
});
test('STALE responses cannot overwrite newer state', () => {
  let s: Submission<string> = red({ phase: 'idle' }, { type: 'submit', newKey: nk });
  const old = (s as { key: string }).key;
  s = red(s, { type: 'reset' });
  s = red(s, { type: 'submit', newKey: nk });
  const after = red(s, { type: 'resolve', key: old, result: 'STALE' });
  assert.equal(after, s);
  assert.equal(red(s, { type: 'reject', key: old, error: 1 }), s);
});
