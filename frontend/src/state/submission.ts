/**
 * Pure state machine for a charged submission. Guarantees (unit-tested):
 *  - a second submit while one is in flight is ignored (no duplicate charge from double clicks);
 *  - after an error the SAME Idempotency-Key is reused on retry (server de-duplicates);
 *  - editing the input discards the key; a new submit gets a fresh one;
 *  - a late response for an old key can never overwrite a newer state (stale-response protection).
 */
export type Submission<T> =
  | { phase: 'idle' }
  | { phase: 'submitting'; key: string }
  | { phase: 'success'; key: string; result: T }
  | { phase: 'error'; key: string; error: unknown };

export type SubmissionAction<T> =
  | { type: 'submit'; newKey: () => string }
  | { type: 'resolve'; key: string; result: T }
  | { type: 'reject'; key: string; error: unknown }
  | { type: 'edit' }
  | { type: 'reset' };

export function submissionReducer<T>(s: Submission<T>, a: SubmissionAction<T>): Submission<T> {
  switch (a.type) {
    case 'submit':
      if (s.phase === 'submitting') return s;
      return { phase: 'submitting', key: s.phase === 'error' ? s.key : a.newKey() };
    case 'resolve': return s.phase === 'submitting' && s.key === a.key ? { phase: 'success', key: a.key, result: a.result } : s;
    case 'reject': return s.phase === 'submitting' && s.key === a.key ? { phase: 'error', key: a.key, error: a.error } : s;
    case 'edit': return s.phase === 'submitting' ? s : { phase: 'idle' };
    case 'reset': return { phase: 'idle' };
  }
}
