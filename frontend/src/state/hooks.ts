import { useCallback, useEffect, useReducer, useRef, useState } from 'react';
import { submissionReducer } from './submission.ts';
import type { Submission } from './submission.ts';
import { newIdempotencyKey } from '../api/client.ts';

export interface Loadable<T> { data: T | null; error: unknown; loading: boolean; reload: () => void }
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[]): Loadable<T> {
  const [st, setSt] = useState<{ data: T | null; error: unknown; loading: boolean }>({ data: null, error: null, loading: true });
  const [tick, setTick] = useState(0);
  const fnRef = useRef(fn); fnRef.current = fn;
  useEffect(() => {
    let live = true; setSt((s) => ({ ...s, loading: true, error: null }));
    fnRef.current().then((d) => { if (live) setSt({ data: d, error: null, loading: false }); }, (e) => { if (live) setSt({ data: null, error: e, loading: false }); });
    return () => { live = false; };            // a stale response from a previous render can never overwrite newer state
  }, [...deps, tick]);
  return { ...st, reload: () => setTick((t) => t + 1) };
}

export function useAnalysis<T>(run: (key: string) => Promise<T>) {
  const [s, dispatch] = useReducer(submissionReducer as (s: Submission<T>, a: Parameters<typeof submissionReducer<T>>[1]) => Submission<T>, { phase: 'idle' } as Submission<T>);
  const sRef = useRef(s); sRef.current = s;
  const runRef = useRef(run); runRef.current = run;
  const submit = useCallback(async () => {
    const cur = sRef.current;
    if (cur.phase === 'submitting') return;                                   // duplicate-submission guard
    const key = cur.phase === 'error' ? cur.key : newIdempotencyKey();        // retry reuses the key => never charged twice
    dispatch({ type: 'submit', newKey: () => key });
    try { dispatch({ type: 'resolve', key, result: await runRef.current(key) }); }
    catch (error) { dispatch({ type: 'reject', key, error }); }
  }, []);
  return { state: s, submit, edit: () => dispatch({ type: 'edit' }), reset: () => dispatch({ type: 'reset' }) };
}
