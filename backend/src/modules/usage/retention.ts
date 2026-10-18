import type { Store } from './store.ts';

export interface RetentionPolicy { analysisDays: number; attemptDays: number; staleReservationMs: number }
export interface RetentionReport { analysesDeleted: number; attemptsDeleted: number; reservationsReleased: number }

/** One retention pass. Idempotent; safe to run repeatedly. Rejects nonsensical policies so a typo cannot wipe everything. */
export function runRetention(store: Store, p: RetentionPolicy, now = new Date()): RetentionReport {
  if (!(p.analysisDays >= 1) || !(p.attemptDays >= 1) || !(p.staleReservationMs >= 60_000)) throw new Error('invalid retention policy');
  return {
    analysesDeleted: store.purgeAnalysesOlderThan(p.analysisDays, now),
    attemptsDeleted: store.purgeAttemptsOlderThan(p.attemptDays, now),
    reservationsReleased: store.releaseStale(p.staleReservationMs, now),
  };
}
