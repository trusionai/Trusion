/**
 * Authoritative server-side store.
 *
 * Three SEPARATE accounting concerns (per spec §10):
 *   A. user allowance      -> usage_periods + reservations
 *   B. provider capacity   -> in-memory health in the gateway (cooldowns)
 *   C. actual provider cost-> ai_attempts
 *
 * ENGINE NOTE: implemented on node:sqlite (experimental in Node 22) because no
 * third-party packages/Postgres were available when this was written. The
 * production target is Postgres/Supabase; this class is the seam to replace.
 * Atomicity here relies on BEGIN IMMEDIATE; the equivalent Postgres design is a
 * single conditional UPDATE ... WHERE used+reserved+units <= limit.
 * All timestamps are UTC ISO-8601. Usage periods are UTC calendar months.
 */
import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { PLANS, isPlanId } from '../entitlements/plans.ts';
import type { PlanConfig, PlanId } from '../entitlements/plans.ts';

export type CostBasis = 'confirmed' | 'estimated' | 'ambiguous_estimate' | 'unknown';

export interface AttemptRecord {
  requestId: string;
  userId: string;
  attemptNo: number;
  provider: string;
  model: string;
  task: string;
  inputTokens: number | null;
  outputTokens: number | null;
  costUsd: number | null;
  costBasis: CostBasis;
  latencyMs: number;
  status: string; // success | rate_limited | timeout | ambiguous_timeout | server_error | auth_error | invalid_output | unsupported | ...
  reason?: string;
}

export type ReserveResult =
  | { ok: true; reservationId: string; replay: boolean; state: string }
  | { ok: false; reason: 'quota_exceeded'; remaining: number }
  | { ok: false; reason: 'idempotency_conflict' };

export function periodOf(d: Date): string {
  return d.toISOString().slice(0, 7); // YYYY-MM in UTC
}

export class Store {
  db: DatabaseSync;

  constructor(path = ':memory:') {
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS entitlements(
        user_id TEXT PRIMARY KEY, plan TEXT NOT NULL, status TEXT NOT NULL,
        valid_until TEXT, source TEXT NOT NULL, updated_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS usage_periods(
        user_id TEXT NOT NULL, period TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0 CHECK(used >= 0),
        reserved INTEGER NOT NULL DEFAULT 0 CHECK(reserved >= 0),
        PRIMARY KEY(user_id, period));
      CREATE TABLE IF NOT EXISTS reservations(
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL, period TEXT NOT NULL,
        idem_key TEXT NOT NULL, units INTEGER NOT NULL CHECK(units > 0),
        charged INTEGER NOT NULL DEFAULT 0,
        state TEXT NOT NULL CHECK(state IN ('reserved','committed','released')),
        created_at TEXT NOT NULL, UNIQUE(user_id, idem_key));
      CREATE TABLE IF NOT EXISTS analyses(
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL,
        status TEXT NOT NULL, result_json TEXT NOT NULL, idem_key TEXT,
        created_at TEXT NOT NULL, UNIQUE(user_id, idem_key));
      CREATE INDEX IF NOT EXISTS analyses_user_created ON analyses(user_id, created_at DESC);
      CREATE TABLE IF NOT EXISTS ai_attempts(
        id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL, user_id TEXT NOT NULL,
        period TEXT NOT NULL, attempt_no INTEGER NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL,
        task TEXT NOT NULL, input_tokens INTEGER, output_tokens INTEGER, cost_usd REAL,
        cost_basis TEXT NOT NULL, latency_ms INTEGER NOT NULL, status TEXT NOT NULL,
        reason TEXT, created_at TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS attempts_user_period ON ai_attempts(user_id, period);
    `);
  }

  /** Run fn inside an IMMEDIATE transaction (write lock taken up-front). */
  private tx<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const out = fn();
      this.db.exec('COMMIT');
      return out;
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
  }

  // ---------------------------------------------------------------- entitlements

  /**
   * Resolve the effective plan from SERVER data only. Anything in a JWT
   * (user_metadata etc.) is ignored by design. No row / expired / inactive => free.
   */
  getPlan(userId: string, now = new Date()): PlanConfig {
    const row = this.db.prepare('SELECT plan, status, valid_until FROM entitlements WHERE user_id = ?').get(userId) as
      | { plan: string; status: string; valid_until: string | null } | undefined;
    if (!row || row.status !== 'active' || !isPlanId(row.plan)) return PLANS.free;
    if (row.valid_until && new Date(row.valid_until).getTime() <= now.getTime()) return PLANS.free;
    return PLANS[row.plan];
  }

  /**
   * Internal-only. Must be called solely from verified billing/admin code paths;
   * there is deliberately NO HTTP route that calls this in this slice.
   */
  grantPlan(userId: string, plan: PlanId, opts: { validUntil?: Date | null; source: string; now?: Date }): void {
    const now = opts.now ?? new Date();
    this.db.prepare(
      `INSERT INTO entitlements(user_id, plan, status, valid_until, source, updated_at) VALUES(?,?,?,?,?,?)
       ON CONFLICT(user_id) DO UPDATE SET plan=excluded.plan, status='active', valid_until=excluded.valid_until,
         source=excluded.source, updated_at=excluded.updated_at`,
    ).run(userId, plan, 'active', opts.validUntil ? opts.validUntil.toISOString() : null, opts.source, now.toISOString());
  }

  revokePlan(userId: string, source: string, now = new Date()): void {
    this.db.prepare(`UPDATE entitlements SET status='revoked', source=?, updated_at=? WHERE user_id=?`)
      .run(source, now.toISOString(), userId);
  }

  // ---------------------------------------------------------------- allowance (A)

  usage(userId: string, now = new Date()): { period: string; used: number; reserved: number } {
    const period = periodOf(now);
    const row = this.db.prepare('SELECT used, reserved FROM usage_periods WHERE user_id=? AND period=?').get(userId, period) as
      | { used: number; reserved: number } | undefined;
    return { period, used: row?.used ?? 0, reserved: row?.reserved ?? 0 };
  }

  /** Atomically reserve units against the monthly limit. Idempotent per (user, key). */
  reserve(userId: string, idemKey: string, units: number, limit: number, now = new Date()): ReserveResult {
    return this.tx(() => {
      const existing = this.db.prepare('SELECT id, units, state FROM reservations WHERE user_id=? AND idem_key=?').get(userId, idemKey) as
        | { id: string; units: number; state: string } | undefined;
      if (existing && existing.state !== 'released') {
        if (existing.units !== units) return { ok: false, reason: 'idempotency_conflict' } as const;
        return { ok: true, reservationId: existing.id, replay: true, state: existing.state } as const;
      }
      if (existing && existing.units !== units) return { ok: false, reason: 'idempotency_conflict' } as const;
      const period = periodOf(now);
      this.db.prepare('INSERT OR IGNORE INTO usage_periods(user_id, period) VALUES(?,?)').run(userId, period);
      const u = this.db.prepare('SELECT used, reserved FROM usage_periods WHERE user_id=? AND period=?').get(userId, period) as { used: number; reserved: number };
      if (u.used + u.reserved + units > limit) {
        return { ok: false, reason: 'quota_exceeded', remaining: Math.max(0, limit - u.used - u.reserved) } as const;
      }
      const id = existing ? existing.id : randomUUID();
      this.db.prepare('UPDATE usage_periods SET reserved = reserved + ? WHERE user_id=? AND period=?').run(units, userId, period);
      if (existing) {
        // A previously released (failed) request is being retried with the same key: re-activate it.
        this.db.prepare(`UPDATE reservations SET state='reserved', period=?, created_at=? WHERE id=?`).run(period, now.toISOString(), id);
      } else {
        this.db.prepare('INSERT INTO reservations(id,user_id,period,idem_key,units,state,created_at) VALUES(?,?,?,?,?,?,?)')
          .run(id, userId, period, idemKey, units, 'reserved', now.toISOString());
      }
      return { ok: true, reservationId: id, replay: false, state: 'reserved' } as const;
    });
  }

  /** Convert a reservation to actual usage (clamped to what was reserved). Idempotent. */
  commit(reservationId: string, actualUnits: number): void {
    this.tx(() => {
      const r = this.db.prepare('SELECT user_id, period, units, state FROM reservations WHERE id=?').get(reservationId) as
        | { user_id: string; period: string; units: number; state: string } | undefined;
      if (!r || r.state !== 'reserved') return;
      const charge = Math.max(0, Math.min(actualUnits, r.units));
      this.db.prepare('UPDATE usage_periods SET reserved = reserved - ?, used = used + ? WHERE user_id=? AND period=?')
        .run(r.units, charge, r.user_id, r.period);
      this.db.prepare(`UPDATE reservations SET state='committed', charged=? WHERE id=?`).run(charge, reservationId);
    });
  }

  /** Give the reservation back (failed request). No effect if already committed/released. */
  release(reservationId: string): void {
    this.tx(() => {
      const r = this.db.prepare('SELECT user_id, period, units, state FROM reservations WHERE id=?').get(reservationId) as
        | { user_id: string; period: string; units: number; state: string } | undefined;
      if (!r || r.state !== 'reserved') return;
      this.db.prepare('UPDATE usage_periods SET reserved = reserved - ? WHERE user_id=? AND period=?').run(r.units, r.user_id, r.period);
      this.db.prepare(`UPDATE reservations SET state='released' WHERE id=?`).run(reservationId);
    });
  }

  /** Crash recovery: release reservations stuck in 'reserved' longer than maxAgeMs. */
  releaseStale(maxAgeMs: number, now = new Date()): number {
    const cutoff = new Date(now.getTime() - maxAgeMs).toISOString();
    const rows = this.db.prepare(`SELECT id FROM reservations WHERE state='reserved' AND created_at < ?`).all(cutoff) as { id: string }[];
    for (const r of rows) this.release(r.id);
    return rows.length;
  }

  // ---------------------------------------------------------------- analyses (ownership enforced here)

  saveAnalysis(a: { userId: string; kind: string; status: string; result: unknown; idemKey?: string | null; now?: Date }): string {
    const id = randomUUID();
    this.db.prepare('INSERT INTO analyses(id,user_id,kind,status,result_json,idem_key,created_at) VALUES(?,?,?,?,?,?,?)')
      .run(id, a.userId, a.kind, a.status, JSON.stringify(a.result), a.idemKey ?? null, (a.now ?? new Date()).toISOString());
    return id;
  }

  /** Returns null for both "missing" and "someone else's" so existence never leaks. */
  getAnalysis(userId: string, id: string): { id: string; kind: string; status: string; result: unknown; createdAt: string } | null {
    const r = this.db.prepare('SELECT id, kind, status, result_json, created_at FROM analyses WHERE id=? AND user_id=?').get(id, userId) as
      | { id: string; kind: string; status: string; result_json: string; created_at: string } | undefined;
    return r ? { id: r.id, kind: r.kind, status: r.status, result: JSON.parse(r.result_json), createdAt: r.created_at } : null;
  }

  getAnalysisByIdemKey(userId: string, key: string): { id: string; kind: string; status: string; result: unknown } | null {
    const r = this.db.prepare('SELECT id, kind, status, result_json FROM analyses WHERE user_id=? AND idem_key=?').get(userId, key) as
      | { id: string; kind: string; status: string; result_json: string } | undefined;
    return r ? { id: r.id, kind: r.kind, status: r.status, result: JSON.parse(r.result_json) } : null;
  }

  listAnalyses(userId: string, limit = 50): { id: string; kind: string; status: string; createdAt: string }[] {
    const rows = this.db.prepare('SELECT id, kind, status, created_at FROM analyses WHERE user_id=? ORDER BY created_at DESC LIMIT ?')
      .all(userId, Math.min(Math.max(1, limit), 200)) as { id: string; kind: string; status: string; created_at: string }[];
    return rows.map((r) => ({ id: r.id, kind: r.kind, status: r.status, createdAt: r.created_at }));
  }

  /** Retention: delete analyses older than `days`. Returns rows deleted. */
  purgeAnalysesOlderThan(days: number, now = new Date()): number {
    const cutoff = new Date(now.getTime() - days * 86_400_000).toISOString();
    const r = this.db.prepare('DELETE FROM analyses WHERE created_at < ?').run(cutoff);
    return Number(r.changes);
  }

  /** Retention for the provider-cost ledger (no message content, but per-user metadata). Returns rows deleted. */
  purgeAttemptsOlderThan(days: number, now = new Date()): number {
    const cutoff = new Date(now.getTime() - days * 86_400_000).toISOString();
    return Number(this.db.prepare('DELETE FROM ai_attempts WHERE created_at < ?').run(cutoff).changes);
  }

  /** Data deletion workflow: remove everything we hold keyed to this user (audit of attempts kept anonymised-by-id only). */
  deleteUserData(userId: string): void {
    this.tx(() => {
      for (const t of ['analyses', 'reservations', 'usage_periods', 'entitlements']) {
        this.db.prepare(`DELETE FROM ${t} WHERE user_id=?`).run(userId);
      }
    });
  }

  // ---------------------------------------------------------------- provider cost (C)

  recordAttempt(a: AttemptRecord, now = new Date()): void {
    this.db.prepare(
      `INSERT INTO ai_attempts(request_id,user_id,period,attempt_no,provider,model,task,input_tokens,output_tokens,cost_usd,cost_basis,latency_ms,status,reason,created_at)
       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    ).run(a.requestId, a.userId, periodOf(now), a.attemptNo, a.provider, a.model, a.task, a.inputTokens, a.outputTokens,
      a.costUsd, a.costBasis, a.latencyMs, a.status, a.reason ?? null, now.toISOString());
  }

  attemptsFor(requestId: string): (AttemptRecord & { period: string })[] {
    const rows = this.db.prepare('SELECT * FROM ai_attempts WHERE request_id=? ORDER BY attempt_no').all(requestId) as any[];
    return rows.map((r) => ({
      requestId: r.request_id, userId: r.user_id, period: r.period, attemptNo: r.attempt_no, provider: r.provider, model: r.model,
      task: r.task, inputTokens: r.input_tokens, outputTokens: r.output_tokens, costUsd: r.cost_usd, costBasis: r.cost_basis,
      latencyMs: r.latency_ms, status: r.status, reason: r.reason ?? undefined,
    }));
  }

  /**
   * Provider spend for a user in a period. Conservatively INCLUDES ambiguous
   * (timed-out, may have completed) attempts using their estimated cost.
   */
  spendUsd(userId: string, now = new Date()): number {
    const r = this.db.prepare(
      `SELECT COALESCE(SUM(cost_usd),0) AS s FROM ai_attempts WHERE user_id=? AND period=? AND cost_usd IS NOT NULL
         AND cost_basis IN ('confirmed','estimated','ambiguous_estimate')`,
    ).get(userId, periodOf(now)) as { s: number };
    return r.s;
  }
}
