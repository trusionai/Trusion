/**
 * Gateway executor: bounded fallback over router-selected candidates, with
 * per-attempt provider-cost accounting. It does NOT touch the user allowance;
 * callers reserve/commit/release that separately (spec §10: three independent ledgers).
 */
import { ProviderError } from './types.ts';
import type { CompletionRequest, CompletionResult, ModelSpec, ProviderAdapter } from './types.ts';
import { selectCandidates, worstCaseCostUsd } from './router.ts';
import type { Health, RouteContext } from './router.ts';
import type { CostBasis, Store } from '../usage/store.ts';

export type Validated<T> = { ok: true; value: T } | { ok: false; reason: string };

export interface GatewayDeps {
  store: Store;
  registry: ModelSpec[];
  adapters: Record<string, ProviderAdapter>;
  health: Health;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
  rng?: () => number;
}

export interface RunParams<T> {
  requestId: string;
  userId: string;
  task: string;
  route: Omit<RouteContext, 'now' | 'spentThisMonthUsd'>;
  request: CompletionRequest;
  validate: (text: string) => Validated<T>;
  maxAttempts?: number;
  totalDeadlineMs?: number;
  perAttemptTimeoutMs?: number;
  defaultCooldownMs?: number;
}

export type RunOutcome<T> =
  | { ok: true; value: T; provider: string; model: string; tier: string; attempts: number }
  | { ok: false; code: 'no_eligible_provider' | 'all_attempts_failed' | 'deadline_exceeded'; attempts: number; rejected: { model: string; provider: string; reason: string }[]; sawAmbiguous: boolean };

export class Gateway {
  deps: GatewayDeps;
  constructor(deps: GatewayDeps) { this.deps = deps; }

  async run<T>(p: RunParams<T>): Promise<RunOutcome<T>> {
    const d = this.deps;
    const clock = d.now ?? (() => new Date());
    const sleep = d.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    const rng = d.rng ?? Math.random;
    const started = clock().getTime();
    const deadline = started + (p.totalDeadlineMs ?? 20_000);
    const maxAttempts = p.maxAttempts ?? 4;
    const cooldown = p.defaultCooldownMs ?? 30_000;
    const tried = new Set<string>();
    let attemptNo = 0;
    let sawAmbiguous = false;
    let lastRejected: { model: string; provider: string; reason: string }[] = [];
    let sawAny = false;

    while (attemptNo < maxAttempts) {
      if (clock().getTime() >= deadline) return { ok: false, code: 'deadline_exceeded', attempts: attemptNo, rejected: lastRejected, sawAmbiguous };
      const sel = selectCandidates(d.registry, { ...p.route, now: clock(), spentThisMonthUsd: d.store.spendUsd(p.userId, clock()) }, d.health);
      lastRejected = sel.rejected;
      const model = sel.candidates.find((m) => !tried.has(`${m.provider}|${m.id}`) && d.adapters[m.provider]);
      if (!model) return { ok: false, code: sawAny ? 'all_attempts_failed' : 'no_eligible_provider', attempts: attemptNo, rejected: lastRejected, sawAmbiguous };
      sawAny = true;
      const key = `${model.provider}|${model.id}`;
      const adapter = d.adapters[model.provider];

      // up to 2 tries on the same model for transient errors, with exponential backoff + full jitter
      for (let retry = 0; retry < 2 && attemptNo < maxAttempts; retry++) {
        attemptNo++;
        const t0 = clock().getTime();
        const remaining = deadline - t0;
        if (remaining <= 0) return { ok: false, code: 'deadline_exceeded', attempts: attemptNo - 1, rejected: lastRejected, sawAmbiguous };
        const ac = new AbortController();
        const timer = setTimeout(() => ac.abort(), Math.min(p.perAttemptTimeoutMs ?? 10_000, remaining));
        const rec = (status: string, extra: { res?: CompletionResult; reason?: string; costUsd?: number | null; basis?: CostBasis } = {}) => {
          const res = extra.res;
          let costUsd = extra.costUsd ?? null; let basis: CostBasis = extra.basis ?? 'unknown';
          if (res) {
            if (res.costUsd !== null) { costUsd = res.costUsd; basis = 'confirmed'; }
            else if (model.tier !== 'paid') { costUsd = 0; basis = 'estimated'; }
            else if (res.inputTokens !== null && res.outputTokens !== null && model.priceInPerM !== null && model.priceOutPerM !== null) {
              costUsd = (res.inputTokens * model.priceInPerM + res.outputTokens * model.priceOutPerM) / 1e6; basis = 'estimated';
            }
          }
          d.store.recordAttempt({ requestId: p.requestId, userId: p.userId, attemptNo, provider: model.provider, model: model.id, task: p.task,
            inputTokens: res?.inputTokens ?? null, outputTokens: res?.outputTokens ?? null, costUsd, costBasis: basis,
            latencyMs: clock().getTime() - t0, status, reason: extra.reason }, clock());
        };
        try {
          const res = await adapter.complete(model, p.request, { signal: ac.signal });
          clearTimeout(timer);
          const v = p.validate(res.text);
          if (v.ok) { rec('success', { res }); return { ok: true, value: v.value, provider: model.provider, model: model.id, tier: model.tier, attempts: attemptNo }; }
          rec('invalid_output', { res, reason: v.reason }); // tokens were spent even though output was unusable
          tried.add(key);
          break; // different model next; HTTP 200 != correct answer
        } catch (e) {
          clearTimeout(timer);
          const err = e instanceof ProviderError ? e : new ProviderError('network', e instanceof Error ? e.message : 'unknown');
          if (err.kind === 'ambiguous_timeout' || err.kind === 'timeout') {
            // Request may have been completed (and billed) by the provider even though we saw no response.
            sawAmbiguous = true;
            const worst = model.tier === 'paid' ? worstCaseCostUsd(model, p.route.inputTokensEstimate, p.route.maxOutputTokens) : 0;
            rec('ambiguous_timeout', { reason: err.message, costUsd: worst, basis: worst === null ? 'unknown' : 'ambiguous_estimate' });
            tried.add(key); break;
          }
          rec(err.kind === 'rate_limit' ? 'rate_limited' : err.kind === 'auth' ? 'auth_error' : err.kind === 'server' ? 'server_error' : err.kind, { reason: err.message });
          if (err.kind === 'rate_limit') { d.health.modelCooldownUntil.set(key, clock().getTime() + (err.retryAfterMs ?? cooldown)); tried.add(key); break; }
          if (err.kind === 'auth') { d.health.providerDisabledUntil.set(model.provider, clock().getTime() + 10 * 60_000); tried.add(key); break; }
          if (err.kind === 'unsupported' || err.kind === 'bad_request') { d.health.modelCooldownUntil.set(key, clock().getTime() + 10 * 60_000); tried.add(key); break; }
          // transient (server/network): back off with jitter, retry once on same model, then move on
          if (retry === 0) { await sleep(Math.floor(rng() * Math.min(2000, 250 * 2 ** attemptNo))); continue; }
          d.health.modelCooldownUntil.set(key, clock().getTime() + 15_000); tried.add(key); break;
        }
      }
    }
    return { ok: false, code: 'all_attempts_failed', attempts: attemptNo, rejected: lastRejected, sawAmbiguous };
  }
}
