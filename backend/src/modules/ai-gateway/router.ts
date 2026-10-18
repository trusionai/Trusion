/**
 * Pure candidate selection. TRUSION (not any upstream router) decides which
 * models may be used for a request. Every rejection carries a reason so routing
 * is explainable and testable.
 */
import type { Capability, ModelSpec } from './types.ts';
import type { PlanConfig } from '../entitlements/plans.ts';

export interface RouteContext {
  plan: PlanConfig;
  needs: Capability[];
  inputTokensEstimate: number;
  maxOutputTokens: number;
  /** User/policy permission to send content to EXTERNAL providers. */
  allowExternal: boolean;
  spentThisMonthUsd: number;
  now: Date;
  /** Paid prices older than this are treated as stale and the model is excluded. */
  priceMaxAgeDays?: number;
}

export interface Health {
  /** key = provider|model */
  modelCooldownUntil: Map<string, number>;
  providerDisabledUntil: Map<string, number>;
}
export const newHealth = (): Health => ({ modelCooldownUntil: new Map(), providerDisabledUntil: new Map() });

export function worstCaseCostUsd(m: ModelSpec, inTok: number, outTok: number): number | null {
  if (m.priceInPerM === null || m.priceOutPerM === null) return null;
  return (inTok * m.priceInPerM + outTok * m.priceOutPerM) / 1_000_000;
}

export interface Selection { candidates: ModelSpec[]; rejected: { model: string; provider: string; reason: string }[] }

export function selectCandidates(registry: ModelSpec[], ctx: RouteContext, health: Health): Selection {
  const rejected: Selection['rejected'] = [];
  const ok: { m: ModelSpec; cost: number }[] = [];
  const maxAgeMs = (ctx.priceMaxAgeDays ?? 30) * 86_400_000;
  for (const m of registry) {
    const rej = (reason: string) => rejected.push({ model: m.id, provider: m.provider, reason });
    if (!m.enabled) { rej('disabled'); continue; }
    if (!ctx.needs.every((c) => m.capabilities.includes(c))) { rej('missing_capability'); continue; }
    if (ctx.inputTokensEstimate + ctx.maxOutputTokens > m.maxContextTokens || ctx.maxOutputTokens > m.maxOutputTokens) { rej('context_too_small'); continue; }
    if (!ctx.allowExternal && m.dataPolicy !== 'local') { rej('external_processing_not_permitted'); continue; }
    const key = `${m.provider}|${m.id}`;
    if ((health.providerDisabledUntil.get(m.provider) ?? 0) > ctx.now.getTime()) { rej('provider_unavailable'); continue; }
    if ((health.modelCooldownUntil.get(key) ?? 0) > ctx.now.getTime()) { rej('cooling_down'); continue; }
    let cost = 0;
    if (m.tier === 'paid') {
      if (!ctx.plan.allowPaidInference) { rej('plan_forbids_paid_inference'); continue; }
      const c = worstCaseCostUsd(m, ctx.inputTokensEstimate, ctx.maxOutputTokens);
      if (c === null) { rej('price_unknown'); continue; }
      if (!m.priceVerifiedAt || ctx.now.getTime() - Date.parse(m.priceVerifiedAt) > maxAgeMs) { rej('price_unverified_or_stale'); continue; }
      if (c > ctx.plan.maxRequestCostUsd) { rej('exceeds_request_cost_cap'); continue; }
      if (ctx.spentThisMonthUsd + c > ctx.plan.monthlySpendUsd) { rej('monthly_budget_exhausted'); continue; }
      cost = c;
    }
    ok.push({ m, cost });
  }
  const tierOrder = { free: 0, local: 0, paid: 1 } as const;
  ok.sort((a, b) => tierOrder[a.m.tier] - tierOrder[b.m.tier] || a.m.qualityRank - b.m.qualityRank || a.cost - b.cost);
  return { candidates: ok.map((x) => x.m), rejected };
}
