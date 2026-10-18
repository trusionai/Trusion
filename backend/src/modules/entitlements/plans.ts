/**
 * Plan configuration. This is the ONLY place plan limits live; the browser
 * never decides what a plan allows.
 *
 * !! ALL NUMBERS BELOW ARE PROVISIONAL PLACEHOLDERS !!
 * They are NOT derived from verified provider pricing or a cost model (no
 * network access when written). The owner must set final values after
 * computing expected cost per analysis. Marked via `provisional: true`.
 */
export type PlanId = 'free' | 'starter' | 'pro' | 'business';
export type TaskKind = 'sms' | 'url' | 'apk' | 'screenshot';

export interface PlanConfig {
  id: PlanId;
  provisional: boolean;
  /** Allowance, in "analysis units" per UTC calendar month. */
  monthlyUnits: number;
  maxApkBytes: number;
  maxImageBytes: number;
  maxTextChars: number;
  /** May the gateway escalate to a PAID model for this user? Free = never. */
  allowPaidInference: boolean;
  /** Hard cap on estimated worst-case provider cost for one request (USD). */
  maxRequestCostUsd: number;
  /** Monthly provider-spend ceiling attributable to this user (USD). */
  monthlySpendUsd: number;
  /** Per-user requests per minute (burst abuse control, separate from quota). */
  requestsPerMinute: number;
}

const MB = 1024 * 1024;

export const PLANS: Readonly<Record<PlanId, PlanConfig>> = Object.freeze({
  free:     { id: 'free',     provisional: true, monthlyUnits: 20, maxImageBytes: 5 * MB,   maxApkBytes: 20 * MB, maxTextChars: 4000,  allowPaidInference: false, maxRequestCostUsd: 0,     monthlySpendUsd: 0,   requestsPerMinute: 10 },
  starter:  { id: 'starter',  provisional: true, monthlyUnits: 300, maxImageBytes: 10 * MB,  maxApkBytes: 50 * MB, maxTextChars: 8000,  allowPaidInference: true,  maxRequestCostUsd: 0.01,  monthlySpendUsd: 1,   requestsPerMinute: 30 },
  pro:      { id: 'pro',      provisional: true, monthlyUnits: 1500, maxImageBytes: 15 * MB, maxApkBytes: 100 * MB, maxTextChars: 16000, allowPaidInference: true,  maxRequestCostUsd: 0.05,  monthlySpendUsd: 6,   requestsPerMinute: 60 },
  business: { id: 'business', provisional: true, monthlyUnits: 6000, maxImageBytes: 20 * MB, maxApkBytes: 150 * MB, maxTextChars: 32000, allowPaidInference: true,  maxRequestCostUsd: 0.10,  monthlySpendUsd: 30,  requestsPerMinute: 120 },
});

/** Units charged per task. APK static analysis is heavier than a text check. */
export const TASK_UNITS: Readonly<Record<TaskKind, number>> = Object.freeze({ sms: 1, url: 1, apk: 3, screenshot: 2 });

export function isPlanId(v: unknown): v is PlanId {
  return typeof v === 'string' && Object.prototype.hasOwnProperty.call(PLANS, v);
}
