import type { ReactNode } from 'react';
import { describeError } from '../api/errors.ts';
import type { Severity, Status } from '../api/types.ts';

export const STATUS_LABEL: Record<Status, string> = { completed: 'Completed', completed_with_limitations: 'Completed with limitations', inconclusive: 'Inconclusive', failed: 'Failed', requires_review: 'Requires human review' };
export const ASSESSMENT_LABEL: Record<string, string> = {
  high_risk: 'High-risk indicators found', suspicious: 'Suspicious indicators found',
  no_red_flags_found: 'No red flags found — this is NOT a guarantee of safety',
  conflicting_signals: 'Conflicting signals — needs human review', no_text_found: 'No readable text found',
};
export const SOURCE_LABEL: Record<string, string> = { heuristic: 'Rule-based', static_analysis: 'Static file analysis', model_inference: 'AI interpretation (can be wrong)', reputation_provider: 'Reputation provider' };

export function Badge(p: { tone: 'neutral' | 'good' | 'warn' | 'bad' | 'info'; children: ReactNode }) { return <span className={`badge badge-${p.tone}`}>{p.children}</span>; }
export const severityTone = (s: Severity) => (s === 'critical' || s === 'high' ? 'bad' : s === 'medium' ? 'warn' : s === 'low' ? 'info' : 'neutral') as 'bad' | 'warn' | 'info' | 'neutral';
export const statusTone = (s: Status) => (s === 'failed' ? 'bad' : s === 'requires_review' ? 'warn' : s === 'completed' ? 'good' : 'info') as 'bad' | 'warn' | 'good' | 'info';

export function Banner(p: { tone: 'info' | 'warn' | 'bad'; title?: string; children?: ReactNode }) {
  return <div className={`banner banner-${p.tone}`} role={p.tone === 'bad' ? 'alert' : 'note'}>{p.title ? <strong>{p.title}</strong> : null}{p.children ? <div>{p.children}</div> : null}</div>;
}
export function ErrorBox(p: { error: unknown; onRetry?: () => void }) {
  const d = describeError(p.error);
  return (
    <Banner tone="bad" title={d.title}>
      <p>{d.detail}</p>
      {d.requestId ? <p className="muted">Reference: <code>{d.requestId}</code></p> : null}
      {d.retryable && p.onRetry ? <button type="button" className="btn" onClick={p.onRetry}>Try again</button> : null}
    </Banner>
  );
}
export function Loading(p: { what?: string }) { return <p className="muted" role="status">Loading{p.what ? ` ${p.what}` : ''}…</p>; }
export function Page(p: { title: string; lead?: string; children: ReactNode }) { return <section className="page" aria-labelledby="page-title"><h1 id="page-title">{p.title}</h1>{p.lead ? <p className="lead">{p.lead}</p> : null}{p.children}</section>; }
