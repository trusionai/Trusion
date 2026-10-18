import { useApp } from '../AppContext.tsx';
import { Badge, ErrorBox, Loading, Page } from '../components/Common.tsx';
import { useLoad } from '../state/hooks.ts';
import { FEATURES } from '../features/registry.ts';

export function Dashboard() {
  const { api } = useApp();
  const d = useLoad(async () => { const [usage, caps, hist] = await Promise.all([api.usage(), api.capabilities(), api.history()]); return { usage, caps, hist }; }, []);
  if (d.loading) return <Page title="Dashboard"><Loading /></Page>;
  if (d.error || !d.data) return <Page title="Dashboard"><ErrorBox error={d.error} onRetry={d.reload} /></Page>;
  const { usage, caps, hist } = d.data; const pct = usage.usage.limit ? Math.min(100, Math.round(((usage.usage.used + usage.usage.reserved) / usage.usage.limit) * 100)) : 0;
  return (
    <Page title="Dashboard" lead="Your plan and allowance come from the server. This page only displays them.">
      <section className="card" aria-label="Plan and usage">
        <h2>Plan: {usage.plan.id}{usage.plan.provisional ? <> <Badge tone="warn">provisional limits</Badge></> : null}</h2>
        <p>{usage.usage.used + usage.usage.reserved} of {usage.usage.limit} analysis units used in {usage.usage.period} (UTC).</p>
        <progress max={100} value={pct} aria-label="Allowance used">{pct}%</progress>
      </section>
      <section className="card" aria-label="What is available"><h2>Capabilities on this server</h2>
        <ul className="plain">
          {FEATURES.filter((f) => f.status === 'available').map((f) => { const c = f.capability ? caps.features[f.capability] : { state: 'available' as const }; return <li key={f.id}>{c?.state === 'available' ? <a href={f.route}>{f.label}</a> : <span>{f.label}</span>} {c?.state === 'available' ? <Badge tone="good">available</Badge> : <Badge tone="bad">unavailable</Badge>}</li>; })}
          <li>AI interpretation {caps.features.ai_interpretation?.state === 'available' ? <Badge tone="good">available (needs your consent per request)</Badge> : <Badge tone="neutral">not configured — rule-based analysis only</Badge>}</li>
        </ul>
      </section>
      <section className="card" aria-label="Recent analyses"><h2>Recent analyses</h2>
        {hist.length === 0 ? <p className="muted">Nothing yet.</p> : <ul className="plain">{hist.slice(0, 5).map((h) => <li key={h.id}><a href={`#/history/${encodeURIComponent(h.id)}`}>{h.kind}</a> <span className="muted">{h.status} · {h.createdAt}</span></li>)}</ul>}
      </section>
    </Page>
  );
}
