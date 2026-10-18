import { useState } from 'react';
import { useApp } from '../AppContext.tsx';
import { Badge, Banner, ErrorBox, Loading, Page } from '../components/Common.tsx';
import { ResultView } from '../components/ResultView.tsx';
import { useLoad } from '../state/hooks.ts';
import { findFeature, statusLabel } from '../features/registry.ts';

export function HistoryPage({ id }: { id?: string }) {
  const { api } = useApp();
  const list = useLoad(() => (id ? Promise.resolve(null) : api.history()), [id]);
  const one = useLoad(() => (id ? api.analysis(id) : Promise.resolve(null)), [id]);
  if (id) {
    if (one.loading) return <Page title="Analysis record"><Loading /></Page>;
    if (one.error || !one.data) return <Page title="Analysis record"><ErrorBox error={one.error} onRetry={one.reload} /><p><a href="#/history">Back to history</a></p></Page>;
    return <Page title="Analysis record" lead={`Stored result (${one.data.kind}).`}><ResultView vm={one.data.vm} id={one.data.id} /><p><a href="#/history">Back to history</a></p></Page>;
  }
  if (list.loading) return <Page title="History"><Loading /></Page>;
  if (list.error || !list.data) return <Page title="History"><ErrorBox error={list.error} onRetry={list.reload} /></Page>;
  return (
    <Page title="History" lead="Only your own analyses are listed. The full text of messages and uploaded files is not stored.">
      {list.data.length === 0 ? <p className="muted">No analyses yet.</p> : (
        <table className="table"><thead><tr><th>Type</th><th>Status</th><th>When (UTC)</th></tr></thead>
          <tbody>{list.data.map((h) => <tr key={h.id}><td><a href={`#/history/${encodeURIComponent(h.id)}`}>{h.kind}</a></td><td>{h.status}</td><td>{h.createdAt}</td></tr>)}</tbody></table>
      )}
    </Page>
  );
}

export function AccountPage() {
  const { api, sm } = useApp();
  const d = useLoad(async () => { const [me, usage] = await Promise.all([api.me(), api.usage()]); return { me, usage }; }, []);
  const [confirm, setConfirm] = useState(false); const [msg, setMsg] = useState<string | null>(null); const [err, setErr] = useState<unknown>(null);
  async function del() { setErr(null); try { await api.deleteMyData(); setMsg('Your analysis history and usage records were deleted.'); setConfirm(false); d.reload(); } catch (e) { setErr(e); } }
  if (d.loading) return <Page title="Account"><Loading /></Page>;
  if (d.error || !d.data) return <Page title="Account"><ErrorBox error={d.error} onRetry={d.reload} /></Page>;
  const { me, usage } = d.data;
  return (
    <Page title="Account">
      <dl className="kv"><dt>Signed in as</dt><dd>{sm.email ?? 'unknown'}</dd><dt>Account id</dt><dd><code>{me.userId}</code></dd>
        <dt>Plan</dt><dd>{me.plan.id} {me.plan.provisional ? <Badge tone="warn">provisional limits</Badge> : null}</dd>
        <dt>Allowance</dt><dd>{usage.usage.used + usage.usage.reserved} / {usage.usage.limit} units ({usage.usage.period}, UTC)</dd></dl>
      <Banner tone="info" title="Billing is not available yet">Plan changes and payments are not implemented in this release, so there is no upgrade button. Your plan is set by the server only.</Banner>
      <section className="card"><h2>Your data</h2>
        {msg ? <Banner tone="info">{msg}</Banner> : null}{err ? <ErrorBox error={err} /> : null}
        {!confirm ? <button type="button" className="btn" onClick={() => setConfirm(true)}>Delete my analysis history</button>
          : <div><p>This permanently deletes your stored analyses, usage records and plan record on the server. It cannot be undone.</p><button type="button" className="btn danger" onClick={() => void del()}>Yes, delete</button> <button type="button" className="btn" onClick={() => setConfirm(false)}>Cancel</button></div>}
      </section>
      <p><button type="button" className="btn" onClick={() => void sm.signOut()}>Sign out</button></p>
    </Page>
  );
}

export function AdminPage() {
  const { api } = useApp(); const d = useLoad(() => api.adminOverview(), []);
  if (d.loading) return <Page title="Administration"><Loading /></Page>;
  if (d.error || !d.data) return <Page title="Administration"><ErrorBox error={d.error} /></Page>;
  return (
    <Page title="Administration" lead="Read-only overview. Access is enforced by the server; this page only displays what it returns.">
      <table className="table"><thead><tr><th>Provider</th><th>Model</th><th>Tier</th><th>Enabled</th><th>Adapter</th><th>Price verified</th></tr></thead>
        <tbody>{d.data.models.map((m, n) => <tr key={n}><td>{m.provider}</td><td>{m.model}</td><td>{m.tier}</td><td>{String(m.enabled)}</td><td>{m.adapterConfigured ? 'configured' : 'missing'}</td><td>{m.priceVerifiedAt ?? 'never'}</td></tr>)}</tbody></table>
      {d.data.models.length === 0 ? <p className="muted">No AI models are configured.</p> : null}
      <p className="muted">Models cooling down: {d.data.cooldowns}. Providers disabled: {d.data.disabledProviders.join(', ') || 'none'}.</p>
    </Page>
  );
}

export function UnavailablePage({ id }: { id?: string }) {
  const f = findFeature(id);
  if (!f) return <Page title="Not found"><p>That feature does not exist.</p><p><a href="#/dashboard">Back to dashboard</a></p></Page>;
  return (
    <Page title={f.label}>
      <Banner tone="warn" title={`Status: ${statusLabel(f.status)}`}><p>{f.reason}</p></Banner>
      <p className="muted">This feature has no run button on purpose. Original prototype section: <code>{f.originalView}</code>.</p>
      <p><a href="#/dashboard">Back to dashboard</a></p>
    </Page>
  );
}
