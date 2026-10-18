import { useEffect, useRef, useState } from 'react';
import { useApp } from './AppContext.tsx';
import { Login } from './pages/Login.tsx';
import { Dashboard } from './pages/Dashboard.tsx';
import { ApkPage, MessagePage, ScreenshotPage, UrlPage } from './pages/Analyze.tsx';
import { AccountPage, AdminPage, HistoryPage, UnavailablePage } from './pages/Other.tsx';
import { parseHash } from './route.ts';
import { FEATURES, statusLabel } from './features/registry.ts';
import { useLoad } from './state/hooks.ts';

function useHash(): string { const [h, setH] = useState(() => window.location.hash); useEffect(() => { const f = () => setH(window.location.hash); window.addEventListener('hashchange', f); return () => window.removeEventListener('hashchange', f); }, []); return h; }

export function App() {
  const { status, api, sm } = useApp();
  const hash = useHash();
  const firstRender = useRef(true);
  useEffect(() => {                                    // after navigation, move focus to the content so keyboard/screen-reader users continue there
    if (firstRender.current) { firstRender.current = false; return; }
    document.getElementById('main')?.focus();
  }, [hash]);
  const me = useLoad(() => (status === 'signedIn' ? api.me() : Promise.resolve(null)), [status]);
  if (status !== 'signedIn') return <Login />;
  const route = parseHash(hash);
  const isAdmin = me.data?.isAdmin === true;                       // display hint only; /v1/admin/* is enforced by the server
  const nav: [string, string][] = [['#/dashboard', 'Dashboard'], ['#/message', 'Messages'], ['#/url', 'Links'], ['#/apk', 'APK files'], ['#/screenshot', 'Screenshots'], ['#/history', 'History'], ['#/account', 'Account'], ...(isAdmin ? [['#/admin', 'Admin'] as [string, string]] : [])];
  return (
    <div className="shell">
      <button type="button" className="skip" onClick={() => document.getElementById('main')?.focus()}>Skip to main content</button>
      <header className="top"><span className="brand">TRUSION</span><span className="muted who">{sm.email}</span></header>
      <nav aria-label="Main" className="nav">
        <ul>{nav.map(([h, l]) => <li key={h}><a href={h} aria-current={hash === h || (h === '#/dashboard' && (hash === '' || hash === '#/')) ? 'page' : undefined}>{l}</a></li>)}</ul>
        <details className="more"><summary>Not available yet</summary>
          <ul>{FEATURES.filter((f) => f.status !== 'available').map((f) => <li key={f.id}><a href={`#/n/${f.id}`}>{f.label}</a> <small className="muted">{statusLabel(f.status)}</small></li>)}</ul></details>
      </nav>
      <main className="main" id="main" tabIndex={-1}>
        {route.id === 'dashboard' ? <Dashboard /> : route.id === 'message' ? <MessagePage /> : route.id === 'url' ? <UrlPage /> : route.id === 'apk' ? <ApkPage />
          : route.id === 'screenshot' ? <ScreenshotPage /> : route.id === 'history' ? <HistoryPage id={route.param} /> : route.id === 'account' ? <AccountPage />
          : route.id === 'admin' ? <AdminPage /> : <UnavailablePage id={route.param} />}
      </main>
    </div>
  );
}
