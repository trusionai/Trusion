import { useState } from 'react';
import type { ChangeEvent, FormEvent } from 'react';
import { AuthFailure } from '../auth/gotrue.ts';
import { useApp } from '../AppContext.tsx';
import { Banner } from '../components/Common.tsx';

const MSG: Record<string, string> = { invalid_credentials: 'Email or password is incorrect.', rate_limited: 'Too many attempts. Please wait and try again.', network: 'Cannot reach the sign-in service.', unavailable: 'The sign-in service is unavailable right now.', unknown: 'Sign-in failed.' };

export function Login() {
  const { sm } = useApp();
  const [mode, setMode] = useState<'in' | 'up' | 'reset'>('in');
  const [email, setEmail] = useState(''); const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false); const [err, setErr] = useState<string | null>(null); const [info, setInfo] = useState<string | null>(null);
  async function onSubmit(e: FormEvent) {
    e.preventDefault(); if (busy) return; setBusy(true); setErr(null); setInfo(null);
    try {
      if (mode === 'in') await sm.signIn(email.trim(), password);
      else if (mode === 'up') { await sm.signUp(email.trim(), password); setInfo('If sign-up is allowed for this address, you will receive a confirmation email. Then sign in.'); setMode('in'); }
      else { await sm.recover(email.trim()); setInfo('If an account exists for that address, a reset email has been sent.'); setMode('in'); }
      setPassword('');
    } catch (x) { setErr(MSG[x instanceof AuthFailure ? x.kind : 'unknown']); } finally { setBusy(false); }
  }
  return (
    <main className="auth">
      <h1>TRUSION</h1>
      <p className="lead">Sign in to analyse messages, links, files and screenshots. Analyses run on the server under your account; there is no guest mode.</p>
      {sm.notice ? <Banner tone="warn">{sm.notice}</Banner> : null}
      {info ? <Banner tone="info">{info}</Banner> : null}
      {err ? <Banner tone="bad" title="Could not continue">{err}</Banner> : null}
      <div role="tablist" className="tabs" aria-label="Account action">
        {(['in', 'up', 'reset'] as const).map((m) => <button key={m} type="button" role="tab" aria-selected={mode === m} className={mode === m ? 'tab on' : 'tab'} onClick={() => { setMode(m); setErr(null); }}>{m === 'in' ? 'Sign in' : m === 'up' ? 'Create account' : 'Reset password'}</button>)}
      </div>
      <form onSubmit={onSubmit} noValidate>
        <label htmlFor="email">Email</label>
        <input id="email" name="email" type="email" autoComplete="email" required value={email} onChange={(e: ChangeEvent<HTMLInputElement>) => setEmail(e.target.value)} />
        {mode !== 'reset' ? <><label htmlFor="password">Password</label>
          <input id="password" name="password" type="password" autoComplete={mode === 'in' ? 'current-password' : 'new-password'} required minLength={8} value={password} onChange={(e: ChangeEvent<HTMLInputElement>) => setPassword(e.target.value)} /></> : null}
        <button type="submit" className="btn primary" disabled={busy || !email || (mode !== 'reset' && !password)}>{busy ? 'Please wait…' : mode === 'in' ? 'Sign in' : mode === 'up' ? 'Create account' : 'Send reset email'}</button>
      </form>
    </main>
  );
}
