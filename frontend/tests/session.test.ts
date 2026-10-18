import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGoTrueAuth, AuthFailure } from '../src/auth/gotrue.ts';
import { SessionManager } from '../src/auth/session.ts';
import type { Scheduler } from '../src/auth/session.ts';
import { bootMockAuth } from './helpers/mock-auth.ts';

const USERS = { 'a@example.com': { password: 'correct-horse', sub: 'user-a' } };
function fakeSched() { const q: { fn: () => void; ms: number; id: number; live: boolean }[] = []; let id = 0;
  const s: Scheduler = { set: (fn, ms) => { const e = { fn, ms, id: ++id, live: true }; q.push(e); return e; }, clear: (h) => { (h as { live: boolean }).live = false; } };
  return { s, q, fire: () => { const e = q.filter((x) => x.live).pop(); if (e) { e.live = false; e.fn(); } } }; }

test('sign-in/out against the mock auth server; wrong password and unknown user give the SAME generic failure', async () => {
  const m = await bootMockAuth(USERS);
  try {
    const auth = createGoTrueAuth({ baseUrl: m.url, publicKey: 'public-anon-key' });
    const sm = new SessionManager(auth);
    await assert.rejects(sm.signIn('a@example.com', 'wrong'), (e: any) => e instanceof AuthFailure && e.kind === 'invalid_credentials');
    await assert.rejects(sm.signIn('nobody@example.com', 'wrong'), (e: any) => e instanceof AuthFailure && e.kind === 'invalid_credentials');
    assert.equal(sm.status, 'signedOut'); assert.equal(sm.getToken(), null);
    await sm.signIn('a@example.com', 'correct-horse');
    assert.equal(sm.status, 'signedIn'); assert.ok(sm.getToken()); assert.equal(sm.email, 'a@example.com');
    await sm.signOut();
    assert.equal(sm.getToken(), null); assert.ok(m.calls.includes('POST /auth/v1/logout'));
    await sm.recover('nobody@example.com');                       // never reveals whether an address exists
    await sm.signUp('new@example.com', 'x');
  } finally { await m.close(); }
});

test('network failure maps to a typed failure, not a fake session', async () => {
  const sm = new SessionManager(createGoTrueAuth({ baseUrl: 'http://127.0.0.1:1/auth/v1', publicKey: 'k' }));
  await assert.rejects(sm.signIn('a@example.com', 'x'), (e: any) => e.kind === 'network');
  assert.equal(sm.status, 'signedOut');
});

test('refresh is scheduled before expiry; on success the session continues, on rejection the user is signed out with a notice', async () => {
  const m = await bootMockAuth(USERS, { ttlSec: 3600 });
  try {
    const f = fakeSched(); let t = 1_000_000;
    const sm = new SessionManager(createGoTrueAuth({ baseUrl: m.url, publicKey: 'k', clock: () => t }), { scheduler: f.s, clock: () => t, refreshSkewMs: 60_000 });
    await sm.signIn('a@example.com', 'correct-horse');
    const first = f.q.filter((x) => x.live).pop()!; assert.equal(first.ms, 3_600_000 - 60_000);
    t += 3_540_000; f.fire(); await new Promise((r) => setTimeout(r, 50));
    assert.equal(sm.status, 'signedIn'); assert.ok(m.calls.some((c) => c.includes('refresh_token')));
    m.state.refreshOk = false; t += 3_540_000; f.fire(); await new Promise((r) => setTimeout(r, 50));
    assert.equal(sm.status, 'signedOut'); assert.match(sm.notice!, /expired/);
  } finally { await m.close(); }
});

test('expired access token is never handed out; expire() clears everything', async () => {
  const m = await bootMockAuth(USERS, { ttlSec: 10 });
  try {
    let t = 5_000_000; const sm = new SessionManager(createGoTrueAuth({ baseUrl: m.url, publicKey: 'k', clock: () => t }), { clock: () => t, scheduler: fakeSched().s });
    await sm.signIn('a@example.com', 'correct-horse'); assert.ok(sm.getToken());
    t += 11_000; assert.equal(sm.getToken(), null);
    sm.expire('bye'); assert.equal(sm.status, 'signedOut'); assert.equal(sm.notice, 'bye');
  } finally { await m.close(); }
});
