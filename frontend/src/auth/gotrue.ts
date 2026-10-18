/**
 * Minimal REST client for a GoTrue-compatible auth server (Supabase Auth).
 *
 * VERIFICATION STATUS: exercised ONLY against a local mock server in tests/helpers/mock-auth.ts. The endpoint
 * paths / body shapes below were written from general knowledge of GoTrue and were NOT checked against current
 * Supabase documentation (no network when written). `baseUrl` must be the full auth base (e.g. ".../auth/v1")
 * taken from your project settings. The `publicKey` is the project's PUBLIC (anon/publishable) key: it identifies
 * the project, it is NOT authorization, and it must never be a service-role/secret key.
 */
export interface AuthSession { accessToken: string; refreshToken?: string; expiresAt: number; email?: string }
export type AuthFailureKind = 'invalid_credentials' | 'rate_limited' | 'network' | 'unavailable' | 'unknown';
export class AuthFailure extends Error {
  kind: AuthFailureKind;
  constructor(kind: AuthFailureKind) { super(kind); this.name = 'AuthFailure'; this.kind = kind; }
}
export interface AuthClient {
  signIn(email: string, password: string): Promise<AuthSession>;
  signUp(email: string, password: string): Promise<void>;
  recover(email: string): Promise<void>;
  refresh(refreshToken: string): Promise<AuthSession>;
  signOut(accessToken: string): Promise<void>;
}

export function createGoTrueAuth(o: { baseUrl: string; publicKey: string; fetchImpl?: typeof fetch; clock?: () => number }): AuthClient {
  const f = o.fetchImpl ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const base = o.baseUrl.replace(/\/+$/, ''); const now = o.clock ?? Date.now;
  async function call(path: string, body: unknown, bearer?: string): Promise<{ status: number; json: unknown }> {
    const ac = new AbortController(); const t = setTimeout(() => ac.abort(), 15_000);
    try {
      const r = await f(base + path, { method: 'POST', credentials: 'omit', signal: ac.signal, headers: { 'content-type': 'application/json', apikey: o.publicKey, ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) }, body: JSON.stringify(body) });
      let json: unknown = null; try { const t2 = await r.text(); json = t2 ? JSON.parse(t2) : null; } catch { /* non-JSON */ }
      return { status: r.status, json };
    } catch { throw new AuthFailure('network'); } finally { clearTimeout(t); }
  }
  const fail = (status: number): never => { throw new AuthFailure(status === 429 ? 'rate_limited' : status >= 500 ? 'unavailable' : status === 400 || status === 401 || status === 422 ? 'invalid_credentials' : 'unknown'); };
  const toSession = (j: unknown): AuthSession => {
    const x = j as { access_token?: unknown; refresh_token?: unknown; expires_in?: unknown; user?: { email?: unknown } } | null;
    if (!x || typeof x.access_token !== 'string' || typeof x.expires_in !== 'number') throw new AuthFailure('unknown');
    return { accessToken: x.access_token, refreshToken: typeof x.refresh_token === 'string' ? x.refresh_token : undefined, expiresAt: now() + x.expires_in * 1000, email: typeof x.user?.email === 'string' ? x.user.email : undefined };
  };
  return {
    async signIn(email, password) { const r = await call('/token?grant_type=password', { email, password }); return r.status === 200 ? toSession(r.json) : fail(r.status); },
    async refresh(refreshToken) { const r = await call('/token?grant_type=refresh_token', { refresh_token: refreshToken }); return r.status === 200 ? toSession(r.json) : fail(r.status); },
    async signUp(email, password) { const r = await call('/signup', { email, password }); if (r.status >= 300) fail(r.status); },
    async recover(email) { const r = await call('/recover', { email }); if (r.status >= 500 || r.status === 429) fail(r.status); /* 4xx swallowed: never reveal whether an address exists */ },
    async signOut(accessToken) { try { await call('/logout', {}, accessToken); } catch { /* best effort: local session is dropped regardless */ } },
  };
}
