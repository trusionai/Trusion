/**
 * Async token verifiers.
 *
 *  - hs256Verifier: explicit shared-secret mode (wraps jwt.ts). Deployment choice, must be configured on purpose.
 *  - jwksVerifier:  asymmetric mode (ES256 / RS256) using the issuer's JWKS.
 *
 * Security properties of jwksVerifier:
 *  - The accepted algorithm is derived from the KEY TYPE (EC P-256 -> ES256, RSA >=2048 -> RS256) and must equal
 *    the token's header alg. HS* / none / anything else is rejected, so "sign with the public key as an HMAC
 *    secret" confusion attacks cannot work.
 *  - Keys come ONLY from the operator-configured JWKS URL. `jku`, `x5u`, `jwk` headers in a token are ignored.
 *  - `kid` is required. Unknown kid triggers at most one refetch per cooldown (key rotation) — never a refetch per request.
 *  - JWKS fetch failure keeps serving cached keys for up to `maxStaleMs` (outage tolerance), then fails closed.
 *  - Issuer is REQUIRED; audience checked when configured; exp required; nbf honoured; sub required.
 *
 * VERIFICATION STATUS: tested offline with locally generated keys and a local JWKS server. NOT verified against a
 * real Supabase project: the JWKS URL and issuer values must be taken from your project's current settings.
 */
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { AuthError, verifyJwt } from './jwt.ts';

export type TokenVerifier = (token: string, now?: Date) => Promise<{ sub: string }>;

export function hs256Verifier(o: { secret: string; audience?: string; issuer?: string }): TokenVerifier {
  if (!o.secret || o.secret.length < 32) throw new Error('HS256 secret must be at least 32 characters');
  return async (token, now) => verifyJwt(token, { secret: o.secret, audience: o.audience, issuer: o.issuer, now });
}

interface Jwk { kty?: string; kid?: string; crv?: string; alg?: string; use?: string; n?: string; e?: string; x?: string; y?: string }
export type FetchJwks = (url: string) => Promise<{ keys: Jwk[] }>;

export function defaultFetchJwks(opts: { allowHttp?: boolean; timeoutMs?: number } = {}): FetchJwks {
  return async (url) => {
    if (!/^https:\/\//i.test(url) && !(opts.allowHttp && /^http:\/\//i.test(url))) throw new Error('JWKS URL must be https');
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), opts.timeoutMs ?? 3000);
    try {
      const r = await fetch(url, { signal: ac.signal, redirect: 'error', headers: { accept: 'application/json' } });
      if (!r.ok) throw new Error(`JWKS HTTP ${r.status}`);
      const text = await r.text();
      if (text.length > 100_000) throw new Error('JWKS too large');
      const j = JSON.parse(text);
      if (!j || !Array.isArray(j.keys)) throw new Error('JWKS malformed');
      return j;
    } finally { clearTimeout(t); }
  };
}

const b64u = (s: string) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

function algForKey(k: Jwk): 'ES256' | 'RS256' | null {
  if (k.kty === 'EC' && k.crv === 'P-256') return 'ES256';
  if (k.kty === 'RSA' && typeof k.n === 'string' && b64u(k.n).length >= 256) return 'RS256'; // >= 2048-bit modulus
  return null;
}

export function jwksVerifier(o: {
  jwksUrl: string; issuer: string; audience?: string; fetchJwks?: FetchJwks;
  cacheTtlMs?: number; unknownKidCooldownMs?: number; maxStaleMs?: number; leewaySec?: number; clock?: () => number;
}): TokenVerifier {
  if (!o.issuer) throw new Error('jwksVerifier requires an issuer');
  const fetchJwks = o.fetchJwks ?? defaultFetchJwks();
  const ttl = o.cacheTtlMs ?? 10 * 60_000;
  const cooldown = o.unknownKidCooldownMs ?? 60_000;
  const maxStale = o.maxStaleMs ?? 24 * 3600_000;
  const clock = o.clock ?? Date.now;
  let keys = new Map<string, { jwk: Jwk; alg: 'ES256' | 'RS256'; pub: ReturnType<typeof createPublicKey> }>();
  let fetchedAt = 0; let lastAttempt = 0; let inflight: Promise<void> | null = null;

  const refresh = (): Promise<void> => {
    if (inflight) return inflight;
    lastAttempt = clock();
    inflight = (async () => {
      try {
        const set = await fetchJwks(o.jwksUrl);
        const next = new Map<string, { jwk: Jwk; alg: 'ES256' | 'RS256'; pub: ReturnType<typeof createPublicKey> }>();
        for (const jwk of set.keys) {
          if (typeof jwk.kid !== 'string' || (jwk.use && jwk.use !== 'sig')) continue;
          const alg = algForKey(jwk);
          if (!alg || (jwk.alg && jwk.alg !== alg)) continue;
          try { next.set(jwk.kid, { jwk, alg, pub: createPublicKey({ key: jwk as never, format: 'jwk' }) }); } catch { /* skip bad key */ }
        }
        if (next.size === 0) throw new Error('JWKS contained no usable keys');
        keys = next; fetchedAt = clock();
      } catch { /* keep previous keys; staleness enforced at use */ } finally { inflight = null; }
    })();
    return inflight;
  };

  return async (token, nowDate) => {
    if (typeof token !== 'string' || token.length > 4096) throw new AuthError('malformed');
    const parts = token.split('.');
    if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) throw new AuthError('malformed');
    let header: any; let payload: any;
    try { header = JSON.parse(b64u(parts[0]).toString('utf8')); payload = JSON.parse(b64u(parts[1]).toString('utf8')); } catch { throw new AuthError('malformed'); }
    if (!header || typeof header.kid !== 'string' || (header.alg !== 'ES256' && header.alg !== 'RS256')) throw new AuthError('alg_not_allowed');

    if (clock() - fetchedAt > ttl && clock() - lastAttempt > 5_000) await refresh();
    let entry = keys.get(header.kid);
    if (!entry && clock() - lastAttempt > cooldown) { await refresh(); entry = keys.get(header.kid); } // rotation
    if (!entry) throw new AuthError('unknown_kid');
    if (fetchedAt && clock() - fetchedAt > maxStale) throw new AuthError('keys_stale');
    if (entry.alg !== header.alg) throw new AuthError('alg_key_mismatch');

    const data = Buffer.from(`${parts[0]}.${parts[1]}`);
    const sig = b64u(parts[2]);
    let ok = false;
    try {
      ok = entry.alg === 'ES256'
        ? cryptoVerify('sha256', data, { key: entry.pub, dsaEncoding: 'ieee-p1363' }, sig)
        : cryptoVerify('RSA-SHA256', data, entry.pub, sig);
    } catch { ok = false; }
    if (!ok) throw new AuthError('bad_signature');

    const now = Math.floor((nowDate ?? new Date()).getTime() / 1000);
    const leeway = o.leewaySec ?? 30;
    if (payload.iss !== o.issuer) throw new AuthError('bad_issuer');
    if (typeof payload.exp !== 'number' || now > payload.exp + leeway) throw new AuthError('expired');
    if (typeof payload.nbf === 'number' && now + leeway < payload.nbf) throw new AuthError('not_yet_valid');
    if (o.audience) {
      const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!aud.includes(o.audience)) throw new AuthError('bad_audience');
    }
    if (typeof payload.sub !== 'string' || payload.sub.length < 1 || payload.sub.length > 128) throw new AuthError('no_subject');
    return { sub: payload.sub };
  };
}
