/**
 * HS256 JWT verification (Supabase legacy-style shared-secret tokens).
 *
 * Only the verified `sub` is used as identity. Claims such as user_metadata /
 * role / plan inside the token are IGNORED for authorisation: user_metadata is
 * user-editable in Supabase and must never grant privileges (the prototype's
 * getUserRole() trusted it).
 *
 * NOT supported (documented gap): asymmetric signing keys / JWKS, which newer
 * Supabase projects may use — requires fetching public keys (no network here).
 */
import { createHmac, timingSafeEqual } from 'node:crypto';

export class AuthError extends Error {
  reason: string;
  constructor(reason: string) { super('unauthorized'); this.name = 'AuthError'; this.reason = reason; }
}

const b64u = (s: string) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

export function verifyJwt(token: string, o: { secret: string; audience?: string; issuer?: string; now?: Date; leewaySec?: number }): { sub: string } {
  if (typeof token !== 'string' || token.length > 4096) throw new AuthError('malformed');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) throw new AuthError('malformed');
  let header: any; let payload: any;
  try { header = JSON.parse(b64u(parts[0]).toString('utf8')); payload = JSON.parse(b64u(parts[1]).toString('utf8')); } catch { throw new AuthError('malformed'); }
  if (!header || header.alg !== 'HS256') throw new AuthError('alg_not_allowed'); // rejects "none", RS*, etc. — algorithm is pinned, never taken from the token
  const expected = createHmac('sha256', o.secret).update(`${parts[0]}.${parts[1]}`).digest();
  const given = b64u(parts[2]);
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw new AuthError('bad_signature');
  const now = Math.floor((o.now ?? new Date()).getTime() / 1000);
  const leeway = o.leewaySec ?? 30;
  if (typeof payload.exp !== 'number' || now > payload.exp + leeway) throw new AuthError('expired');
  if (typeof payload.nbf === 'number' && now + leeway < payload.nbf) throw new AuthError('not_yet_valid');
  if (o.audience) {
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(o.audience)) throw new AuthError('bad_audience');
  }
  if (o.issuer && payload.iss !== o.issuer) throw new AuthError('bad_issuer');
  if (typeof payload.sub !== 'string' || payload.sub.length < 1 || payload.sub.length > 128) throw new AuthError('no_subject');
  return { sub: payload.sub };
}

/** Test/dev helper to mint tokens; not used by request handling. */
export function signJwt(claims: Record<string, unknown>, secret: string, header: Record<string, unknown> = { alg: 'HS256', typ: 'JWT' }): string {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const body = `${enc(header)}.${enc(claims)}`;
  return `${body}.${createHmac('sha256', secret).update(body).digest('base64url')}`;
}
