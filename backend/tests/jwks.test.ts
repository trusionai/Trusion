import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { generateKeyPairSync, sign, createHmac } from 'node:crypto';
import { jwksVerifier, hs256Verifier, defaultFetchJwks } from '../src/modules/auth/verifier.ts';

const ISS = 'https://project.example/auth/v1';
const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
const nowS = () => Math.floor(Date.now() / 1000);

function ecKey(kid: string) {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { kid, jwk: { ...(publicKey.export({ format: 'jwk' }) as object), kid, use: 'sig', alg: 'ES256' }, priv: privateKey };
}
function rsaKey(kid: string, bits = 2048) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: bits });
  return { kid, jwk: { ...(publicKey.export({ format: 'jwk' }) as object), kid, use: 'sig' }, priv: privateKey };
}
const claims = (o: Record<string, unknown> = {}) => ({ sub: 'user-1', iss: ISS, aud: 'authenticated', exp: nowS() + 300, ...o });
function signEs(k: ReturnType<typeof ecKey>, c: object, header: object = {}) {
  const h = enc({ alg: 'ES256', typ: 'JWT', kid: k.kid, ...header }); const p = enc(c);
  return `${h}.${p}.${sign('sha256', Buffer.from(`${h}.${p}`), { key: k.priv, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}
function signRs(k: ReturnType<typeof rsaKey>, c: object, header: object = {}) {
  const h = enc({ alg: 'RS256', typ: 'JWT', kid: k.kid, ...header }); const p = enc(c);
  return `${h}.${p}.${sign('RSA-SHA256', Buffer.from(`${h}.${p}`), k.priv).toString('base64url')}`;
}
function verifierWith(getKeys: () => object[], extra: Record<string, unknown> = {}) {
  const calls: string[] = [];
  const v = jwksVerifier({ jwksUrl: 'https://project.example/auth/v1/.well-known/jwks.json', issuer: ISS, audience: 'authenticated',
    fetchJwks: async (u) => { calls.push(u); return { keys: getKeys() as never }; }, ...extra });
  return { v, calls };
}
const reason = async (p: Promise<unknown>) => { try { await p; return 'ACCEPTED'; } catch (e: any) { return e.reason ?? e.message; } };

test('ES256 and RS256 tokens verify; subject is returned', async () => {
  const e = ecKey('e1'), r = rsaKey('r1');
  const { v } = verifierWith(() => [e.jwk, r.jwk]);
  assert.deepEqual(await v(signEs(e, claims())), { sub: 'user-1' });
  assert.deepEqual(await v(signRs(r, claims({ sub: 'u2' }))), { sub: 'u2' });
});

test('invalid signature, wrong issuer/audience, expired, not-yet-valid, missing sub/kid are all rejected', async () => {
  const e = ecKey('e1'); const other = ecKey('e1');                      // same kid, different private key
  const { v } = verifierWith(() => [e.jwk]);
  assert.equal(await reason(v(signEs(other, claims()))), 'bad_signature');
  assert.equal(await reason(v(signEs(e, claims({ iss: 'https://evil.example/auth/v1' })))), 'bad_issuer');
  assert.equal(await reason(v(signEs(e, claims({ iss: undefined })))), 'bad_issuer');
  assert.equal(await reason(v(signEs(e, claims({ aud: 'other' })))), 'bad_audience');
  assert.equal(await reason(v(signEs(e, claims({ exp: nowS() - 3600 })))), 'expired');
  assert.equal(await reason(v(signEs(e, claims({ exp: undefined })))), 'expired');
  assert.equal(await reason(v(signEs(e, claims({ nbf: nowS() + 3600 })))), 'not_yet_valid');
  assert.equal(await reason(v(signEs(e, claims({ sub: '' })))), 'no_subject');
  assert.equal(await reason(v(signEs(e, claims(), { kid: undefined }))), 'alg_not_allowed');
});

test('ALGORITHM CONFUSION: HS256 signed with the public key material, alg=none, HS512 and RS256-header-on-EC-key are rejected', async () => {
  const e = ecKey('e1');
  const { v } = verifierWith(() => [e.jwk]);
  const pubAsSecret = JSON.stringify(e.jwk);
  const h = enc({ alg: 'HS256', typ: 'JWT', kid: 'e1' }), p = enc(claims());
  const hs = `${h}.${p}.${createHmac('sha256', pubAsSecret).update(`${h}.${p}`).digest('base64url')}`;
  assert.equal(await reason(v(hs)), 'alg_not_allowed');
  assert.equal(await reason(v(`${enc({ alg: 'none', kid: 'e1' })}.${p}.`)), 'malformed');
  assert.equal(await reason(v(`${enc({ alg: 'none', kid: 'e1' })}.${p}.AAAA`)), 'alg_not_allowed');
  const hs512 = `${enc({ alg: 'HS512', kid: 'e1' })}.${p}.AAAA`;
  assert.equal(await reason(v(hs512)), 'alg_not_allowed');
  const mismatch = `${enc({ alg: 'RS256', typ: 'JWT', kid: 'e1' })}.${p}.AAAA`;     // header claims RSA, key is EC
  assert.equal(await reason(v(mismatch)), 'alg_key_mismatch');
});

test('jku / x5u / embedded jwk headers are ignored: keys only ever come from the configured URL', async () => {
  const e = ecKey('e1'); const attacker = ecKey('e1');
  const { v, calls } = verifierWith(() => [e.jwk]);
  const t = signEs(attacker, claims(), { jku: 'https://attacker.example/jwks.json', jwk: attacker.jwk });
  assert.equal(await reason(v(t)), 'bad_signature');
  assert.ok(calls.every((u) => u === 'https://project.example/auth/v1/.well-known/jwks.json'));
});

test('key rotation: unknown kid triggers ONE refetch, then is accepted; repeated unknown kids do not hammer the JWKS endpoint', async () => {
  const k1 = ecKey('k1'), k2 = ecKey('k2'), ghost = ecKey('ghost');
  let keys: object[] = [k1.jwk]; let t = 1_000_000;
  const { v, calls } = verifierWith(() => keys, { clock: () => t, unknownKidCooldownMs: 60_000 });
  assert.equal(await reason(v(signEs(k1, claims()))), 'ACCEPTED');
  const before = calls.length;
  keys = [k1.jwk, k2.jwk]; t += 61_000;                                    // provider rotated; cooldown elapsed
  assert.equal(await reason(v(signEs(k2, claims()))), 'ACCEPTED');
  assert.equal(calls.length, before + 1);
  for (let i = 0; i < 20; i++) assert.equal(await reason(v(signEs(ghost, claims()))), 'unknown_kid');
  assert.ok(calls.length <= before + 2, `JWKS refetch storm: ${calls.length - before} fetches`);
});

test('JWKS outage: cached keys keep working (stale-if-error) until maxStale, then fail closed', async () => {
  const e = ecKey('e1'); let up = true; let t = 5_000_000;
  const v = jwksVerifier({ jwksUrl: 'https://p.example/jwks', issuer: ISS, audience: 'authenticated', clock: () => t, cacheTtlMs: 1000, maxStaleMs: 3_600_000,
    fetchJwks: async () => { if (!up) throw new Error('down'); return { keys: [e.jwk] as never }; } });
  assert.equal(await reason(v(signEs(e, claims()))), 'ACCEPTED');
  up = false; t += 60_000;
  assert.equal(await reason(v(signEs(e, claims()))), 'ACCEPTED', 'serves from cache during outage');
  t += 3_700_000;
  assert.equal(await reason(v(signEs(e, claims({ exp: Math.floor(t / 1000) + 300 })), new Date(t))), 'keys_stale', 'fails closed after maxStale');
});

test('weak RSA (1024-bit) and unsupported key types are not accepted', async () => {
  const weak = rsaKey('w1', 1024);
  const { v } = verifierWith(() => [weak.jwk, ecKey('x').jwk]);
  assert.equal(await reason(v(signRs(weak, claims()))), 'unknown_kid');
});

test('JWKS fetcher: https required unless explicitly allowed; real HTTP fetch works against a local JWKS server and caps size', async () => {
  await assert.rejects(defaultFetchJwks()('http://127.0.0.1:1/jwks'), /https/);
  const e = ecKey('e1'); let big = false;
  const srv = http.createServer((_q, r) => { r.setHeader('content-type', 'application/json'); r.end(big ? ' '.repeat(200_000) : JSON.stringify({ keys: [e.jwk] })); });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}/jwks`;
  try {
    const v = jwksVerifier({ jwksUrl: url, issuer: ISS, audience: 'authenticated', fetchJwks: defaultFetchJwks({ allowHttp: true }) });
    assert.equal(await reason(v(signEs(e, claims()))), 'ACCEPTED');
    big = true;
    await assert.rejects(defaultFetchJwks({ allowHttp: true })(url), /too large|JSON/);
  } finally { srv.close(); }
});

test('explicit HS256 mode: enforces issuer and audience when configured; short secrets refused', async () => {
  assert.throws(() => hs256Verifier({ secret: 'short' }), /32/);
  const secret = 'x'.repeat(40);
  const v = hs256Verifier({ secret, issuer: ISS, audience: 'authenticated' });
  const mk = (c: object) => { const h = enc({ alg: 'HS256', typ: 'JWT' }), p = enc(c); return `${h}.${p}.${createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url')}`; };
  assert.equal(await reason(v(mk(claims()))), 'ACCEPTED');
  assert.equal(await reason(v(mk(claims({ iss: 'https://evil' })))), 'bad_issuer');
  assert.equal(await reason(v(mk(claims({ aud: 'x' })))), 'bad_audience');
});
