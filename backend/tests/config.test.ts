import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config/env.ts';

test('config fails fast on missing/short JWT secret and wildcard CORS', () => {
  assert.throws(() => loadConfig({}), /JWT_MODE must be set explicitly/);
  assert.throws(() => loadConfig({ JWT_MODE: 'hs256', SUPABASE_JWT_SECRET: 'short' }), /32 characters/);
  assert.throws(() => loadConfig({ JWT_MODE: 'hs256', SUPABASE_JWT_SECRET: 'x'.repeat(40), CORS_ORIGINS: '*' }), /not allowed/);
  assert.throws(() => loadConfig({ JWT_MODE: 'jwks' }), /JWKS_URL/);
  assert.throws(() => loadConfig({ JWT_MODE: 'jwks', JWKS_URL: 'https://p.example/jwks' }), /JWT_ISSUER/);
  assert.ok(loadConfig({ JWT_MODE: 'jwks', JWKS_URL: 'https://p.example/jwks', JWT_ISSUER: 'https://p.example/auth/v1', CORS_ORIGINS: 'https://a.example', ADMIN_USER_IDS: 'a, b' }).app.adminUserIds!.length === 2);
});
test('config with no models/providers loads but warns that AI is disabled; providers missing keys are skipped', () => {
  const c = loadConfig({ JWT_MODE: 'hs256', SUPABASE_JWT_SECRET: 'x'.repeat(40), CORS_ORIGINS: 'https://app.example', AI_PROVIDERS: JSON.stringify([{ name: 'p', baseUrl: 'https://x.example/v1', apiKeyEnv: 'P_KEY' }]) });
  assert.equal(Object.keys(c.adapters).length, 0);
  assert.ok(c.warnings.some((w) => /MODELS_CONFIG/.test(w)) && c.warnings.some((w) => /P_KEY/.test(w)));
  const c2 = loadConfig({ JWT_MODE: 'hs256', SUPABASE_JWT_SECRET: 'x'.repeat(40), CORS_ORIGINS: 'https://app.example', P_KEY: 'k', AI_PROVIDERS: JSON.stringify([{ name: 'p', baseUrl: 'https://x.example/v1', apiKeyEnv: 'P_KEY' }]) });
  assert.ok(c2.adapters.p);
  assert.throws(() => loadConfig({ JWT_MODE: 'hs256', SUPABASE_JWT_SECRET: 'x'.repeat(40), AI_PROVIDERS: JSON.stringify([{ name: 'p', baseUrl: 'ftp://x' }]) }), /http\(s\)/);
});

test('APK pool and retention settings: sane defaults, strict integer validation, no way to configure a nonsensical value', () => {
  const base = { JWT_MODE: 'hs256', SUPABASE_JWT_SECRET: 'x'.repeat(40), CORS_ORIGINS: 'https://a.example' };
  const d = loadConfig(base);
  assert.deepEqual(d.apkPool, { maxConcurrent: 2, maxQueue: 8, timeoutMs: 10_000, memoryMb: 256 });
  assert.deepEqual(d.retention, { analysisDays: 90, attemptDays: 400 });
  assert.equal(loadConfig({ ...base, APK_MAX_CONCURRENT: '4', RETENTION_ANALYSIS_DAYS: '30' }).apkPool.maxConcurrent, 4);
  for (const bad of [{ APK_MAX_CONCURRENT: '0' }, { APK_TIMEOUT_MS: '5' }, { APK_MEMORY_MB: 'lots' }, { RETENTION_ANALYSIS_DAYS: '0' }, { RETENTION_ANALYSIS_DAYS: '1.5' }, { APK_MAX_QUEUE: '-1' }]) assert.throws(() => loadConfig({ ...base, ...bad }), /must be an integer/);
});
