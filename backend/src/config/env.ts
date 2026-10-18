import { readFileSync } from 'node:fs';
import { parseRegistry } from '../modules/ai-gateway/registry.ts';
import type { ModelSpec, ProviderAdapter } from '../modules/ai-gateway/types.ts';
import { OpenAICompatAdapter } from '../modules/ai-gateway/providers/openai-compat.ts';
import type { AppConfig } from '../http/app.ts';
import { hs256Verifier, jwksVerifier, defaultFetchJwks } from '../modules/auth/verifier.ts';
import type { TokenVerifier } from '../modules/auth/verifier.ts';

export interface Loaded { retention: { analysisDays: number; attemptDays: number }; apkPool: { maxConcurrent: number; maxQueue: number; timeoutMs: number; memoryMb: number }; port: number; dbPath: string; app: AppConfig; registry: ModelSpec[]; adapters: Record<string, ProviderAdapter>; warnings: string[] }

/**
 * Fails fast on unsafe configuration. Provider base URLs are NOT hard-coded here:
 * they must be supplied (and verified against the provider's current docs) by the operator.
 */
export function loadConfig(env: Record<string, string | undefined> = process.env): Loaded {
  const warnings: string[] = [];
  // Token verification mode is an explicit deployment decision — never guessed.
  const mode = env.JWT_MODE;
  const audience = env.JWT_AUDIENCE || 'authenticated';
  let verifier: TokenVerifier;
  if (mode === 'jwks') {
    if (!env.JWKS_URL) throw new Error('JWT_MODE=jwks requires JWKS_URL');
    if (!env.JWT_ISSUER) throw new Error('JWT_MODE=jwks requires JWT_ISSUER');
    verifier = jwksVerifier({ jwksUrl: env.JWKS_URL, issuer: env.JWT_ISSUER, audience, fetchJwks: defaultFetchJwks({ allowHttp: env.JWKS_ALLOW_HTTP === 'true' }) });
    if (env.JWKS_ALLOW_HTTP === 'true') warnings.push('JWKS_ALLOW_HTTP=true: development only; production must use https.');
  } else if (mode === 'hs256') {
    const secret = env.SUPABASE_JWT_SECRET ?? '';
    if (secret.length < 32) throw new Error('JWT_MODE=hs256 requires SUPABASE_JWT_SECRET of at least 32 characters');
    verifier = hs256Verifier({ secret, audience, issuer: env.JWT_ISSUER || undefined });
    if (!env.JWT_ISSUER) warnings.push('HS256 mode without JWT_ISSUER: issuer is not being checked.');
  } else throw new Error('JWT_MODE must be set explicitly to "jwks" or "hs256"');
  const cors = (env.CORS_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  if (cors.includes('*')) throw new Error('CORS_ORIGINS must list explicit origins; "*" is not allowed');
  if (cors.length === 0) warnings.push('CORS_ORIGINS is empty: browsers will be unable to call this API.');

  let registry: ModelSpec[] = [];
  if (env.MODELS_CONFIG) registry = parseRegistry(JSON.parse(readFileSync(env.MODELS_CONFIG, 'utf8')));
  else warnings.push('MODELS_CONFIG not set: no AI models are enabled; analyses will be heuristics-only.');

  const adapters: Record<string, ProviderAdapter> = {};
  if (env.AI_PROVIDERS) {
    const list = JSON.parse(env.AI_PROVIDERS) as { name: string; baseUrl: string; apiKeyEnv?: string }[];
    for (const p of list) {
      const key = p.apiKeyEnv ? env[p.apiKeyEnv] : undefined;
      if (p.apiKeyEnv && !key) { warnings.push(`Provider "${p.name}" skipped: env ${p.apiKeyEnv} is not set.`); continue; }
      if (!/^https?:\/\//.test(p.baseUrl)) throw new Error(`Provider "${p.name}": baseUrl must be http(s)`);
      adapters[p.name] = new OpenAICompatAdapter({ name: p.name, baseUrl: p.baseUrl, apiKey: key });
    }
  }
  for (const m of registry) if (m.enabled && !adapters[m.provider]) warnings.push(`Model "${m.id}" is enabled but provider "${m.provider}" has no adapter configured.`);

  const posInt = (name: string, dflt: number, min = 1, max = 1_000_000): number => {
    const raw = env[name]; if (raw === undefined || raw === '') return dflt;
    const n = Number(raw); if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${name} must be an integer between ${min} and ${max}`); return n;
  };
  const apkPool = { maxConcurrent: posInt('APK_MAX_CONCURRENT', 2, 1, 64), maxQueue: posInt('APK_MAX_QUEUE', 8, 0, 1000), timeoutMs: posInt('APK_TIMEOUT_MS', 10_000, 100, 120_000), memoryMb: posInt('APK_MEMORY_MB', 256, 16, 4096) };
  // Retention policy (PROVISIONAL defaults; the owner must set them from their privacy policy).
  const retention = { analysisDays: posInt('RETENTION_ANALYSIS_DAYS', 90, 1, 3650), attemptDays: posInt('RETENTION_ATTEMPT_DAYS', 400, 1, 3650) };
  return {
    retention, apkPool, port: Number(env.PORT ?? 8080), dbPath: env.DB_PATH ?? './data/trusion.db', registry, adapters, warnings,
    app: { verifier, adminUserIds: (env.ADMIN_USER_IDS ?? '').split(',').map((x) => x.trim()).filter(Boolean), corsOrigins: cors,
      maxJsonBytes: 64 * 1024, ipRequestsPerMinute: Number(env.IP_REQUESTS_PER_MINUTE ?? 120), trustProxy: env.TRUST_PROXY === 'true' },
  };
}
