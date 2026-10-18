/**
 * HTTP layer (node:http, no framework). The server is the authority for identity,
 * plan, quota and ownership; the browser's claims about any of these are ignored.
 */
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { HttpError } from '../shared/types.ts';
import { AuthError, verifyJwt } from '../modules/auth/jwt.ts';
import type { TokenVerifier } from '../modules/auth/verifier.ts';
import { Store } from '../modules/usage/store.ts';
import { Gateway } from '../modules/ai-gateway/gateway.ts';
import { PLANS, TASK_UNITS } from '../modules/entitlements/plans.ts';
import type { PlanConfig, TaskKind } from '../modules/entitlements/plans.ts';
import { analyzeSms } from '../modules/sms-analysis/analyze.ts';
import { analyzeUrl } from '../modules/url-scanner/url-analysis.ts';
import { normalizeUserUrl, traceRedirects, UrlRejected } from '../modules/url-scanner/ssrf-guard.ts';
import type { RedirectTrace } from '../modules/url-scanner/ssrf-guard.ts';
import { createApkPool, PoolError } from '../modules/file-analysis/apk-pool.ts';
import type { ApkRunner } from '../modules/file-analysis/apk-pool.ts';
import { sniffImage, ImageRejected } from '../modules/file-analysis/image.ts';
import { OcrError } from '../modules/file-analysis/ocr.ts';
import type { OcrEngine, OcrProbe } from '../modules/file-analysis/ocr.ts';
import { analyzeScreenshot } from '../modules/screenshot-analysis/analyze.ts';

export interface AppConfig {
  /** Preferred: an async verifier (HS256-explicit or JWKS). If absent, the legacy HS256 fields below are used. */
  verifier?: TokenVerifier;
  /** Subject ids allowed to use /v1/admin/*. Authority is THIS server-side list only — never token claims. */
  adminUserIds?: string[];
  jwtSecret?: string; jwtAudience?: string; jwtIssuer?: string;
  corsOrigins: string[]; maxJsonBytes: number; ipRequestsPerMinute: number; trustProxy: boolean;
}
export interface AppDeps {
  store: Store; gateway: Gateway; config: AppConfig; now?: () => Date;
  /** OCR engine for screenshots. If omitted or unavailable the feature is reported as unavailable (never simulated). */
  ocr?: OcrEngine;
  /** Isolated APK analysis (worker thread, timeout, memory cap, bounded queue). Defaults to a pool with safe limits. */
  apkRunner?: ApkRunner;
  /** Injectable for tests; defaults to the SSRF-guarded real tracer. */
  urlTracer?: (u: URL) => Promise<RedirectTrace>;
  log?: (rec: Record<string, unknown>) => void;
}

const IDEM_RE = /^[A-Za-z0-9_-]{8,64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

class Window {
  hits = new Map<string, { n: number; reset: number }>();
  check(key: string, limit: number, now: number): boolean {
    if (this.hits.size > 50_000) this.hits.clear();
    const h = this.hits.get(key);
    if (!h || now >= h.reset) { this.hits.set(key, { n: 1, reset: now + 60_000 }); return true; }
    h.n++;
    return h.n <= limit;
  }
}

async function readBody(req: http.IncomingMessage, maxBytes: number): Promise<Buffer> {
  const declared = Number(req.headers['content-length']);
  if (Number.isFinite(declared) && declared > maxBytes) { req.resume(); throw new HttpError(413, 'payload_too_large', `Body exceeds ${maxBytes} bytes`); }
  const chunks: Buffer[] = []; let total = 0;
  for await (const c of req) {
    total += (c as Buffer).length;
    if (total > maxBytes) { req.destroy(); throw new HttpError(413, 'payload_too_large', `Body exceeds ${maxBytes} bytes`); }
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks);
}

async function readJson(req: http.IncomingMessage, maxBytes: number): Promise<Record<string, unknown>> {
  if (!/^application\/json\b/i.test(String(req.headers['content-type'] ?? ''))) throw new HttpError(415, 'unsupported_media_type', 'Content-Type must be application/json');
  const raw = await readBody(req, maxBytes);
  let v: unknown;
  try { v = JSON.parse(raw.toString('utf8')); } catch { throw new HttpError(400, 'invalid_json', 'Body is not valid JSON'); }
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new HttpError(400, 'invalid_json', 'Body must be a JSON object');
  return v as Record<string, unknown>;
}

export function createApp(deps: AppDeps): http.RequestListener {
  const { store, gateway, config } = deps;
  const clock = deps.now ?? (() => new Date());
  const ipWin = new Window(); const userWin = new Window();
  const tracer = deps.urlTracer ?? ((u: URL) => traceRedirects(u));
  const log = deps.log ?? ((r) => console.log(JSON.stringify(r)));
  const apkRunner: ApkRunner = deps.apkRunner ?? createApkPool();
  const admins = new Set(config.adminUserIds ?? []);
  const verify: TokenVerifier = config.verifier ?? (async (t, now) => verifyJwt(t, { secret: config.jwtSecret ?? '', audience: config.jwtAudience, issuer: config.jwtIssuer, now }));
  let ocrProbe: { at: number; p: Promise<OcrProbe> } | null = null;
  const ocrState = (): Promise<OcrProbe> => {
    if (!deps.ocr) return Promise.resolve({ ok: false, reason: 'not_configured' });
    if (!ocrProbe || Date.now() - ocrProbe.at > 60_000) ocrProbe = { at: Date.now(), p: deps.ocr.probe().catch(() => ({ ok: false, reason: 'probe_failed' })) };
    return ocrProbe.p;
  };
  const aiAvailable = () => gateway.deps.registry.some((m) => m.enabled && gateway.deps.adapters[m.provider]);

  return async (req: http.IncomingMessage, res: http.ServerResponse) => {
    const requestId = randomUUID();
    const t0 = Date.now();
    let status = 500; let userId: string | undefined;
    const send = (code: number, body: unknown) => {
      status = code;
      const s = JSON.stringify(body);
      res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(s) });
      res.end(s);
    };
    // Security headers on every response
    res.setHeader('x-request-id', requestId);
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('x-frame-options', 'DENY');
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('content-security-policy', "default-src 'none'; frame-ancestors 'none'");
    res.setHeader('cache-control', 'no-store');
    res.setHeader('strict-transport-security', 'max-age=31536000; includeSubDomains');
    res.setHeader('cross-origin-resource-policy', 'same-site');
    // CORS: explicit allowlist only; never "*".
    const origin = req.headers.origin;
    if (typeof origin === 'string' && config.corsOrigins.includes(origin)) {
      res.setHeader('access-control-allow-origin', origin);
      res.setHeader('vary', 'Origin');
      res.setHeader('access-control-allow-headers', 'authorization, content-type, idempotency-key, x-consent-external-processing');
      res.setHeader('access-control-allow-methods', 'GET, POST, DELETE, OPTIONS');
      res.setHeader('access-control-max-age', '600');
    }

    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const method = req.method ?? 'GET';
      if (method === 'OPTIONS') { status = 204; res.writeHead(204); res.end(); return; }

      const ip = (config.trustProxy && typeof req.headers['x-forwarded-for'] === 'string' ? req.headers['x-forwarded-for'].split(',')[0].trim() : req.socket.remoteAddress) ?? 'unknown';
      if (!ipWin.check(ip, config.ipRequestsPerMinute, clock().getTime())) { res.setHeader('retry-after', '60'); throw new HttpError(429, 'rate_limited', 'Too many requests'); }

      if (method === 'GET' && url.pathname === '/healthz') return send(200, { status: 'ok' });
      if (method === 'GET' && url.pathname === '/readyz') {
        try { store.db.prepare('SELECT 1').get(); return send(200, { status: 'ready' }); } catch { return send(503, { status: 'not_ready' }); }
      }

      if (method === 'GET' && url.pathname === '/v1/capabilities') {
        const o = await ocrState();
        return send(200, { features: {
          sms: { state: 'available' }, url: { state: 'available' }, apk: { state: 'available' },
          screenshot: o.ok ? { state: 'available', note: 'OCR language: eng' } : { state: 'unavailable', reason: 'ocr_engine_unavailable' },
          ai_interpretation: aiAvailable() ? { state: 'available', requiresConsent: true } : { state: 'unavailable', reason: 'no_model_configured' },
        } });
      }

      // ---- authentication (everything below requires a verified identity)
      const m = /^Bearer\s+(\S+)$/.exec(String(req.headers.authorization ?? ''));
      if (!m) { res.setHeader('www-authenticate', 'Bearer'); throw new HttpError(401, 'unauthorized', 'Authentication required'); }
      try { userId = (await verify(m[1], clock())).sub; }
      catch (e) { if (e instanceof AuthError) { res.setHeader('www-authenticate', 'Bearer'); throw new HttpError(401, 'unauthorized', 'Invalid or expired credentials'); } throw e; }
      const plan: PlanConfig = store.getPlan(userId, clock());          // server-side entitlement only
      if (!userWin.check(userId, plan.requestsPerMinute, clock().getTime())) { res.setHeader('retry-after', '60'); throw new HttpError(429, 'rate_limited', 'Too many requests'); }

      const usageView = () => {
        const u = store.usage(userId!, clock());
        return { period: u.period, used: u.used, reserved: u.reserved, limit: plan.monthlyUnits, remaining: Math.max(0, plan.monthlyUnits - u.used - u.reserved) };
      };

      if (method === 'GET' && url.pathname === '/v1/me') return send(200, { userId, plan: { id: plan.id, provisional: plan.provisional }, isAdmin: admins.has(userId), requestId });
      if (url.pathname.startsWith('/v1/admin/')) {
        if (!admins.has(userId)) throw new HttpError(403, 'forbidden', 'Administrator access required');   // server-side allowlist only
        if (method === 'GET' && url.pathname === '/v1/admin/overview') {
          const reg = gateway.deps.registry.map((m) => ({ provider: m.provider, model: m.id, tier: m.tier, enabled: m.enabled, priceVerifiedAt: m.priceVerifiedAt, adapterConfigured: !!gateway.deps.adapters[m.provider] }));
          const h = gateway.deps.health; const nowMs = clock().getTime();
          return send(200, { models: reg, cooldowns: [...h.modelCooldownUntil].filter(([, t]) => t > nowMs).length, disabledProviders: [...h.providerDisabledUntil].filter(([, t]) => t > nowMs).map(([k]) => k), requestId });
        }
        throw new HttpError(404, 'not_found', 'Not found');
      }
      if (method === 'GET' && url.pathname === '/v1/usage') {
        return send(200, { plan: { id: plan.id, provisional: plan.provisional, maxApkBytes: plan.maxApkBytes, maxImageBytes: plan.maxImageBytes, maxTextChars: plan.maxTextChars, allowPaidInference: plan.allowPaidInference }, usage: usageView(), requestId });
      }
      if (method === 'GET' && url.pathname === '/v1/analyses') return send(200, { analyses: store.listAnalyses(userId, Number(url.searchParams.get('limit')) || 50) });
      const one = /^\/v1\/analyses\/([^/]+)$/.exec(url.pathname);
      if (method === 'GET' && one) {
        if (!UUID_RE.test(one[1])) throw new HttpError(404, 'not_found', 'Not found');
        const a = store.getAnalysis(userId, one[1]);
        if (!a) throw new HttpError(404, 'not_found', 'Not found'); // same answer for missing and not-yours
        return send(200, a);
      }
      if (method === 'DELETE' && url.pathname === '/v1/me') { store.deleteUserData(userId); return send(200, { deleted: true }); }

      const kindMatch = /^\/v1\/analyze\/(sms|url|apk|screenshot)$/.exec(url.pathname);
      if (method === 'POST' && kindMatch) {
        const kind = kindMatch[1] as TaskKind;
        let body: Record<string, unknown> = {}; let apkBuf: Buffer | undefined; let imgBuf: Buffer | undefined; let ocrVersion: string | undefined;
        if (kind === 'apk') {
          const ct = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
          if (!['application/vnd.android.package-archive', 'application/octet-stream'].includes(ct)) throw new HttpError(415, 'unsupported_media_type', 'Send the APK as application/vnd.android.package-archive');
          apkBuf = await readBody(req, plan.maxApkBytes);
          if (apkBuf.length === 0) throw new HttpError(400, 'empty_body', 'No file received');
        } else if (kind === 'screenshot') {
          const ct = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
          if (!['image/png', 'image/jpeg'].includes(ct)) throw new HttpError(415, 'unsupported_media_type', 'Send the screenshot as image/png or image/jpeg');
          const probe = await ocrState();
          if (!probe.ok) throw new HttpError(503, 'ocr_unavailable', 'Screenshot analysis is currently unavailable: no OCR engine is configured on the server');
          imgBuf = await readBody(req, plan.maxImageBytes);
          if (imgBuf.length === 0) throw new HttpError(400, 'empty_body', 'No file received');
          try { sniffImage(imgBuf); } catch (e) { if (e instanceof ImageRejected) throw new HttpError(422, e.code, e.message); throw e; }
          ocrVersion = probe.version;
        } else body = await readJson(req, config.maxJsonBytes);

        const headerKey = req.headers['idempotency-key'];
        const idem = typeof headerKey === 'string' ? headerKey : typeof body.idempotencyKey === 'string' ? body.idempotencyKey : undefined;
        if (idem !== undefined && !IDEM_RE.test(idem)) throw new HttpError(400, 'invalid_idempotency_key', 'Idempotency key must be 8-64 chars [A-Za-z0-9_-]');
        const key = idem ?? randomUUID();

        // Validate input BEFORE reserving quota.
        let smsText = ''; let urlInput = ''; let follow = false; let consent = false;
        if (kind === 'sms') {
          if (typeof body.text !== 'string' || !body.text.trim()) throw new HttpError(400, 'invalid_input', '"text" is required');
          if (body.text.length > plan.maxTextChars) throw new HttpError(413, 'text_too_long', `Text exceeds ${plan.maxTextChars} characters for your plan`);
          smsText = body.text; consent = body.consentExternalProcessing === true;
        } else if (kind === 'screenshot') {
          consent = String(req.headers['x-consent-external-processing'] ?? '').toLowerCase() === 'true';
        } else if (kind === 'url') {
          if (typeof body.url !== 'string') throw new HttpError(400, 'invalid_input', '"url" is required');
          urlInput = body.url; follow = body.followRedirects === true;
          try { normalizeUserUrl(urlInput); } catch (e) { if (e instanceof UrlRejected) throw new HttpError(400, e.code, e.message); throw e; }
        }

        if (idem) {
          const prior = store.getAnalysisByIdemKey(userId, key);
          if (prior) return send(200, { ...prior, replay: true, usage: usageView(), requestId });
        }
        const units = TASK_UNITS[kind];
        const r = store.reserve(userId, `${kind}:${key}`, units, plan.monthlyUnits, clock());
        if (!r.ok) {
          if (r.reason === 'quota_exceeded') throw new HttpError(429, 'quota_exceeded', 'Monthly allowance used up for your plan', { remaining: r.remaining, plan: plan.id });
          throw new HttpError(409, 'idempotency_conflict', 'Idempotency key was used for a different request');
        }
        if (r.replay) {
          const prior = store.getAnalysisByIdemKey(userId, key);
          if (prior) return send(200, { ...prior, replay: true, usage: usageView(), requestId });
          throw new HttpError(409, 'request_in_progress', 'An identical request is still being processed');
        }

        try {
          let result: { status: string }; let ambiguous = false;
          if (kind === 'sms') {
            const o = await analyzeSms({ text: smsText, gateway, userId, plan, requestId, allowExternal: consent });
            result = o.result; ambiguous = o.sawAmbiguousProviderCost;
          } else if (kind === 'url') {
            const trace = follow ? await tracer(normalizeUserUrl(urlInput)) : undefined;
            result = analyzeUrl(urlInput, { trace });
          } else if (kind === 'screenshot') {
            try {
              const o = await analyzeScreenshot({ image: imgBuf!, ocr: deps.ocr!, ocrVersion, gateway, userId, plan, requestId, allowExternal: consent });
              result = o.result; ambiguous = o.sawAmbiguousProviderCost;
            } catch (e) {
              if (e instanceof ImageRejected) throw new HttpError(422, e.code, e.message);
              if (e instanceof OcrError) throw new HttpError(e.code === 'ocr_timeout' ? 504 : 502, e.code, 'The screenshot could not be processed');
              throw e;
            }
          } else {
            try { result = await apkRunner(apkBuf!); }
            catch (e) {
              if (e instanceof PoolError) {
                if (e.code === 'busy') { res.setHeader('retry-after', '5'); throw new HttpError(503, 'busy', 'Analysis capacity is full, please retry shortly'); }
                if (e.code === 'timeout') throw new HttpError(504, 'analysis_timeout', 'The file took too long to analyse');
                if (e.code === 'too_complex') throw new HttpError(422, 'file_too_complex', 'The file is too complex to analyse safely');
                throw new HttpError(500, 'internal_error', 'Internal error');
              }
              throw e;
            }
          }
          if (result.status === 'failed') {
            store.release(r.reservationId);                               // failed work is not billed to the user
            throw new HttpError(422, (result as any).failure?.code ?? 'analysis_failed', (result as any).failure?.message ?? 'Analysis could not be performed', result);
          }
          store.commit(r.reservationId, units);
          const id = store.saveAnalysis({ userId, kind, status: result.status, result, idemKey: idem ? key : null, now: clock() });
          if (ambiguous) log({ level: 'warn', msg: 'provider_cost_ambiguous', requestId, userId });
          return send(200, { id, kind, status: result.status, result, usage: usageView(), requestId });
        } catch (e) {
          store.release(r.reservationId);                                  // no-op if already committed
          throw e;
        }
      }
      throw new HttpError(404, 'not_found', 'Not found');
    } catch (e) {
      if (e instanceof HttpError) {
        const body: any = { error: { code: e.code, message: e.message, requestId } };
        if (e.details && e.status !== 422) body.error.details = e.details;
        if (e.details && e.status === 422) body.result = e.details;
        if (!res.headersSent) send(e.status, body);
      } else {
        // Never leak internals; log only the error class + request id (no bodies, tokens or stacks to the client).
        log({ level: 'error', msg: 'unhandled', requestId, err: e instanceof Error ? e.name : 'unknown' });
        if (!res.headersSent) send(500, { error: { code: 'internal_error', message: 'Internal error', requestId } });
      }
    } finally {
      log({ level: 'info', msg: 'request', requestId, method: req.method, path: (req.url ?? '').split('?')[0], status, ms: Date.now() - t0, user: userId ? 'auth' : 'anon' });
    }
  };
}
export { PLANS };
