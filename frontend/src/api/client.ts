/**
 * Typed client for the TRUSION backend. Only calls routes that exist in backend/src/http/app.ts.
 *  - Bearer token comes from the injected getToken (kept in memory by the auth layer); never from storage.
 *  - Per-request timeout. POST analyses are NEVER auto-retried: a charged operation is only repeated by an explicit
 *    user retry, which reuses the same Idempotency-Key so the server cannot charge twice.
 *  - Any 401 calls onUnauthorized once so the app can drop the session.
 *  - Responses are validated (schemas.ts); anything malformed becomes `invalid_response`, never a fabricated result.
 */
import { ApiError, kindForStatus } from './errors.ts';
import { parseCapabilities, parseEnvelope, parseHistory, parseMe, parseUsageResponse, toViewModel } from './schemas.ts';
import type { Capabilities, Envelope, HistoryItem, Kind, Me, UsageResponse } from './types.ts';

export interface ClientOptions {
  baseUrl: string; getToken: () => string | null; onUnauthorized?: () => void; fetchImpl?: typeof fetch; timeoutMs?: number; uploadTimeoutMs?: number;
}
export interface AdminOverview { models: { provider: string; model: string; tier: string; enabled: boolean; priceVerifiedAt: string | null; adapterConfigured: boolean }[]; cooldowns: number; disabledProviders: string[] }

export const newIdempotencyKey = (): string => {
  const b = new Uint8Array(16); crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
};

export function createApiClient(o: ClientOptions) {
  const f = o.fetchImpl ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const base = o.baseUrl.replace(/\/+$/, '');

  async function request(path: string, init: { method?: string; headers?: Record<string, string>; body?: BodyInit; auth?: boolean; timeoutMs?: number }): Promise<unknown> {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), init.timeoutMs ?? o.timeoutMs ?? 30_000);
    const headers: Record<string, string> = { accept: 'application/json', ...(init.headers ?? {}) };
    if (init.auth !== false) {
      const tok = o.getToken();
      if (!tok) { clearTimeout(t); o.onUnauthorized?.(); throw new ApiError('unauthenticated', 401, 'unauthorized', 'Not signed in'); }
      headers.authorization = `Bearer ${tok}`;
    }
    let res: Response;
    try { res = await f(base + path, { method: init.method ?? 'GET', headers, body: init.body, signal: ac.signal, credentials: 'omit', cache: 'no-store' }); }
    catch (e) {
      clearTimeout(t);
      if ((e as { name?: string })?.name === 'AbortError') throw new ApiError('timeout', 0, 'timeout', 'Request timed out');
      throw new ApiError('network', 0, 'network', 'Network error');
    }
    let text: string;
    try { text = await res.text(); } catch { clearTimeout(t); throw new ApiError('network', res.status, 'network', 'Connection lost while reading the response'); } finally { clearTimeout(t); }
    let json: unknown = null;
    try { json = text ? JSON.parse(text) : null; } catch { /* handled below */ }
    const rid = res.headers.get('x-request-id') ?? undefined;
    if (!res.ok) {
      const errObj = (json as { error?: { code?: unknown } } | null)?.error; const code = typeof errObj?.code === 'string' ? errObj.code : `http_${res.status}`;
      const kind = kindForStatus(res.status, code);
      if (kind === 'unauthenticated') o.onUnauthorized?.();
      const e = new ApiError(kind, res.status, code, `HTTP ${res.status} ${code}`, rid);
      if (res.status === 422 && json && typeof json === 'object' && (json as { result?: unknown }).result) (e as ApiError & { partial?: unknown }).partial = (json as { result: unknown }).result;
      throw e;
    }
    if (json === null) throw new ApiError('invalid_response', res.status, 'invalid_response', 'Empty or non-JSON response', rid);
    return json;
  }

  const jsonPost = (path: string, body: unknown, key: string) =>
    request(path, { method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': key }, body: JSON.stringify(body) });

  return {
    capabilities: async (): Promise<Capabilities> => parseCapabilities(await request('/v1/capabilities', { auth: false })),
    me: async (): Promise<Me> => parseMe(await request('/v1/me', {})),
    usage: async (): Promise<UsageResponse> => parseUsageResponse(await request('/v1/usage', {})),
    history: async (): Promise<HistoryItem[]> => parseHistory(await request('/v1/analyses', {})),
    analysis: async (id: string): Promise<Envelope> => {
      const j = await request(`/v1/analyses/${encodeURIComponent(id)}`, {}) as { id?: unknown; kind?: Kind; status?: never; result?: unknown };
      return parseEnvelope(j);
    },
    analyzeSms: async (a: { text: string; consentExternalProcessing: boolean; idempotencyKey: string }): Promise<Envelope> =>
      parseEnvelope(await jsonPost('/v1/analyze/sms', { text: a.text, consentExternalProcessing: a.consentExternalProcessing }, a.idempotencyKey), 'sms'),
    analyzeUrl: async (a: { url: string; followRedirects: boolean; idempotencyKey: string }): Promise<Envelope> =>
      parseEnvelope(await jsonPost('/v1/analyze/url', { url: a.url, followRedirects: a.followRedirects }, a.idempotencyKey), 'url'),
    analyzeApk: async (a: { file: Blob; idempotencyKey: string }): Promise<Envelope> =>
      parseEnvelope(await request('/v1/analyze/apk', { method: 'POST', timeoutMs: o.uploadTimeoutMs ?? 120_000, headers: { 'content-type': 'application/vnd.android.package-archive', 'idempotency-key': a.idempotencyKey }, body: a.file }), 'apk'),
    analyzeScreenshot: async (a: { file: Blob; contentType: 'image/png' | 'image/jpeg'; consentExternalProcessing: boolean; idempotencyKey: string }): Promise<Envelope> =>
      parseEnvelope(await request('/v1/analyze/screenshot', { method: 'POST', timeoutMs: o.uploadTimeoutMs ?? 120_000, headers: { 'content-type': a.contentType, 'idempotency-key': a.idempotencyKey, 'x-consent-external-processing': String(a.consentExternalProcessing) }, body: a.file }), 'screenshot'),
    deleteMyData: async (): Promise<void> => { await request('/v1/me', { method: 'DELETE' }); },
    adminOverview: async (): Promise<AdminOverview> => {
      const j = await request('/v1/admin/overview', {}) as AdminOverview;
      if (!Array.isArray(j?.models)) throw new ApiError('invalid_response', 200, 'invalid_response', 'bad admin overview');
      return { models: j.models, cooldowns: Number(j.cooldowns) || 0, disabledProviders: Array.isArray(j.disabledProviders) ? j.disabledProviders.map(String) : [] };
    },
  };
}
export type ApiClient = ReturnType<typeof createApiClient>;
export { toViewModel };
