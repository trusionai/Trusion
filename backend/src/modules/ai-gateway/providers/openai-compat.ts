/**
 * Adapter for providers exposing the widely used OpenAI-style
 * POST {baseUrl}/chat/completions API (candidates: OpenRouter, Groq, Ollama's /v1
 * endpoint, self-hosted routers).
 *
 * VERIFICATION STATUS: request/response handling is tested against a LOCAL MOCK
 * SERVER only. It has NOT been run against any real provider and the request
 * shape/limits were NOT checked against current official docs (no network when
 * written). baseUrl/apiKey come from operator config and are never client-supplied.
 */
import { ProviderError } from '../types.ts';
import type { CompletionRequest, CompletionResult, ModelSpec, ProviderAdapter } from '../types.ts';

const MAX_RESPONSE_BYTES = 1024 * 1024;

export class OpenAICompatAdapter implements ProviderAdapter {
  name: string;
  baseUrl: string;
  apiKey?: string;
  fetchImpl: typeof fetch;
  constructor(o: { name: string; baseUrl: string; apiKey?: string; fetchImpl?: typeof fetch }) {
    this.name = o.name; this.baseUrl = o.baseUrl.replace(/\/+$/, ''); this.apiKey = o.apiKey; this.fetchImpl = o.fetchImpl ?? fetch;
  }

  async complete(model: ModelSpec, req: CompletionRequest, opts: { signal: AbortSignal }): Promise<CompletionResult> {
    const userContent = req.images?.length
      ? [{ type: 'text', text: req.user }, ...req.images.map((i) => ({ type: 'image_url', image_url: { url: `data:${i.mediaType};base64,${i.base64}` } }))]
      : req.user;
    const body: Record<string, unknown> = {
      model: model.id, temperature: 0, max_tokens: req.maxOutputTokens,
      messages: [{ role: 'system', content: req.system }, { role: 'user', content: userContent }],
    };
    if (req.json) body.response_format = { type: 'json_object' };
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}/chat/completions`, {
        method: 'POST', signal: opts.signal,
        headers: { 'content-type': 'application/json', ...(this.apiKey ? { authorization: `Bearer ${this.apiKey}` } : {}) },
        body: JSON.stringify(body),
      });
    } catch (e: any) {
      // Aborted after the request was dispatched => provider may have processed it.
      if (e?.name === 'AbortError' || opts.signal.aborted) throw new ProviderError('ambiguous_timeout', 'request timed out after dispatch');
      throw new ProviderError('network', 'could not reach provider');
    }
    const s = res.status;
    if (!res.ok) {
      try { await res.body?.cancel(); } catch { /* ignore */ }
      if (s === 429) {
        const ra = Number(res.headers.get('retry-after'));
        throw new ProviderError('rate_limit', 'provider rate limit', Number.isFinite(ra) && ra > 0 ? Math.min(ra, 600) * 1000 : undefined);
      }
      if (s === 401 || s === 403) throw new ProviderError('auth', `provider rejected credentials (${s})`);
      if (s === 408 || s >= 500) throw new ProviderError('server', `provider error ${s}`);
      throw new ProviderError('bad_request', `provider refused request (${s})`);
    }
    let text: string;
    try {
      text = await res.text();
      if (text.length > MAX_RESPONSE_BYTES) throw new Error('too large');
    } catch (e: any) {
      if (e?.name === 'AbortError' || opts.signal.aborted) throw new ProviderError('ambiguous_timeout', 'timed out while reading response');
      throw new ProviderError('server', 'unreadable provider response');
    }
    let j: any;
    try { j = JSON.parse(text); } catch { throw new ProviderError('server', 'provider returned non-JSON'); }
    const content = j?.choices?.[0]?.message?.content;
    if (typeof content !== 'string') throw new ProviderError('server', 'provider response missing content');
    const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : null);
    return { text: content, inputTokens: num(j?.usage?.prompt_tokens), outputTokens: num(j?.usage?.completion_tokens), costUsd: num(j?.usage?.cost) };
  }
}
