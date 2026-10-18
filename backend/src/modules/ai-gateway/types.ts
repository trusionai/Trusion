export type Capability = 'text' | 'vision' | 'audio' | 'json';
export type Tier = 'free' | 'paid' | 'local';

export interface ModelSpec {
  /** Provider-side model identifier. MUST be verified against current provider docs before enabling. */
  id: string;
  provider: string;
  tier: Tier;
  capabilities: Capability[];
  maxContextTokens: number;
  maxOutputTokens: number;
  /** USD per 1M tokens; null = unknown (paid models with unknown price are never selected). */
  priceInPerM: number | null;
  priceOutPerM: number | null;
  /** ISO date the price was last verified against official docs; null = never verified. */
  priceVerifiedAt: string | null;
  dataPolicy: 'external_logged' | 'external_no_train' | 'local';
  /** Lower is better (owner-assigned until evaluation data exists). */
  qualityRank: number;
  enabled: boolean;
}

export interface CompletionRequest {
  system: string;
  user: string;
  images?: { mediaType: string; base64: string }[];
  maxOutputTokens: number;
  json: boolean;
}

export interface CompletionResult {
  text: string;
  inputTokens: number | null;
  outputTokens: number | null;
  /** Provider-reported cost in USD if (and only if) the provider returned one. */
  costUsd: number | null;
}

export type ProviderErrorKind = 'rate_limit' | 'server' | 'network' | 'timeout' | 'ambiguous_timeout' | 'auth' | 'unsupported' | 'bad_request';

export class ProviderError extends Error {
  kind: ProviderErrorKind;
  retryAfterMs?: number;
  constructor(kind: ProviderErrorKind, message: string, retryAfterMs?: number) {
    super(message);
    this.name = 'ProviderError';
    this.kind = kind;
    this.retryAfterMs = retryAfterMs;
  }
}

export interface ProviderAdapter {
  name: string;
  complete(model: ModelSpec, req: CompletionRequest, opts: { signal: AbortSignal }): Promise<CompletionResult>;
}
