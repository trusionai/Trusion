/**
 * Runtime validation of backend responses (no dependency). A response that does not have the expected shape is
 * rejected as `invalid_response` and never rendered. Validation does not "fix" data: wrong types => reject.
 */
import { ApiError } from './errors.ts';
import type { Capabilities, EvidenceSource, Indicator, Kind, Me, ResultVM, Severity, Status, UsageInfo, UsageResponse, HistoryItem, Envelope } from './types.ts';

const bad = (what: string): never => { throw new ApiError('invalid_response', 200, 'invalid_response', `Unexpected response shape: ${what}`); };
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown, what: string): string => (typeof v === 'string' ? v : bad(what));
const optStr = (v: unknown, what: string): string | undefined => (v === undefined || v === null ? undefined : str(v, what));
const num = (v: unknown, what: string): number => (typeof v === 'number' && Number.isFinite(v) ? v : bad(what));
const bool = (v: unknown, what: string): boolean => (typeof v === 'boolean' ? v : bad(what));
const arr = (v: unknown, what: string): unknown[] => (Array.isArray(v) ? v : bad(what));
const obj = (v: unknown, what: string): Record<string, unknown> => (isObj(v) ? v : bad(what));
const strArr = (v: unknown, what: string): string[] => arr(v, what).map((x, i) => str(x, `${what}[${i}]`));

const STATUSES: Status[] = ['completed', 'completed_with_limitations', 'inconclusive', 'failed', 'requires_review'];
const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
const SOURCES: EvidenceSource[] = ['heuristic', 'static_analysis', 'model_inference', 'reputation_provider'];
const KINDS: Kind[] = ['sms', 'url', 'apk', 'screenshot'];
const oneOf = <T extends string>(v: unknown, set: T[], what: string): T => (typeof v === 'string' && (set as string[]).includes(v) ? (v as T) : bad(what));

export function parseIndicator(v: unknown, what = 'indicator'): Indicator {
  const o = obj(v, what);
  return { id: str(o.id, `${what}.id`), severity: oneOf(o.severity, SEVERITIES, `${what}.severity`), source: oneOf(o.source, SOURCES, `${what}.source`), description: str(o.description, `${what}.description`), evidence: optStr(o.evidence, `${what}.evidence`) };
}
const indicators = (v: unknown, what: string) => arr(v, what).map((x, i) => parseIndicator(x, `${what}[${i}]`));

export function parseUsageInfo(v: unknown): UsageInfo {
  const o = obj(v, 'usage');
  return { period: str(o.period, 'usage.period'), used: num(o.used, 'usage.used'), reserved: num(o.reserved, 'usage.reserved'), limit: num(o.limit, 'usage.limit'), remaining: num(o.remaining, 'usage.remaining') };
}
export function parseUsageResponse(v: unknown): UsageResponse {
  const o = obj(v, 'usage response'); const p = obj(o.plan, 'plan');
  return { usage: parseUsageInfo(o.usage), plan: { id: str(p.id, 'plan.id'), provisional: bool(p.provisional, 'plan.provisional'), maxApkBytes: num(p.maxApkBytes, 'plan.maxApkBytes'), maxImageBytes: num(p.maxImageBytes, 'plan.maxImageBytes'), maxTextChars: num(p.maxTextChars, 'plan.maxTextChars'), allowPaidInference: bool(p.allowPaidInference, 'plan.allowPaidInference') } };
}
export function parseMe(v: unknown): Me {
  const o = obj(v, 'me'); const p = obj(o.plan, 'me.plan');
  return { userId: str(o.userId, 'me.userId'), plan: { id: str(p.id, 'me.plan.id'), provisional: bool(p.provisional, 'me.plan.provisional') }, isAdmin: bool(o.isAdmin, 'me.isAdmin') };
}
export function parseCapabilities(v: unknown): Capabilities {
  const f = obj(obj(v, 'capabilities').features, 'features'); const out: Capabilities['features'] = {};
  for (const [k, raw] of Object.entries(f)) { const o = obj(raw, `feature ${k}`); out[k] = { state: oneOf(o.state, ['available', 'unavailable'], `feature ${k}.state`), reason: optStr(o.reason, 'reason'), note: optStr(o.note, 'note'), requiresConsent: o.requiresConsent === true }; }
  return out && { features: out };
}
export function parseHistory(v: unknown): HistoryItem[] {
  return arr(obj(v, 'history').analyses, 'analyses').map((x, i) => { const o = obj(x, `analyses[${i}]`); return { id: str(o.id, 'id'), kind: oneOf(o.kind, KINDS, 'kind'), status: oneOf(o.status, STATUSES, 'status'), createdAt: str(o.createdAt, 'createdAt') }; });
}

/** Normalise the per-kind backend result into the single view-model the UI renders. */
export function toViewModel(kind: Kind, status: Status, resultRaw: unknown): ResultVM {
  const r = obj(resultRaw, 'result');
  const vm: ResultVM = { kind, status, assessment: r.assessment === null || r.assessment === undefined ? null : str(r.assessment, 'assessment'), score: typeof r.score === 'number' ? r.score : null, indicators: [], limitations: strArr(r.limitations ?? [], 'limitations'), actions: strArr(r.recommendedActions ?? [], 'recommendedActions'), urls: [] };
  if (r.failure !== undefined) { const f = obj(r.failure, 'failure'); vm.failure = { code: str(f.code, 'failure.code'), message: str(f.message, 'failure.message') }; }
  if (kind === 'sms' || kind === 'screenshot') {
    const h = obj(r.heuristic, 'heuristic'); vm.indicators = indicators(h.indicators, 'heuristic.indicators'); vm.score = num(h.score, 'heuristic.score');
    vm.urls = arr(r.urls, 'urls').map((x, i) => { const u = obj(x, `urls[${i}]`); return { url: str(u.url, 'url'), assessment: optStr(u.assessment, 'url.assessment'), error: optStr(u.error, 'url.error') }; });
    const a = obj(r.ai, 'ai'); const q = Array.isArray(a.indicators) ? a.indicators.map((x, i) => { const o = obj(x, `ai.indicators[${i}]`); return { quote: str(o.quote, 'quote'), explanation: str(o.explanation, 'explanation') }; }) : [];
    vm.ai = { used: bool(a.used, 'ai.used'), notUsedReason: optStr(a.notUsedReason, 'ai.notUsedReason'), verdict: optStr(a.verdict, 'ai.verdict'), confidence: typeof a.confidence === 'number' ? a.confidence : undefined, scamType: optStr(a.scamType, 'ai.scamType'), recommendedAction: optStr(a.recommendedAction, 'ai.recommendedAction'), quotes: q };
    if (kind === 'screenshot') {
      const o = obj(r.ocr, 'ocr'); vm.ocr = { engine: str(o.engine, 'ocr.engine'), version: optStr(o.version, 'ocr.version'), language: str(o.language, 'ocr.language'), textLength: num(o.textLength, 'ocr.textLength'), textPreview: str(o.textPreview, 'ocr.textPreview'), previewTruncated: bool(o.previewTruncated, 'ocr.previewTruncated') };
      const i = obj(r.image, 'image'); vm.image = { type: str(i.type, 'image.type'), width: num(i.width, 'image.width'), height: num(i.height, 'image.height'), sha256: str(i.sha256, 'image.sha256'), sizeBytes: num(i.sizeBytes, 'image.sizeBytes') };
    }
  } else if (kind === 'url') {
    vm.indicators = indicators(r.indicators, 'indicators');
    const n = obj(r.normalized, 'normalized'); vm.normalizedUrl = { href: str(n.href, 'href'), host: str(n.host, 'host'), registrableDomain: str(n.registrableDomain, 'registrableDomain') };
  } else {
    vm.indicators = indicators(r.indicators ?? [], 'indicators');
    if (status !== 'failed') {
      const f = obj(r.file, 'file'); const e = obj(r.embedded, 'embedded'); const s = obj(r.signing, 'signing'); const pk = isObj(r.package) ? r.package : {};
      vm.apk = { sha256: str(f.sha256, 'file.sha256'), sizeBytes: num(f.sizeBytes, 'file.sizeBytes'), packageName: optStr(pk.name, 'package.name'),
        permissions: arr(r.permissions, 'permissions').map((x, i) => { const p = obj(x, `permissions[${i}]`); return { name: str(p.name, 'perm.name'), dangerous: bool(p.dangerous, 'perm.dangerous'), note: optStr(p.note, 'perm.note') }; }),
        embeddedUrls: strArr(e.urls, 'embedded.urls'), payloadFiles: strArr(e.payloadFiles, 'embedded.payloadFiles'), signing: { v1SignatureFiles: strArr(s.v1SignatureFiles, 'signing.v1'), signingBlockPresent: bool(s.signingBlockPresent, 'signing.block') } };
    }
  }
  return vm;
}

export function parseEnvelope(v: unknown, fallbackKind?: Kind): Envelope {
  const o = obj(v, 'envelope');
  const kind = oneOf(o.kind ?? fallbackKind, KINDS, 'kind'); const status = oneOf(o.status, STATUSES, 'status');
  return { id: str(o.id, 'id'), kind, status, replay: o.replay === true, usage: o.usage === undefined ? undefined : parseUsageInfo(o.usage), requestId: optStr(o.requestId, 'requestId'), vm: toViewModel(kind, status, o.result) };
}
