export type Status = 'completed' | 'completed_with_limitations' | 'inconclusive' | 'failed' | 'requires_review';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type EvidenceSource = 'heuristic' | 'static_analysis' | 'model_inference' | 'reputation_provider';
export type Kind = 'sms' | 'url' | 'apk' | 'screenshot';

export interface Indicator { id: string; severity: Severity; source: EvidenceSource; description: string; evidence?: string }
export interface UsageInfo { period: string; used: number; reserved: number; limit: number; remaining: number }
export interface PlanInfo { id: string; provisional: boolean; maxApkBytes: number; maxImageBytes: number; maxTextChars: number; allowPaidInference: boolean }
export interface UsageResponse { plan: PlanInfo; usage: UsageInfo }
export interface Me { userId: string; plan: { id: string; provisional: boolean }; isAdmin: boolean }
export interface FeatureState { state: 'available' | 'unavailable'; reason?: string; note?: string; requiresConsent?: boolean }
export interface Capabilities { features: Record<string, FeatureState> }
export interface HistoryItem { id: string; kind: Kind; status: Status; createdAt: string }

/** Everything the UI renders, normalised from the per-kind backend result. All strings are rendered as TEXT only. */
export interface ResultVM {
  kind: Kind;
  status: Status;
  assessment: string | null;
  score: number | null;
  indicators: Indicator[];
  limitations: string[];
  actions: string[];
  urls: { url: string; assessment?: string; error?: string }[];
  ai?: { used: boolean; notUsedReason?: string; verdict?: string; confidence?: number; scamType?: string; recommendedAction?: string; quotes: { quote: string; explanation: string }[] };
  ocr?: { engine: string; version?: string; language: string; textLength: number; textPreview: string; previewTruncated: boolean };
  image?: { type: string; width: number; height: number; sha256: string; sizeBytes: number };
  apk?: { sha256: string; sizeBytes: number; packageName?: string; permissions: { name: string; dangerous: boolean; note?: string }[]; embeddedUrls: string[]; payloadFiles: string[]; signing: { v1SignatureFiles: string[]; signingBlockPresent: boolean } };
  normalizedUrl?: { href: string; host: string; registrableDomain: string };
  failure?: { code: string; message: string };
}
export interface Envelope { id: string; kind: Kind; status: Status; replay: boolean; usage?: UsageInfo; requestId?: string; vm: ResultVM }
