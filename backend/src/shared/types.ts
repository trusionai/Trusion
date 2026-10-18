/**
 * Shared types. Analysis status values follow the production-readiness spec:
 * a failed or unverifiable analysis must NEVER be reported as "safe".
 */
export type AnalysisStatus =
  | 'completed'
  | 'completed_with_limitations'
  | 'inconclusive'
  | 'failed'
  | 'requires_review';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/** Where a finding came from. UI must be able to distinguish these. */
export type EvidenceSource = 'heuristic' | 'static_analysis' | 'model_inference' | 'reputation_provider';

export interface Indicator {
  id: string;
  severity: Severity;
  source: EvidenceSource;
  /** Human-readable explanation of why this matters. */
  description: string;
  /** Concrete evidence extracted from the actual input (never invented). */
  evidence?: string;
}

export class HttpError extends Error {
  status: number;
  code: string;
  details?: unknown;
  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}
