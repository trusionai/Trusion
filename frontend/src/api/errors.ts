export type ApiErrorKind = 'unauthenticated' | 'forbidden' | 'not_found' | 'too_large' | 'unprocessable' | 'quota' | 'rate_limited' | 'unavailable' | 'server' | 'network' | 'timeout' | 'invalid_response' | 'bad_request' | 'conflict' | 'unsupported_media';

export class ApiError extends Error {
  kind: ApiErrorKind; status: number; code: string; requestId?: string;
  constructor(kind: ApiErrorKind, status: number, code: string, message: string, requestId?: string) {
    super(message); this.name = 'ApiError'; this.kind = kind; this.status = status; this.code = code; this.requestId = requestId;
  }
}

export function kindForStatus(status: number, code: string): ApiErrorKind {
  if (status === 401) return 'unauthenticated';
  if (status === 403) return 'forbidden';
  if (status === 404) return 'not_found';
  if (status === 409) return 'conflict';
  if (status === 413) return 'too_large';
  if (status === 415) return 'unsupported_media';
  if (status === 422) return 'unprocessable';
  if (status === 429) return code === 'quota_exceeded' ? 'quota' : 'rate_limited';
  if (status === 503) return 'unavailable';
  if (status >= 500) return 'server';
  return 'bad_request';
}

/** User-facing copy. Server text is never trusted as markup, and provider/internal detail is never shown. */
export function describeError(e: unknown): { title: string; detail: string; retryable: boolean; requestId?: string } {
  if (!(e instanceof ApiError)) return { title: 'Something went wrong', detail: 'An unexpected error occurred. Nothing was analysed.', retryable: true };
  const rid = e.requestId;
  switch (e.kind) {
    case 'unauthenticated': return { title: 'Session expired', detail: 'Please sign in again. Your analysis was not run.', retryable: false, requestId: rid };
    case 'forbidden': return { title: 'Not permitted', detail: 'Your account is not allowed to do this.', retryable: false, requestId: rid };
    case 'quota': return { title: 'Monthly allowance used up', detail: 'Your plan has no analyses left this month. This request was not run and was not charged.', retryable: false, requestId: rid };
    case 'rate_limited': return { title: 'Too many requests', detail: 'Please wait a minute and try again.', retryable: true, requestId: rid };
    case 'too_large': return { title: 'Too large', detail: 'The input is larger than your plan allows.', retryable: false, requestId: rid };
    case 'unsupported_media': return { title: 'Unsupported file type', detail: 'This file type cannot be analysed.', retryable: false, requestId: rid };
    case 'unprocessable': return { title: 'Could not analyse this input', detail: e.code === 'not_an_apk' || e.code === 'not_zip' ? 'The file is not a valid Android package.' : e.code === 'unsupported_image_type' ? 'Only PNG and JPEG images are supported.' : e.code === 'image_too_large_dimensions' ? 'The image dimensions are too large.' : 'The input could not be processed. You were not charged.', retryable: false, requestId: rid };
    case 'bad_request': return { title: 'Invalid input', detail: e.code === 'invalid_url' || e.code === 'scheme_not_allowed' ? 'Enter a valid http or https URL.' : 'Please check your input and try again.', retryable: false, requestId: rid };
    case 'unavailable': return { title: 'Feature unavailable', detail: 'This capability is not available on the server right now. No result was produced.', retryable: true, requestId: rid };
    case 'timeout': return { title: 'Request timed out', detail: 'The server did not answer in time. No result was produced. You can try again with the same request; you will not be charged twice.', retryable: true, requestId: rid };
    case 'network': return { title: 'Cannot reach the server', detail: 'Check your connection. No result was produced.', retryable: true };
    case 'invalid_response': return { title: 'Unexpected server response', detail: 'The response did not look right, so it was discarded.', retryable: true, requestId: rid };
    case 'conflict': return { title: 'Request already in progress', detail: 'An identical request is still being processed.', retryable: true, requestId: rid };
    default: return { title: 'Server error', detail: 'The server could not complete the request. No result was produced.', retryable: true, requestId: rid };
  }
}
