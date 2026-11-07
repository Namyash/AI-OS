/**
 * Why a backend request failed. The UI decides what to show (and whether to retry) from `kind` alone.
 *
 * - `no-token`: the page holds no access token, so no request was sent.
 * - `unauthorized`: the backend answered 401; retrying with the same token cannot succeed.
 * - `timeout`: no complete reply within the client timeout.
 * - `network`: the request could not be made or the connection broke.
 * - `http`: any other non-2xx answer; `status` and, when the backend sent one, `code` are set.
 * - `invalid-response`: a 2xx answer whose body is not JSON or does not match the expected shape.
 * - `aborted`: the caller cancelled the request (for example on unmount).
 */
export type ApiErrorKind =
  | 'no-token'
  | 'unauthorized'
  | 'timeout'
  | 'network'
  | 'http'
  | 'invalid-response'
  | 'aborted';

export interface ApiErrorDetails {
  status?: number;
  code?: string;
}

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  /** HTTP status when the backend answered, otherwise null. */
  readonly status: number | null;
  /** Machine-readable code from the backend's `{"error": {"code", "message"}}` body, otherwise null. */
  readonly code: string | null;

  constructor(kind: ApiErrorKind, message: string, details: ApiErrorDetails = {}) {
    super(message);
    this.name = 'ApiError';
    this.kind = kind;
    this.status = details.status ?? null;
    this.code = details.code ?? null;
  }
}
