import { ApiError, type ApiErrorDetails } from './api-error';
import { isRecord } from './guards';

const DEFAULT_TIMEOUT_MS = 5_000;
/** Upper bound for backend-provided text copied into an error message. */
const MAX_BACKEND_TEXT_LENGTH = 200;

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface ApiClientOptions {
  timeoutMs?: number;
  /** Transport; defaults to the global `fetch`. Replaced in tests. */
  fetch?: FetchLike;
}

export interface RequestOptions {
  /** Cancels the request; the call then rejects with an `aborted` ApiError. */
  signal?: AbortSignal;
}

interface BackendFailure {
  code: string;
  message: string;
}

/** Backend error envelope: `{"error": {"code": "...", "message": "..."}}`. */
function readBackendFailure(body: unknown): BackendFailure | null {
  if (!isRecord(body) || !isRecord(body.error)) {
    return null;
  }
  const { code, message } = body.error;
  return typeof code === 'string' && typeof message === 'string' ? { code, message } : null;
}

const defaultFetch: FetchLike = (input, init) => globalThis.fetch(input, init);

/**
 * Resolves a request path against the page's own origin and refuses anything that leaves it.
 * Going through the URL parser (instead of testing the string) also catches forms such as `//host`, `/\host`
 * and absolute URLs, so the UI can only ever call the backend that served this page.
 */
function resolveSameOrigin(path: string): string {
  const { origin } = globalThis.location;
  const url = new URL(path, origin);
  if (url.origin !== origin) {
    throw new TypeError('API requests must target the origin that served this page.');
  }
  return url.href;
}

function isSyntaxError(error: unknown): boolean {
  return error instanceof Error && error.name === 'SyntaxError';
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch (error) {
    if (isSyntaxError(error)) {
      throw new ApiError('invalid-response', 'The backend reply was not valid JSON.', { status: response.status });
    }
    // Anything else (an abort or a connection reset while reading) is classified by the caller.
    throw error;
  }
}

function truncate(text: string): string {
  return text.length > MAX_BACKEND_TEXT_LENGTH ? `${text.slice(0, MAX_BACKEND_TEXT_LENGTH)}...` : text;
}

async function failureFromResponse(response: Response): Promise<ApiError> {
  let failure: BackendFailure | null = null;
  try {
    failure = readBackendFailure(await response.json());
  } catch {
    // The error body is optional diagnostics. Without a usable one the status alone still classifies the error.
  }
  const details: ApiErrorDetails = { status: response.status };
  if (failure) {
    details.code = failure.code;
  }
  if (response.status === 401) {
    return new ApiError('unauthorized', 'The backend did not accept this window: it has no valid session.', details);
  }
  const message = failure
    ? truncate(`HTTP ${response.status} ${failure.code}: ${failure.message}`)
    : `HTTP ${response.status}`;
  return new ApiError('http', message, details);
}

/**
 * The only way the UI talks to the backend. Same-origin GET requests.
 *
 * The page holds no credential. The kiosk launcher installs an HttpOnly session cookie that the browser attaches to
 * same-origin requests by itself, so this code neither sees nor sends a secret. A request without a valid session is
 * answered 401 and surfaces as the `unauthorized` error.
 * Every reply is checked with a caller-supplied type guard because the backend is an external boundary.
 */
export class ApiClient {
  readonly #timeoutMs: number;
  readonly #fetch: FetchLike;

  constructor({ timeoutMs = DEFAULT_TIMEOUT_MS, fetch: fetchImpl = defaultFetch }: ApiClientOptions = {}) {
    this.#timeoutMs = timeoutMs;
    this.#fetch = fetchImpl;
  }

  /**
   * GETs `path` and returns the JSON body once `guard` accepts it.
   * Rejects with an ApiError (see `ApiErrorKind`) for every failure of the request itself. It rejects with a
   * TypeError, before anything is sent, when the request cannot be built at all: a `path` that leaves the page's
   * origin (a programming error) or a page with no usable origin (for example one opened from a file: URL).
   * A `signal` that is already aborted rejects as `aborted` without calling the transport.
   */
  async get<T>(path: string, guard: (value: unknown) => value is T, { signal }: RequestOptions = {}): Promise<T> {
    const url = resolveSameOrigin(path);
    if (signal?.aborted) {
      throw new ApiError('aborted', 'The request was cancelled.');
    }

    const request = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      request.abort();
    }, this.#timeoutMs);
    const abortWithCaller = () => request.abort();
    signal?.addEventListener('abort', abortWithCaller, { once: true });

    try {
      const response = await this.#fetch(url, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: request.signal,
        // The session cookie is the only credential and it travels with same-origin requests only (this is the
        // fetch default, written out because the whole sign-in rests on it). No cached copies, no referrer, and no
        // redirects that could carry the request somewhere else.
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
      });
      if (!response.ok) {
        throw await failureFromResponse(response);
      }
      const body = await readJson(response);
      if (!guard(body)) {
        throw new ApiError('invalid-response', 'The backend reply did not have the expected shape.', {
          status: response.status,
        });
      }
      return body;
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      if (timedOut) {
        throw new ApiError('timeout', 'The backend did not reply in time.');
      }
      if (request.signal.aborted) {
        throw new ApiError('aborted', 'The request was cancelled.');
      }
      throw new ApiError('network', 'The backend could not be reached.');
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abortWithCaller);
    }
  }
}
