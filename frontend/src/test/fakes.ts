import { ApiClient, type FetchLike } from '../services/api-client';

export const HEALTH_BODY = { status: 'ok', schema_version: 1, version: '0.0.1' } as const;

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

/** The backend's reply to a request that has no valid session: the uniform error envelope with HTTP 401. */
export function unauthorizedResponse(): Response {
  return jsonResponse({ error: { code: 'unauthorized', message: 'Authentication is required.' } }, 401);
}

/** A transport that never answers but, like the real `fetch`, rejects when its request is aborted. */
export const hangingFetch: FetchLike = (_input, init) =>
  new Promise((_resolve, reject) => {
    const abort = () => reject(new DOMException('The operation was aborted.', 'AbortError'));
    if (init.signal?.aborted) {
      abort();
    } else {
      init.signal?.addEventListener('abort', abort, { once: true });
    }
  });

export function makeClient(fetch: FetchLike, options: { timeoutMs?: number } = {}): ApiClient {
  const { timeoutMs } = options;
  return new ApiClient(timeoutMs === undefined ? { fetch } : { fetch, timeoutMs });
}
