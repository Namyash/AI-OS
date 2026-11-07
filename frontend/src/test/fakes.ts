import { ApiClient, type FetchLike } from '../services/api-client';

/** Obviously fake bearer token for tests; the real one is generated per boot and never appears in the repo. */
export const TEST_TOKEN = 'test-token-0123456789-abcdef';

export const HEALTH_BODY = { status: 'ok', schema_version: 1, version: '0.0.1' } as const;

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
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

export function makeClient(fetch: FetchLike, options: { token?: string | null; timeoutMs?: number } = {}): ApiClient {
  const { token = TEST_TOKEN, timeoutMs } = options;
  return new ApiClient(timeoutMs === undefined ? { token, fetch } : { token, fetch, timeoutMs });
}
