import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HEALTH_BODY, hangingFetch, jsonResponse, makeClient, unauthorizedResponse } from '../test/fakes';
import type { FetchLike } from './api-client';
import { ApiError, type ApiErrorKind } from './api-error';
import { isHealthResponse } from './health';

type FetchMock = ReturnType<typeof vi.fn<FetchLike>>;

function respondWith(make: () => Response | Promise<Response>): FetchMock {
  return vi.fn<FetchLike>(async () => make());
}

async function failureOf(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ApiError) {
      return error;
    }
    throw error;
  }
  throw new Error('Expected the request to fail.');
}

function lastCall(fetch: FetchMock): { url: string; init: RequestInit } {
  const call = fetch.mock.calls.at(-1);
  if (!call) {
    throw new Error('fetch was not called');
  }
  return { url: call[0], init: call[1] };
}

describe('ApiClient.get', () => {
  it('sends a plain GET to the page origin and returns the validated body', async () => {
    const fetch = respondWith(() => jsonResponse(HEALTH_BODY));
    const client = makeClient(fetch);

    await expect(client.get('/health', isHealthResponse)).resolves.toEqual(HEALTH_BODY);

    const { url, init } = lastCall(fetch);
    expect(url).toBe('http://localhost:3000/health');
    expect(init.method).toBe('GET');
  });

  it('holds no credential of its own: no Authorization header and nothing in the URL', async () => {
    const fetch = respondWith(() => jsonResponse(HEALTH_BODY));

    await makeClient(fetch).get('/health', isHealthResponse);

    const { url, init } = lastCall(fetch);
    // The session cookie is attached by the browser, not by this code, so the only header is the media type asked for.
    expect(init.headers).toEqual({ Accept: 'application/json' });
    expect(new URL(url).search).toBe('');
    expect(new URL(url).hash).toBe('');
  });

  it('lets the browser attach the session cookie to this origin only, caches nothing, sends no referrer and refuses redirects', async () => {
    const fetch = respondWith(() => jsonResponse(HEALTH_BODY));

    await makeClient(fetch).get('/health', isHealthResponse);

    expect(lastCall(fetch).init).toMatchObject({
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    });
  });

  it('writes nothing to the console on success or on any failure', async () => {
    const channels = (['log', 'info', 'warn', 'error', 'debug'] as const).map((name) =>
      vi.spyOn(console, name).mockImplementation(() => undefined),
    );
    const replies: Array<() => Response | Promise<Response>> = [
      () => jsonResponse(HEALTH_BODY),
      unauthorizedResponse,
      () => jsonResponse({ error: { code: 'boom', message: 'Broke.' } }, 500),
      () => new Response('not json', { status: 200 }),
      () => Promise.reject(new TypeError('Failed to fetch')),
    ];

    for (const reply of replies) {
      await makeClient(respondWith(reply))
        .get('/health', isHealthResponse)
        .catch(() => undefined);
    }

    for (const channel of channels) {
      expect(channel).not.toHaveBeenCalled();
    }
  });

  it.each([
    ['a protocol-relative URL', '//evil.example/health'],
    ['an absolute URL', 'https://evil.example/health'],
    ['a backslash host', '/\\evil.example/health'],
    ['a look-alike host', 'http://localhost:3000.evil.example/health'],
    ['another port on the same host', 'http://localhost:9999/health'],
  ])('refuses %s because the UI only calls the origin that served it', async (_name, path) => {
    const fetch = respondWith(() => jsonResponse(HEALTH_BODY));

    await expect(makeClient(fetch).get(path, isHealthResponse)).rejects.toThrow(TypeError);
    expect(fetch).not.toHaveBeenCalled();
  });

  describe('error mapping', () => {
    it('maps 401 to "unauthorized" and keeps the backend error code', async () => {
      const error = await failureOf(makeClient(respondWith(unauthorizedResponse)).get('/health', isHealthResponse));

      expect(error).toMatchObject({ kind: 'unauthorized', status: 401, code: 'unauthorized' });
    });

    it('describes a 401 as a missing session, in its own words rather than the backend text', async () => {
      const error = await failureOf(makeClient(respondWith(unauthorizedResponse)).get('/health', isHealthResponse));

      expect(error.message).toMatch(/no valid session/);
      expect(error.message).not.toMatch(/token|url|address/i);
      expect(error.message).not.toContain('Authentication is required.');
    });

    it('maps 401 without a usable body to "unauthorized" too', async () => {
      const fetch = respondWith(() => new Response('<html>nope</html>', { status: 401 }));

      const error = await failureOf(makeClient(fetch).get('/health', isHealthResponse));

      expect(error).toMatchObject({ kind: 'unauthorized', status: 401, code: null });
    });

    it('maps other error statuses to "http" with the status and the backend error envelope', async () => {
      const fetch = respondWith(() => jsonResponse({ error: { code: 'internal_error', message: 'Broke.' } }, 500));

      const error = await failureOf(makeClient(fetch).get('/health', isHealthResponse));

      expect(error).toMatchObject({ kind: 'http', status: 500, code: 'internal_error' });
      expect(error.message).toBe('HTTP 500 internal_error: Broke.');
    });

    it('maps an error status with a body that is not the envelope to "http" with the status only', async () => {
      const bodies = [new Response('<h1>Bad gateway</h1>', { status: 502 }), jsonResponse({ error: 'flat' }, 502)];

      for (const body of bodies) {
        const error = await failureOf(makeClient(respondWith(() => body)).get('/health', isHealthResponse));
        expect(error).toMatchObject({ kind: 'http', status: 502, code: null, message: 'HTTP 502' });
      }
    });

    it('bounds how much backend-provided text it copies into an error', async () => {
      const fetch = respondWith(() => jsonResponse({ error: { code: 'big', message: 'x'.repeat(10_000) } }, 500));

      const error = await failureOf(makeClient(fetch).get('/health', isHealthResponse));

      expect(error.message.length).toBeLessThan(300);
    });

    it('maps a transport failure to "network"', async () => {
      const fetch = vi.fn<FetchLike>(() => Promise.reject(new TypeError('Failed to fetch')));

      const error = await failureOf(makeClient(fetch).get('/health', isHealthResponse));

      expect(error.kind).toBe('network');
    });

    it.each<[string, () => Response, ApiErrorKind]>([
      ['a body that is not JSON', () => new Response('not json', { status: 200 }), 'invalid-response'],
      ['an empty body', () => new Response('', { status: 200 }), 'invalid-response'],
      ['JSON of the wrong shape', () => jsonResponse({ status: 'ok' }), 'invalid-response'],
    ])('maps %s to "%s"', async (_name, reply, kind) => {
      const error = await failureOf(makeClient(respondWith(reply)).get('/health', isHealthResponse));

      expect(error.kind).toBe(kind);
    });
  });

  describe('timeout and cancellation', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    it('gives up after the timeout, aborts the request and reports "timeout"', async () => {
      const fetch = vi.fn<FetchLike>(hangingFetch);
      const pending = failureOf(makeClient(fetch, { timeoutMs: 3_000 }).get('/health', isHealthResponse));

      await vi.advanceTimersByTimeAsync(2_999);
      expect(lastCall(fetch).init.signal?.aborted).toBe(false);
      await vi.advanceTimersByTimeAsync(1);

      expect((await pending).kind).toBe('timeout');
      expect(lastCall(fetch).init.signal?.aborted).toBe(true);
    });

    it('stops the timeout timer once the request has finished', async () => {
      const fetch = respondWith(() => jsonResponse(HEALTH_BODY));

      await makeClient(fetch).get('/health', isHealthResponse);

      expect(vi.getTimerCount()).toBe(0);
    });

    it('reports "aborted" when the caller cancels, and leaves no timer behind', async () => {
      const fetch = vi.fn<FetchLike>(hangingFetch);
      const caller = new AbortController();
      const pending = failureOf(makeClient(fetch).get('/health', isHealthResponse, { signal: caller.signal }));

      caller.abort();

      expect((await pending).kind).toBe('aborted');
      expect(vi.getTimerCount()).toBe(0);
    });

    it('reports "aborted" without sending a request that was already cancelled', async () => {
      const fetch = vi.fn<FetchLike>(hangingFetch);
      const caller = new AbortController();
      caller.abort();

      const error = await failureOf(makeClient(fetch).get('/health', isHealthResponse, { signal: caller.signal }));

      expect(error.kind).toBe('aborted');
      expect(fetch).not.toHaveBeenCalled();
      expect(vi.getTimerCount()).toBe(0);
    });
  });
});
