import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiClient, type FetchLike, type RequestOptions } from '../services/api-client';
import { HEALTH_BODY, hangingFetch, jsonResponse, makeClient, TEST_TOKEN } from '../test/fakes';
import {
  type BackendHealthOptions,
  HEALTH_POLL_INTERVAL_MS,
  HEALTH_RETRY_BASE_MS,
  HEALTH_RETRY_MAX_MS,
  retryDelayMs,
  useBackendHealth,
} from './useBackendHealth';

type FetchMock = ReturnType<typeof vi.fn<FetchLike>>;

/** Answers with each reply in turn, then keeps repeating the last one. A reply is built per call (a body reads once). */
function scripted(...replies: Array<() => Response | Promise<Response>>): FetchMock {
  let call = 0;
  return vi.fn<FetchLike>(async () => {
    const reply = replies[Math.min(call, replies.length - 1)];
    call += 1;
    if (!reply) {
      throw new Error('scripted() needs at least one reply');
    }
    return reply();
  });
}

const ok = () => jsonResponse(HEALTH_BODY);
const unreachable = () => Promise.reject(new TypeError('Failed to fetch'));

/** The client is created once: a new client on every render would restart polling. */
function mount(
  fetch: FetchMock,
  clientOptions: { token?: string | null; timeoutMs?: number } = {},
  hookOptions: BackendHealthOptions = {},
) {
  const client = makeClient(fetch, clientOptions);
  return renderHook(() => useBackendHealth(client, hookOptions));
}

async function advance(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('retryDelayMs', () => {
  it('doubles from the base and never exceeds the maximum', () => {
    const delays = [1, 2, 3, 4, 5, 6, 7, 40].map((failures) => retryDelayMs(failures, 1_000, 30_000));

    expect(delays).toEqual([1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000]);
  });

  it('is what the hook uses by default', () => {
    expect(retryDelayMs(1, HEALTH_RETRY_BASE_MS, HEALTH_RETRY_MAX_MS)).toBe(HEALTH_RETRY_BASE_MS);
  });
});

describe('useBackendHealth', () => {
  it('starts as connecting and becomes connected with the backend version once /health answers', async () => {
    const fetch = scripted(ok);
    const { result } = mount(fetch);
    expect(result.current).toEqual({ status: 'connecting' });

    await advance(0);

    expect(result.current).toEqual({ status: 'connected', health: HEALTH_BODY });
  });

  it('keeps checking at the poll interval while connected', async () => {
    const fetch = scripted(ok);
    mount(fetch);
    await advance(0);
    expect(fetch).toHaveBeenCalledTimes(1);

    await advance(HEALTH_POLL_INTERVAL_MS - 1);
    expect(fetch).toHaveBeenCalledTimes(1);
    await advance(1);
    expect(fetch).toHaveBeenCalledTimes(2);
    await advance(HEALTH_POLL_INTERVAL_MS);
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it('reports unreachable after a failure and retries with exponential backoff up to a cap', async () => {
    const fetch = scripted(unreachable);
    const { result } = mount(fetch, {}, { retryBaseMs: 1_000, retryMaxMs: 4_000 });

    await advance(0);
    expect(result.current).toEqual({ status: 'unreachable', cause: 'network', httpStatus: null });
    expect(fetch).toHaveBeenCalledTimes(1);

    // Waits between attempts: 1s, 2s, 4s, then capped at 4s.
    for (const [wait, callsAfter] of [
      [1_000, 2],
      [2_000, 3],
      [4_000, 4],
      [4_000, 5],
    ] as const) {
      await advance(wait - 1);
      expect(fetch).toHaveBeenCalledTimes(callsAfter - 1);
      await advance(1);
      expect(fetch).toHaveBeenCalledTimes(callsAfter);
    }
    expect(result.current.status).toBe('unreachable');
  });

  it('recovers to connected on the first success and starts the backoff over after the next failure', async () => {
    const fetch = scripted(unreachable, unreachable, ok, unreachable);
    const { result } = mount(fetch);

    await advance(0); // failure 1
    await advance(HEALTH_RETRY_BASE_MS); // failure 2
    await advance(2 * HEALTH_RETRY_BASE_MS); // success
    expect(result.current.status).toBe('connected');

    await advance(HEALTH_POLL_INTERVAL_MS); // failure again: the wait is back to the base, not 4s
    expect(result.current.status).toBe('unreachable');
    const callsBefore = fetch.mock.calls.length;
    await advance(HEALTH_RETRY_BASE_MS - 1);
    expect(fetch).toHaveBeenCalledTimes(callsBefore);
    await advance(1);
    expect(fetch).toHaveBeenCalledTimes(callsBefore + 1);
  });

  it('treats a server error as unreachable and records the status', async () => {
    const fetch = scripted(() => jsonResponse({ error: { code: 'internal_error', message: 'Broke.' } }, 503));
    const { result } = mount(fetch);

    await advance(0);

    expect(result.current).toEqual({ status: 'unreachable', cause: 'http', httpStatus: 503 });
  });

  it('treats a reply that fails validation as unreachable, not connected', async () => {
    const fetch = scripted(() => jsonResponse({ status: 'ok' }));
    const { result } = mount(fetch);

    await advance(0);

    expect(result.current).toEqual({ status: 'unreachable', cause: 'invalid-response', httpStatus: 200 });
  });

  it('treats a request that gets no answer as unreachable (timeout) and retries', async () => {
    const fetch = vi.fn<FetchLike>(hangingFetch);
    const { result } = mount(fetch, { timeoutMs: 500 });

    await advance(499);
    expect(result.current.status).toBe('connecting');
    await advance(1);
    expect(result.current).toEqual({ status: 'unreachable', cause: 'timeout', httpStatus: null });

    await advance(HEALTH_RETRY_BASE_MS);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('stops for good on 401 and reports unauthorized', async () => {
    const fetch = scripted(() => jsonResponse({ error: { code: 'invalid_token', message: 'Bad token.' } }, 401));
    const { result } = mount(fetch);

    await advance(0);
    expect(result.current).toEqual({ status: 'unauthorized', cause: 'rejected' });

    await advance(60 * 60 * 1_000);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(result.current.status).toBe('unauthorized');
  });

  it('goes unauthorized without any request when the page has no token', async () => {
    const fetch = scripted(ok);
    const { result } = mount(fetch, { token: null });

    await advance(0);
    await advance(HEALTH_POLL_INTERVAL_MS);

    expect(result.current).toEqual({ status: 'unauthorized', cause: 'no-token' });
    expect(fetch).not.toHaveBeenCalled();
  });

  it('becomes unauthorized if the token is rejected later, for example after a backend restart', async () => {
    const fetch = scripted(ok, () => jsonResponse({ error: { code: 'invalid_token', message: 'Bad token.' } }, 401));
    const { result } = mount(fetch);
    await advance(0);
    expect(result.current.status).toBe('connected');

    await advance(HEALTH_POLL_INTERVAL_MS);

    expect(result.current).toEqual({ status: 'unauthorized', cause: 'rejected' });
    await advance(HEALTH_POLL_INTERVAL_MS * 4);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('cancels the in-flight request and all timers on unmount', async () => {
    const fetch = vi.fn<FetchLike>(hangingFetch);
    const { unmount } = mount(fetch);
    await advance(0);
    const signal = fetch.mock.calls[0]?.[1].signal;
    expect(signal?.aborted).toBe(false);

    unmount();

    expect(signal?.aborted).toBe(true);
    await advance(HEALTH_POLL_INTERVAL_MS * 4);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  describe('when the client fails with something other than an ApiError', () => {
    /**
     * The client reports every request failure as an ApiError. What it can still throw is a failure to build the
     * request at all, for example a TypeError for a page that has no usable origin (opened from a file: URL).
     */
    class FailsOnceClient extends ApiClient {
      calls = 0;

      override async get<T>(path: string, guard: (value: unknown) => value is T, options?: RequestOptions): Promise<T> {
        this.calls += 1;
        if (this.calls === 1) {
          throw new TypeError('Invalid URL');
        }
        return super.get(path, guard, options);
      }
    }

    function mountFailsOnce() {
      const client = new FailsOnceClient({ token: TEST_TOKEN, fetch: scripted(ok) });
      return { client, ...renderHook(() => useBackendHealth(client)) };
    }

    beforeEach(() => {
      vi.spyOn(console, 'error').mockImplementation(() => undefined);
    });

    it('reports it as unreachable instead of staying on "connecting" forever', async () => {
      const { result } = mountFailsOnce();

      await advance(0);

      expect(result.current).toEqual({ status: 'unreachable', cause: 'unexpected', httpStatus: null });
    });

    it('keeps retrying and recovers, instead of ending polling with an unhandled rejection', async () => {
      const { result, client } = mountFailsOnce();
      await advance(0);

      await advance(HEALTH_RETRY_BASE_MS);

      expect(client.calls).toBe(2);
      expect(result.current).toEqual({ status: 'connected', health: HEALTH_BODY });
    });

    it('does not hide the error: it is written to the console', async () => {
      mountFailsOnce();

      await advance(0);

      expect(console.error).toHaveBeenCalledWith(expect.any(String), expect.any(TypeError));
    });
  });

  it('stops polling on unmount while waiting to retry', async () => {
    const fetch = scripted(unreachable);
    const { unmount } = mount(fetch);
    await advance(0);

    unmount();
    await advance(HEALTH_RETRY_MAX_MS * 2);

    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
