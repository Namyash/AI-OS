import { useEffect, useState } from 'react';
import type { ApiClient } from '../services/api-client';
import { ApiError } from '../services/api-error';
import { fetchHealth, type HealthResponse } from '../services/health';

/** Delay between health checks while the backend is connected. */
export const HEALTH_POLL_INTERVAL_MS = 15_000;
/** First retry delay after a failed check; doubles on every further failure. */
export const HEALTH_RETRY_BASE_MS = 1_000;
/** Longest delay between retries. */
export const HEALTH_RETRY_MAX_MS = 30_000;

/**
 * Failures that may heal on their own, so the hook keeps retrying. `unexpected` is a failure that is not an ApiError:
 * the check could not even build its request (for example the page has no usable origin), which is a bug or an
 * unusable page, shown rather than hidden.
 */
export type UnreachableCause = 'network' | 'timeout' | 'http' | 'invalid-response' | 'unexpected';

export type BackendHealth =
  | { status: 'connecting' }
  | { status: 'connected'; health: HealthResponse }
  | { status: 'unreachable'; cause: UnreachableCause; httpStatus: number | null }
  | { status: 'unauthorized' };

export interface BackendHealthOptions {
  pollIntervalMs?: number;
  retryBaseMs?: number;
  retryMaxMs?: number;
}

/**
 * Delay before retry number `failures` (1 for the first retry): base, 2x base, 4x base ... capped at `maxMs`.
 * No jitter: the only client is the local kiosk, so there is no crowd of clients to spread out.
 */
export function retryDelayMs(failures: number, baseMs: number, maxMs: number): number {
  return Math.min(maxMs, baseMs * 2 ** (failures - 1));
}

/**
 * Tracks whether the backend is reachable by calling `GET /health`.
 *
 * - Starts as `connecting` until the first check finishes.
 * - While connected it re-checks every `pollIntervalMs`.
 * - After a failed check the state is `unreachable` and checks are retried with exponential backoff; the first
 *   success resets the backoff.
 * - A 401 ends in `unauthorized` and polling stops: this window has no valid session and the page cannot create one
 *   (the kiosk launcher installs it), so asking again would only be refused again.
 * - A failure that is not an ApiError is shown as `unreachable` with cause `unexpected`, logged, and retried like
 *   any other failure; it never ends polling.
 *
 * In-flight requests and timers are cancelled on unmount or when `client` changes.
 */
export function useBackendHealth(
  client: ApiClient,
  {
    pollIntervalMs = HEALTH_POLL_INTERVAL_MS,
    retryBaseMs = HEALTH_RETRY_BASE_MS,
    retryMaxMs = HEALTH_RETRY_MAX_MS,
  }: BackendHealthOptions = {},
): BackendHealth {
  const [health, setHealth] = useState<BackendHealth>({ status: 'connecting' });

  useEffect(() => {
    const lifetime = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let failures = 0;

    const retryLater = (cause: UnreachableCause, httpStatus: number | null): void => {
      failures += 1;
      setHealth({ status: 'unreachable', cause, httpStatus });
      timer = setTimeout(check, retryDelayMs(failures, retryBaseMs, retryMaxMs));
    };

    const check = async (): Promise<void> => {
      try {
        const reply = await fetchHealth(client, lifetime.signal);
        if (lifetime.signal.aborted) {
          return;
        }
        failures = 0;
        setHealth({ status: 'connected', health: reply });
        timer = setTimeout(check, pollIntervalMs);
      } catch (error) {
        if (lifetime.signal.aborted) {
          return;
        }
        if (!(error instanceof ApiError)) {
          // The client reports every request failure as an ApiError, so this is a bug or an unusable page. Throwing
          // here would be an unhandled rejection inside a timer: no state update and no retry, leaving the bar on a
          // stale state on a kiosk with no console. Show it, log it, and keep checking.
          console.error('The backend health check failed unexpectedly.', error);
          retryLater('unexpected', null);
          return;
        }
        if (error.kind === 'unauthorized') {
          setHealth({ status: 'unauthorized' });
          return;
        }
        if (error.kind === 'aborted') {
          return;
        }
        retryLater(error.kind, error.status);
      }
    };

    void check();
    return () => {
      lifetime.abort();
      clearTimeout(timer);
    };
  }, [client, pollIntervalMs, retryBaseMs, retryMaxMs]);

  return health;
}
