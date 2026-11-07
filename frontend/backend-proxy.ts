import type { ProxyOptions } from 'vite';

/**
 * Where `npm run dev` and `npm run preview` forward backend requests, and the guard on that target.
 * Kept out of vite.config.ts so a test can import it without loading the whole Vite configuration.
 */

/** Environment variable that overrides the target. Read by the build tooling only, never injected into the bundle. */
export const BACKEND_URL_VARIABLE = 'PAI_BACKEND_URL';

/**
 * Backend paths forwarded by the dev and preview servers. Add a path here when the backend gains an endpoint the UI
 * calls; the UI must not assume endpoints that are not documented in docs/development/.
 */
export const BACKEND_PATHS: readonly string[] = ['/health'];

/**
 * The backend's own default address (`DEFAULT_HOST` and `DEFAULT_PORT` in backend/core/config.py, which is the only
 * place they are defined). tests/backend-proxy.test.ts fails when the two drift apart, so a developer who starts the
 * backend with no settings reaches it through the proxy with no settings either.
 */
export const DEFAULT_BACKEND_URL = 'http://127.0.0.1:8765';

const LOOPBACK_HOSTNAMES: ReadonlySet<string> = new Set(['127.0.0.1', 'localhost', '[::1]']);

/**
 * The proxy forwards the bearer token, so the target must be a backend on this computer. Anything else is
 * rejected instead of silently sending the token across a network. The messages never repeat the rejected value:
 * a URL can carry credentials.
 */
export function resolveBackendOrigin(configured: string | undefined): string {
  const trimmed = configured?.trim();
  const value = trimmed ? trimmed : DEFAULT_BACKEND_URL;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${BACKEND_URL_VARIABLE} is not a valid URL, for example ${DEFAULT_BACKEND_URL}.`);
  }
  const isHttp = url.protocol === 'http:' || url.protocol === 'https:';
  if (!isHttp || !LOOPBACK_HOSTNAMES.has(url.hostname)) {
    throw new Error(`${BACKEND_URL_VARIABLE} must be an http(s) URL on this computer (127.0.0.1, localhost or [::1]).`);
  }
  return url.origin;
}

/** The `server.proxy` / `preview.proxy` table: every path in `BACKEND_PATHS` goes to the configured backend. */
export function backendProxy(env: Readonly<Record<string, string>>): Record<string, ProxyOptions> {
  const target = resolveBackendOrigin(env[BACKEND_URL_VARIABLE]);
  return Object.fromEntries(BACKEND_PATHS.map((path) => [path, { target, changeOrigin: true }]));
}
