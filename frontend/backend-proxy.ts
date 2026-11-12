import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import type { ProxyOptions } from 'vite';

/**
 * Where `npm run dev` and `npm run preview` forward backend requests, the guard on that target, and the optional
 * development credential added on the way. Kept out of vite.config.ts so a test can import it without loading the
 * whole Vite configuration. Nothing here is imported by `src/`, so none of it can reach the browser bundle.
 */

/** Environment variable that overrides the target. Read by the build tooling only, never injected into the bundle. */
export const BACKEND_URL_VARIABLE = 'PAI_BACKEND_URL';

/**
 * Environment variable naming a file that holds a backend bearer token (the file the backend writes at `PAI_TOKEN_FILE`).
 * Development only: in the kiosk the page authenticates with the session cookie installed by the launcher and
 * no token is involved. Read by the build tooling only; the path and the token never enter the bundle.
 */
export const DEV_TOKEN_FILE_VARIABLE = 'PAI_DEV_TOKEN_FILE';

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
 * The proxy may add the developer's bearer token to every request, so the target must be a backend on this computer.
 * Anything else is rejected instead of silently sending the token across a network. The messages never repeat the
 * rejected value: a URL can carry credentials.
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

/**
 * Visible ASCII only. The value becomes an HTTP header value, so a line break or other control character (a file
 * that holds more than a token) must never get through. The backend's own tokens are far shorter than the cap.
 */
const TOKEN_PATTERN = /^[\x21-\x7e]+$/;
const MAX_TOKEN_LENGTH = 512;

export type DevTokenProblem = 'unreadable' | 'empty' | 'malformed';

export type DevTokenResult = { token: string } | { problem: DevTokenProblem };

/**
 * Reads the token from the file the developer named. Surrounding whitespace (the newline an editor or shell adds) is
 * ignored. Never throws and never puts the file's content in a message: a problem is reported by kind only.
 */
export function readDevToken(file: string): DevTokenResult {
  let contents: string;
  try {
    contents = readFileSync(file, 'utf8');
  } catch {
    return { problem: 'unreadable' };
  }
  const token = contents.trim();
  if (token === '') {
    return { problem: 'empty' };
  }
  return token.length <= MAX_TOKEN_LENGTH && TOKEN_PATTERN.test(token) ? { token } : { problem: 'malformed' };
}

const PROBLEM_DESCRIPTION: Readonly<Record<DevTokenProblem, string>> = {
  unreadable: 'cannot be read',
  empty: 'is empty',
  malformed: 'does not hold one token on a single line of visible characters',
};

type Warn = (message: string) => void;

interface HeaderTarget {
  setHeader(name: string, value: string): unknown;
}

/**
 * Returns the handler that adds `Authorization: Bearer <token>` to a request on its way to the backend.
 *
 * The file is read for every request, so the token the backend issues at each start is picked up without restarting the
 * dev server. When it cannot be used the request is forwarded without the header (the backend then answers 401 and
 * the UI says so) and one warning is printed, again after the file has worked in between. The warning names the
 * variable and the kind of problem, never the path or the token.
 */
function devTokenInjector(file: string, warn: Warn): (request: HeaderTarget) => void {
  let reported: DevTokenProblem | undefined;
  return (request) => {
    const result = readDevToken(file);
    if ('problem' in result) {
      if (reported !== result.problem) {
        reported = result.problem;
        warn(
          `${DEV_TOKEN_FILE_VARIABLE} is set but the file ${PROBLEM_DESCRIPTION[result.problem]}: requests go to the backend without credentials.`,
        );
      }
      return;
    }
    reported = undefined;
    request.setHeader('Authorization', `Bearer ${result.token}`);
  };
}

/** The token file, as an absolute path (like the backend's own `PAI_TOKEN_FILE`), or undefined when not configured. */
function resolveDevTokenFile(configured: string | undefined): string | undefined {
  const trimmed = configured?.trim();
  if (!trimmed) {
    return undefined;
  }
  if (!isAbsolute(trimmed)) {
    throw new Error(`${DEV_TOKEN_FILE_VARIABLE} must be an absolute path.`);
  }
  return trimmed;
}

/**
 * The `server.proxy` / `preview.proxy` table: every path in `BACKEND_PATHS` goes to the configured backend, with the
 * developer's token added when `PAI_DEV_TOKEN_FILE` is set.
 *
 * The target is checked first, so a target that is not on this computer throws before the token file is looked at:
 * the token is only ever attached to requests for a loopback backend.
 */
export function backendProxy(
  env: Readonly<Record<string, string>>,
  warn: Warn = console.warn,
): Record<string, ProxyOptions> {
  const target = resolveBackendOrigin(env[BACKEND_URL_VARIABLE]);
  const tokenFile = resolveDevTokenFile(env[DEV_TOKEN_FILE_VARIABLE]);

  const options: ProxyOptions = { target, changeOrigin: true };
  if (tokenFile !== undefined) {
    const inject = devTokenInjector(tokenFile, warn);
    options.configure = (proxy) => {
      proxy.on('proxyReq', inject);
    };
  }
  return Object.fromEntries(BACKEND_PATHS.map((path) => [path, options]));
}
