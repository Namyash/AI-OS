/**
 * Fragment parameter in which the access token reaches the page: `#token=<value>`. The backend generates the token;
 * how it gets from the backend to this fragment is the kiosk launcher's job (milestone M1.4b, not built yet).
 */
const TOKEN_PARAM = 'token';

/**
 * Visible ASCII only. Whitespace and control characters are not allowed in a bearer credential, and anything
 * else could not be sent as an HTTP header value anyway.
 */
const TOKEN_PATTERN = /^[\x21-\x7e]+$/;

interface LocationLike {
  readonly pathname: string;
  readonly search: string;
  readonly hash: string;
}

interface HistoryLike {
  readonly state: unknown;
  replaceState(data: unknown, unused: string, url?: string | URL | null): void;
}

function decode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    // Not valid percent-encoding: use the value as written. The pattern check still applies.
    return value;
  }
}

/**
 * Reads the access token from the URL fragment and removes it from the address bar in the same step.
 *
 * Call exactly once, at startup, before anything renders: after the first call the fragment is gone, so a second
 * call returns null. The token is returned to the caller and must be kept in memory only (never in
 * localStorage, sessionStorage, cookies, the query string or a log).
 *
 * Only the `token` parameter is removed; other fragment parameters, the path and the query are left as they were.
 * Returns null when no token was supplied or the supplied value is not a usable bearer token.
 */
export function captureTokenFromUrl(location: LocationLike, history: HistoryLike): string | null {
  const fragment = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash;
  if (fragment === '') {
    return null;
  }

  let rawToken: string | null = null;
  const kept: string[] = [];
  for (const pair of fragment.split('&')) {
    const separator = pair.indexOf('=');
    const key = separator === -1 ? pair : pair.slice(0, separator);
    if (key !== TOKEN_PARAM) {
      kept.push(pair);
    } else if (rawToken === null) {
      rawToken = separator === -1 ? '' : pair.slice(separator + 1);
    }
  }
  if (rawToken === null) {
    return null;
  }

  // Strip first, validate second: even a malformed token must not stay in the address bar.
  const remainingFragment = kept.length > 0 ? `#${kept.join('&')}` : '';
  history.replaceState(history.state, '', `${location.pathname}${location.search}${remainingFragment}`);

  // Decoded with decodeURIComponent, not URLSearchParams, so a literal "+" in the token is not turned into a space.
  const token = decode(rawToken);
  return TOKEN_PATTERN.test(token) ? token : null;
}
