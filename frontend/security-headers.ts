/**
 * Response headers recommended for serving the production build.
 *
 * Single source of truth: `vite preview` sends exactly these so the built bundle is exercised under the policy,
 * and docs/development/FRONTEND.md quotes the same policy (a test keeps the two in step). The backend sets them
 * when it serves `dist/`.
 *
 * The UI performs requests to its own origin only, loads no third-party code, fonts or images, and uses no inline
 * scripts or style attributes, so everything not listed is denied.
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
].join('; ');

export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  'Content-Security-Policy': CONTENT_SECURITY_POLICY,
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
};
