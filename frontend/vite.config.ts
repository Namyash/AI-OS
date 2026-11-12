import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv } from 'vite';
import { backendProxy } from './backend-proxy';
import { SECURITY_HEADERS } from './security-headers';

/**
 * Build, dev server and preview server. The tests have their own file (vitest.config.ts).
 */
export default defineConfig(({ command, mode }) => {
  // Only the servers use the proxy, and both `dev` and `preview` run as the 'serve' command. Resolving it here and
  // nowhere else means a PAI_BACKEND_URL that is refused stops the servers, which could attach the developer's token
  // to requests for it, and cannot break `build`: a production build never reads PAI_BACKEND_URL or
  // PAI_DEV_TOKEN_FILE. Only PAI_* variables are read, and only here (Vite exposes VITE_* variables to client code,
  // and none are used).
  const proxy = command === 'serve' ? backendProxy(loadEnv(mode, process.cwd(), 'PAI_')) : undefined;

  return {
    // Relative asset URLs: the backend serves dist/ from the site root, and a relative base also works from any mount.
    base: './',
    plugins: [react()],
    build: {
      // No data: URIs, so the Content-Security-Policy can keep `img-src 'self'`.
      assetsInlineLimit: 0,
    },
    // Loopback only: the dev and preview servers must not be reachable from the network.
    server: { host: '127.0.0.1', proxy },
    preview: { host: '127.0.0.1', proxy, headers: SECURITY_HEADERS },
  };
});
