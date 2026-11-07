import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

/**
 * Test configuration. It is a separate file on purpose: Vitest prefers vitest.config.ts over vite.config.ts, so the
 * tests never load the dev/preview proxy settings and a PAI_BACKEND_URL meant for the dev server cannot break them.
 */
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    environmentOptions: { jsdom: { url: 'http://localhost:3000/' } },
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}', 'tests/**/*.test.ts'],
    restoreMocks: true,
    unstubGlobals: true,
    unstubEnvs: true,
  },
});
