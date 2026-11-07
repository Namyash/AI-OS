// @vitest-environment node
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  BACKEND_PATHS,
  BACKEND_URL_VARIABLE,
  backendProxy,
  DEFAULT_BACKEND_URL,
  resolveBackendOrigin,
} from '../backend-proxy';
import viteConfig from '../vite.config';

/**
 * The dev and preview servers forward the bearer token to the proxy target, so the target must be the backend
 * and must be on this computer. These tests keep both properties from regressing.
 *
 * Runs in the node environment: importing vite.config.ts loads Vite and esbuild, which jsdom's globals break.
 */
const frontendRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const repositoryRoot = join(frontendRoot, '..');

function read(...segments: string[]): string {
  return readFileSync(join(repositoryRoot, ...segments), 'utf8');
}

/** The backend's default address, read from the only file that defines it. */
function backendDefaultOrigin(): string {
  const source = read('backend', 'core', 'config.py');
  const host = /^DEFAULT_HOST\s*=\s*"([^"]+)"/m.exec(source)?.[1];
  const port = /^DEFAULT_PORT\s*=\s*(\d+)/m.exec(source)?.[1];
  if (host === undefined || port === undefined) {
    throw new Error('DEFAULT_HOST or DEFAULT_PORT not found in backend/core/config.py: update this test with it.');
  }
  return `http://${host}:${port}`;
}

describe('default proxy target', () => {
  it('is the address the backend listens on when it has no settings', () => {
    expect(DEFAULT_BACKEND_URL).toBe(backendDefaultOrigin());
    expect(resolveBackendOrigin(undefined)).toBe(backendDefaultOrigin());
  });

  it.each([
    ['frontend/.env.example', () => readFileSync(join(frontendRoot, '.env.example'), 'utf8')],
    ['docs/development/FRONTEND.md', () => read('docs', 'development', 'FRONTEND.md')],
  ])('is the one written in %s', (_name, load) => {
    expect(load()).toContain(DEFAULT_BACKEND_URL);
  });
});

describe('resolveBackendOrigin', () => {
  it.each([undefined, '', '   '])('falls back to the default for %j', (value) => {
    expect(resolveBackendOrigin(value)).toBe(DEFAULT_BACKEND_URL);
  });

  it.each([
    ['http://127.0.0.1:9000', 'http://127.0.0.1:9000'],
    ['http://localhost:9000', 'http://localhost:9000'],
    ['http://[::1]:9000', 'http://[::1]:9000'],
    ['https://127.0.0.1:9443', 'https://127.0.0.1:9443'],
    ['  http://127.0.0.1:9000  ', 'http://127.0.0.1:9000'],
    ['http://127.0.0.1:9000/some/path?x=1', 'http://127.0.0.1:9000'],
  ])('accepts a backend on this computer: %j', (value, origin) => {
    expect(resolveBackendOrigin(value)).toBe(origin);
  });

  it.each([
    ['another host', 'http://backend.internal:8765'],
    ['a private network address', 'http://10.0.0.5:8765'],
    ['the unspecified address', 'http://0.0.0.0:8765'],
    ['a host that only starts with localhost', 'http://localhost.attacker.example'],
    ['a host that only starts with an address', 'http://127.0.0.1.attacker.example'],
    ['a host that only starts with 127.', 'http://127.attacker.example'],
    ['a host that only ends with localhost', 'http://notlocalhost:8765'],
    ['a sub-domain of localhost', 'http://backend.localhost:8765'],
    ['credentials that make a loopback address look like the user name', 'http://127.0.0.1@attacker.example'],
    ['a loopback address in the fragment', 'http://attacker.example#@127.0.0.1'],
    ['a loopback address in the path', 'http://attacker.example/127.0.0.1'],
    ['another scheme', 'ftp://127.0.0.1'],
    ['a file URL', 'file:///etc/passwd'],
    ['a name that is not a URL', 'not a url'],
    ['an address without a scheme', '127.0.0.1:8765'],
  ])('refuses %s', (_name, value) => {
    expect(() => resolveBackendOrigin(value)).toThrow(BACKEND_URL_VARIABLE);
  });

  it('does not repeat a refused value, which may carry credentials', () => {
    let message: string | undefined;
    try {
      resolveBackendOrigin('http://user:hunter2@attacker.example');
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }

    expect(message).toContain(BACKEND_URL_VARIABLE);
    expect(message).not.toMatch(/hunter2|attacker/);
  });
});

describe('backendProxy', () => {
  it('forwards every backend path to the configured backend, and nothing else', () => {
    const proxy = backendProxy({ [BACKEND_URL_VARIABLE]: 'http://127.0.0.1:9000' });

    expect(Object.keys(proxy)).toEqual([...BACKEND_PATHS]);
    for (const options of Object.values(proxy)) {
      expect(options).toMatchObject({ target: 'http://127.0.0.1:9000', changeOrigin: true });
    }
  });

  it('uses the default target when the variable is not set', () => {
    expect(Object.values(backendProxy({}))[0]).toMatchObject({ target: DEFAULT_BACKEND_URL });
  });

  it('refuses a target that is not on this computer', () => {
    expect(() => backendProxy({ [BACKEND_URL_VARIABLE]: 'http://backend.internal:8765' })).toThrow(
      BACKEND_URL_VARIABLE,
    );
  });
});

describe('vite.config.ts', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('does not look at the proxy target when building, so a stray variable cannot break `npm run build`', () => {
    vi.stubEnv(BACKEND_URL_VARIABLE, 'http://backend.internal:8765');

    const config = viteConfig({ command: 'build', mode: 'production' });

    expect(config.server?.proxy).toBeUndefined();
    expect(config.preview?.proxy).toBeUndefined();
  });

  it('refuses to start the dev and preview servers when the target is not on this computer', () => {
    vi.stubEnv(BACKEND_URL_VARIABLE, 'http://backend.internal:8765');

    expect(() => viteConfig({ command: 'serve', mode: 'development' })).toThrow(BACKEND_URL_VARIABLE);
    expect(() => viteConfig({ command: 'serve', mode: 'production', isPreview: true })).toThrow(BACKEND_URL_VARIABLE);
  });

  it('gives the dev and preview servers the same proxy, bound to this computer only', () => {
    vi.stubEnv(BACKEND_URL_VARIABLE, 'http://127.0.0.1:9000');

    const config = viteConfig({ command: 'serve', mode: 'development' });

    expect(config.server?.proxy).toEqual(backendProxy({ [BACKEND_URL_VARIABLE]: 'http://127.0.0.1:9000' }));
    expect(config.preview?.proxy).toEqual(config.server?.proxy);
    expect(config.server?.host).toBe('127.0.0.1');
    expect(config.preview?.host).toBe('127.0.0.1');
  });
});

describe('test runner configuration', () => {
  it('is separate from vite.config.ts, so the tests never load the proxy settings', () => {
    const runnerConfig = readFileSync(join(frontendRoot, 'vitest.config.ts'), 'utf8');

    expect(runnerConfig).toContain('environment:');
    expect(runnerConfig).not.toMatch(/backend-proxy|proxy:/);
  });
});
