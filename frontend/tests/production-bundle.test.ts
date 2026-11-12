// @vitest-environment node
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build, type Rollup } from 'vite';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { BACKEND_URL_VARIABLE, DEV_TOKEN_FILE_VARIABLE } from '../backend-proxy';

/**
 * The development token workflow (PAI_DEV_TOKEN_FILE and the header the dev proxy adds) lives in the build tooling.
 * The production bundle must hold no trace of it: no variable name, no file path, no token, no Authorization header.
 * The page authenticates with the session cookie the kiosk launcher installs, and nothing else.
 *
 * This builds the project for real, with the dev variables set to marker values, and reads every file of the output.
 */
const frontendRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Obviously fake marker values: if one of them turns up in the output, the dev settings leaked into the build. */
const MARKER_TOKEN = 'fake-dev-token-marker-0123456789';
const MARKER_DIRECTORY = 'pai-bundle-marker-directory';
const MARKER_BACKEND = 'http://127.0.0.1:59999';

const scratch = mkdtempSync(join(tmpdir(), `${MARKER_DIRECTORY}-`));
const tokenFile = join(scratch, 'dev-token');
let outputs: Array<{ name: string; text: string }>;

beforeAll(async () => {
  writeFileSync(tokenFile, MARKER_TOKEN);
  vi.stubEnv(DEV_TOKEN_FILE_VARIABLE, tokenFile);
  vi.stubEnv(BACKEND_URL_VARIABLE, MARKER_BACKEND);

  const result = await build({
    root: frontendRoot,
    configFile: join(frontendRoot, 'vite.config.ts'),
    mode: 'production',
    logLevel: 'silent',
    build: { write: false },
  });

  const results = (Array.isArray(result) ? result : [result]) as Array<Rollup.RollupOutput | Rollup.RollupWatcher>;
  outputs = results
    .flatMap((entry) => ('output' in entry ? entry.output : []))
    .map((file) => ({
      name: file.fileName,
      // Text of scripts, styles and html; binary assets (the font files) cannot hold these strings as text.
      text: file.type === 'chunk' ? file.code : typeof file.source === 'string' ? file.source : '',
    }));
}, 120_000);

afterAll(() => {
  vi.unstubAllEnvs();
  rmSync(scratch, { recursive: true, force: true });
});

describe('production bundle', () => {
  it('is built and read (guards against scanning nothing)', () => {
    const names = outputs.map(({ name }) => name);

    expect(names).toContain('index.html');
    expect(names.some((name) => name.endsWith('.js'))).toBe(true);
    expect(outputs.filter(({ text }) => text !== '').length).toBeGreaterThanOrEqual(3);
  });

  it.each([
    ['the token file variable', DEV_TOKEN_FILE_VARIABLE],
    ['the backend target variable', BACKEND_URL_VARIABLE],
    ['the token file path', tokenFile],
    ['the token file directory', MARKER_DIRECTORY],
    ['the token', MARKER_TOKEN],
    ['the proxy target', MARKER_BACKEND],
  ])('does not contain %s', (_name, needle) => {
    const offenders = outputs.filter(({ text }) => text.includes(needle)).map(({ name }) => name);

    expect(offenders).toEqual([]);
  });

  it('sets no Authorization header and holds no bearer credential or proxy hook', () => {
    const offenders = outputs
      .filter(({ text }) => /authorization|bearer|proxyReq|readDevToken|backend-proxy/i.test(text))
      .map(({ name }) => name);

    expect(offenders).toEqual([]);
  });
});
