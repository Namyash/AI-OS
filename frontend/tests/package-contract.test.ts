import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The install must work with the Node and npm that the target image ships, because `.npmrc` sets `engine-strict`
 * and a failed engine check aborts `npm ci`.
 */
const root = join(dirname(fileURLToPath(import.meta.url)), '..');

function readJson(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(root, name), 'utf8')) as Record<string, unknown>;
}

describe('package.json engines', () => {
  const { engines } = readJson('package.json') as { engines?: Record<string, string> };

  it('require a Node version', () => {
    expect(engines?.node).toMatch(/^>=\d+\.\d+\.\d+$/);
  });

  it('name no npm version: the npm that ships with the supported Node must be able to install this project', () => {
    // Debian 13 packages Node 20 with npm 9, and nothing here needs npm 10 (the lockfile format is readable by npm 9).
    // A bound would make `npm ci` fail on that image with EBADENGINE although the install, tests and build work.
    expect(engines).not.toHaveProperty('npm');
  });
});

describe('package-lock.json', () => {
  it('records the same engines as package.json, so the two cannot disagree about what is supported', () => {
    const lock = readJson('package-lock.json') as { packages: Record<string, { engines?: unknown }> };

    expect(lock.packages['']?.engines).toEqual(readJson('package.json').engines);
  });
});
