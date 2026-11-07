import { posix } from 'node:path';
import { describe, expect, it } from 'vitest';
import { applicationFiles, importSpecifiers } from './support/source-files';

/**
 * Layering from docs/development/FRONTEND.md: dependencies point one way. Each folder under src/ lists the folders
 * it may import from (itself included). `App.tsx` and `main.tsx` sit above all of them and are not restricted.
 */
const MAY_IMPORT: Readonly<Record<string, readonly string[]>> = {
  services: ['services'],
  hooks: ['hooks', 'services'],
  components: ['components', 'hooks'],
  features: ['features', 'components', 'hooks', 'services'],
};

const files = applicationFiles();

/** Relative imports of a file as `src/<folder>/...` paths. Packages (`react`) are not part of the layering. */
function localImports(path: string, source: string): Array<{ specifier: string; target: string }> {
  return importSpecifiers(source)
    .filter((specifier) => specifier.startsWith('.'))
    .map((specifier) => ({ specifier, target: posix.normalize(posix.join(posix.dirname(path), specifier)) }));
}

describe('layering', () => {
  it.each(Object.keys(MAY_IMPORT))('%s has files to check (guards against checking nothing)', (layer) => {
    expect(files.filter(({ path }) => path.startsWith(`src/${layer}/`)).length).toBeGreaterThan(0);
  });

  it.each(Object.entries(MAY_IMPORT))('%s imports only from %j', (layer, allowed) => {
    const violations = files
      .filter(({ path }) => path.startsWith(`src/${layer}/`))
      .flatMap(({ path, source }) =>
        localImports(path, source)
          .filter(({ target }) => {
            const [top, folder] = target.split('/');
            return top !== 'src' || folder === undefined || !allowed.includes(folder);
          })
          .map(({ specifier }) => `${path} imports ${specifier}`),
      );

    expect(violations).toEqual([]);
  });
});
