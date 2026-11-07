import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

/** Helpers for the tests that read the application source instead of running it. */

export const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const sourceRoot = join(root, 'src');

export interface SourceFile {
  /** Path from the frontend root, with forward slashes: `src/services/token.ts`. */
  path: string;
  /** The file as written. */
  source: string;
  /** The same file with its comments removed (see `withoutComments`). */
  code: string;
}

/**
 * Removes comments so that a comment may name what the code avoids (for example "never in localStorage") without
 * failing a guard.
 *
 * Scripts go through the TypeScript compiler, which knows a `//` inside a string, a URL or JSX text from a comment;
 * a regular expression cannot tell them apart and would delete `'//host/x'` as if it were a comment. Types are
 * erased in the process, which does not matter here: guards look for what the code does. CSS has only block
 * comments, so `//` there is part of a value such as `url(//host/x.css)`.
 */
export function withoutComments(text: string, fileName: string): string {
  if (fileName.endsWith('.css')) {
    return text.replace(/\/\*[\s\S]*?\*\//g, '');
  }
  return ts.transpileModule(text, {
    fileName,
    compilerOptions: {
      removeComments: true,
      target: ts.ScriptTarget.ESNext,
      module: ts.ModuleKind.ESNext,
      jsx: ts.JsxEmit.Preserve,
    },
  }).outputText;
}

/**
 * True when the text contains `//` followed by something: an absolute URL (`https://host`, `wss://host`, any scheme)
 * or a protocol-relative one (`//host/x`), the two ways to name a resource on another origin. Run it on text that
 * has no comments, where a double slash has no other business.
 */
export function mentionsRemoteResource(text: string): boolean {
  return /\/\/\S/.test(text);
}

/** Application source: every .ts, .tsx and .css file under src/ except tests and test helpers. */
export function applicationFiles(): SourceFile[] {
  return readdirSync(sourceRoot, { recursive: true, encoding: 'utf8' })
    .map((entry) => join(sourceRoot, entry))
    .filter((path) => /\.(ts|tsx|css)$/.test(path))
    .map((path) => ({ path: relative(root, path).split(sep).join('/'), absolute: path }))
    .filter(({ path }) => !/\.test\.tsx?$/.test(path) && !path.startsWith('src/test/'))
    .map(({ path, absolute }) => {
      const source = readFileSync(absolute, 'utf8');
      return { path, source, code: withoutComments(source, path) };
    });
}

/** Module specifiers a script imports, re-exports or dynamically imports. Comments are ignored; type-only imports count. */
export function importSpecifiers(source: string): string[] {
  return ts.preProcessFile(source, true, true).importedFiles.map((reference) => reference.fileName);
}
