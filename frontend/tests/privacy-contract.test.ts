import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CONTENT_SECURITY_POLICY } from '../security-headers';
import { applicationFiles, mentionsRemoteResource, root, withoutComments } from './support/source-files';

/**
 * Static guards for the privacy contract in docs/development/FRONTEND.md. They read the source, so a change that
 * would let the UI reach beyond its own origin or persist the access token fails here, not in review.
 */
const files = applicationFiles();

/** Ways for script to talk to the network. Only the API client may use them. */
const NETWORK_API =
  /\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|serviceWorker|importScripts|\bnew\s+Image\s*\(/;

describe('application source', () => {
  it('is found (guards against these checks silently scanning nothing)', () => {
    expect(files.length).toBeGreaterThan(10);
  });

  it('performs network I/O only in services/api-client.ts', () => {
    const offenders = files
      .filter(({ path }) => path !== 'src/services/api-client.ts')
      .filter(({ code }) => NETWORK_API.test(code))
      .map(({ path }) => path);

    expect(offenders).toEqual([]);
  });

  it('never persists anything in the browser: no web storage, cookies or IndexedDB (the token lives in memory only)', () => {
    const offenders = files
      .filter(({ code }) => /localStorage|sessionStorage|document\.cookie|indexedDB/.test(code))
      .map(({ path }) => path);

    expect(offenders).toEqual([]);
  });

  it('names no other origin: no absolute or protocol-relative URL in script or CSS', () => {
    const offenders = files.filter(({ code }) => mentionsRemoteResource(code)).map(({ path }) => path);

    expect(offenders).toEqual([]);
  });

  it('uses no style attributes or inline scripts that the Content-Security-Policy would block', () => {
    const offenders = files
      .filter(({ path }) => path.endsWith('.tsx'))
      .filter(({ code }) => /\bstyle=\{|dangerouslySetInnerHTML|\beval\(|new Function\(/.test(code))
      .map(({ path }) => path);

    expect(offenders).toEqual([]);
  });
});

/**
 * The guards above are only worth something if they catch what they are for. These feed them the leaks a review
 * once showed them missing: a protocol-relative URL looked like a comment and was deleted before the check ran.
 */
describe('the guards catch what they are for', () => {
  const flagged = (file: string, text: string) => mentionsRemoteResource(withoutComments(text, file));

  it.each([
    ['a CSS @import of a protocol-relative URL', 'x.css', '@import url(//fonts.example.com/a.css);'],
    ['a CSS url() with an absolute URL', 'x.css', 'a { background: url(https://cdn.example/a.png); }'],
    ['an image loaded from a protocol-relative URL', 'x.ts', "new Image().src = '//evil.example/p.gif';"],
    ['a dynamic import of a protocol-relative URL', 'x.ts', "export const m = import('//evil.example/x.js');"],
    ['an absolute URL in a string', 'x.ts', "export const url = 'https://evil.example/';"],
    ['a WebSocket URL', 'x.ts', "export const socket = new WebSocket('wss://evil.example');"],
    ['an absolute URL in JSX text', 'x.tsx', 'export const A = () => <p>http://evil.example</p>;'],
  ])('flags %s', (_name, file, text) => {
    expect(flagged(file, text)).toBe(true);
  });

  it.each([
    ['a line comment that names a URL', 'x.ts', '// see https://example.com/docs\nexport const a = 1;'],
    ['a block comment that names a URL', 'x.ts', '/* see //example.com */\nexport const a = 1;'],
    ['a JSX comment that names a URL', 'x.tsx', 'export const A = () => <p>{/* https://example.com */}hi</p>;'],
    ['a CSS comment that names a URL', 'x.css', '/* https://example.com */\na { color: red; }'],
    ['paths on the same origin', 'x.ts', "export const path = '/health'; export const asset = './a.css';"],
  ])('ignores %s', (_name, file, text) => {
    expect(flagged(file, text)).toBe(false);
  });

  it.each([
    ['fetch', "fetch('/x')"],
    ['an image request', "new Image().src = '/x.gif'"],
    ['a beacon', "navigator.sendBeacon('/x')"],
    ['a socket', "new WebSocket('/x')"],
  ])('treats %s as network I/O', (_name, text) => {
    expect(NETWORK_API.test(withoutComments(text, 'x.ts'))).toBe(true);
  });
});

describe('index.html', () => {
  const html = readFileSync(join(root, 'index.html'), 'utf8');

  it('has no inline script and loads scripts only from its own origin', () => {
    const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];

    expect(scripts.length).toBeGreaterThan(0);
    for (const [, attributes = '', body = ''] of scripts) {
      expect(body.trim()).toBe('');
      expect(attributes).toMatch(/\bsrc="(?:\.|\/)[^"]*"/);
      expect(attributes).not.toMatch(/src="(?:https?:)?\/\//);
    }
  });

  it('references no external resources and no inline styles', () => {
    expect(mentionsRemoteResource(html)).toBe(false);
    expect(html).not.toMatch(/\sstyle=|<style\b/i);
  });
});

describe('Content-Security-Policy', () => {
  const directives = new Map(
    CONTENT_SECURITY_POLICY.split(';').map((directive) => {
      const [name = '', ...sources] = directive.trim().split(/\s+/);
      return [name, sources] as const;
    }),
  );

  it('denies everything by default', () => {
    expect(directives.get('default-src')).toEqual(["'none'"]);
  });

  it("allows only the page's own origin (or nothing) in every directive", () => {
    for (const [name, sources] of directives) {
      if (['base-uri', 'form-action', 'frame-ancestors', 'object-src', 'default-src'].includes(name)) {
        expect(sources, name).toEqual(["'none'"]);
      } else {
        expect(sources, name).toEqual(["'self'"]);
      }
    }
  });

  it('is the policy documented in docs/development/FRONTEND.md', () => {
    const doc = readFileSync(join(root, '..', 'docs', 'development', 'FRONTEND.md'), 'utf8');

    expect(doc).toContain(CONTENT_SECURITY_POLICY);
  });
});
