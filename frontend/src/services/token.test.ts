import { afterEach, describe, expect, it, vi } from 'vitest';
import { captureTokenFromUrl } from './token';

function openPage(url: string): void {
  window.history.replaceState(null, '', url);
}

function capture(): string | null {
  return captureTokenFromUrl(window.location, window.history);
}

afterEach(() => openPage('/'));

describe('captureTokenFromUrl', () => {
  it('returns the token and removes the whole fragment from the address bar', () => {
    openPage('/#token=abc123');

    expect(capture()).toBe('abc123');

    expect(window.location.hash).toBe('');
    expect(window.location.href).toBe('http://localhost:3000/');
  });

  it('replaces the history entry instead of adding one, so the token is not left behind in history', () => {
    openPage('/#token=abc123');
    const entries = window.history.length;

    capture();

    expect(window.history.length).toBe(entries);
  });

  it('removes only the token and keeps the path, the query and other fragment parameters', () => {
    openPage('/app?view=1#a=1&token=abc123&b=2');

    expect(capture()).toBe('abc123');

    expect(window.location.pathname).toBe('/app');
    expect(window.location.search).toBe('?view=1');
    expect(window.location.hash).toBe('#a=1&b=2');
  });

  it('can only be taken once: a second call finds nothing', () => {
    openPage('/#token=abc123');

    expect(capture()).toBe('abc123');
    expect(capture()).toBeNull();
  });

  it('uses the first token parameter and removes every one of them', () => {
    openPage('/#token=first&token=second');

    expect(capture()).toBe('first');
    expect(window.location.hash).toBe('');
  });

  it('decodes percent-encoding but keeps a literal "+" (it is not a space)', () => {
    openPage('/#token=a%2Fb%3D');
    expect(capture()).toBe('a/b=');

    openPage('/#token=a+b/c==');
    expect(capture()).toBe('a+b/c==');
  });

  it('uses a value that is not valid percent-encoding as written', () => {
    openPage('/#token=abc%zz');

    expect(capture()).toBe('abc%zz');
  });

  it('returns null and leaves the URL alone when there is no token', () => {
    openPage('/page?x=1#section=2');

    expect(capture()).toBeNull();
    expect(window.location.href).toBe('http://localhost:3000/page?x=1#section=2');
  });

  it('returns null for an empty fragment', () => {
    openPage('/#');

    expect(capture()).toBeNull();
  });

  it.each([
    ['empty', '#token='],
    ['containing a space', '#token=has%20space'],
    ['containing a control character', '#token=ab%00cd'],
    ['containing non-ASCII characters', '#token=caf%C3%A9'],
  ])('rejects a token that is %s, but still removes it from the address bar', (_name, fragment) => {
    openPage(`/${fragment}`);

    expect(capture()).toBeNull();
    expect(window.location.hash).toBe('');
  });

  it('does not persist the token anywhere: no web storage, no cookie', () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    openPage('/#token=abc123');

    capture();

    expect(setItem).not.toHaveBeenCalled();
    expect(document.cookie).toBe('');
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });
});
