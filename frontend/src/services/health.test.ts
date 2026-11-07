import { describe, expect, it, vi } from 'vitest';
import { HEALTH_BODY, jsonResponse, makeClient } from '../test/fakes';
import type { FetchLike } from './api-client';
import { ApiError } from './api-error';
import { fetchHealth, isHealthResponse } from './health';

describe('isHealthResponse', () => {
  it('accepts the documented reply', () => {
    expect(isHealthResponse({ status: 'ok', schema_version: 3, version: '1.2.3' })).toBe(true);
  });

  it('tolerates extra fields so the backend can add some without breaking the UI', () => {
    expect(isHealthResponse({ ...HEALTH_BODY, uptime_seconds: 12 })).toBe(true);
  });

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['a string', 'ok'],
    ['a number', 1],
    ['an array', [HEALTH_BODY]],
    ['an empty object', {}],
    ['a missing status', { schema_version: 1, version: '0.0.1' }],
    ['a status other than "ok"', { ...HEALTH_BODY, status: 'degraded' }],
    ['a status of the wrong type', { ...HEALTH_BODY, status: true }],
    ['a missing schema_version', { status: 'ok', version: '0.0.1' }],
    ['a schema_version that is a string', { ...HEALTH_BODY, schema_version: '1' }],
    ['a schema_version that is not an integer', { ...HEALTH_BODY, schema_version: 1.5 }],
    ['a schema_version that is NaN', { ...HEALTH_BODY, schema_version: Number.NaN }],
    ['a missing version', { status: 'ok', schema_version: 1 }],
    ['a version that is a number', { ...HEALTH_BODY, version: 1 }],
    ['an empty version', { ...HEALTH_BODY, version: '' }],
    ['a version that is implausibly long', { ...HEALTH_BODY, version: 'v'.repeat(65) }],
  ])('rejects %s', (_name, value) => {
    expect(isHealthResponse(value)).toBe(false);
  });
});

describe('fetchHealth', () => {
  it('requests /health and returns the validated reply', async () => {
    const fetch = vi.fn<FetchLike>(async () => jsonResponse(HEALTH_BODY));

    await expect(fetchHealth(makeClient(fetch))).resolves.toEqual(HEALTH_BODY);

    expect(fetch.mock.calls[0]?.[0]).toBe('http://localhost:3000/health');
  });

  it.each([
    ['not JSON', () => new Response('<html></html>', { status: 200 })],
    ['JSON of another shape', () => jsonResponse({ ok: true })],
    ['a status other than "ok"', () => jsonResponse({ ...HEALTH_BODY, status: 'starting' })],
  ])('rejects a reply that is %s as an invalid response', async (_name, reply) => {
    const fetch = vi.fn<FetchLike>(async () => reply());

    await expect(fetchHealth(makeClient(fetch))).rejects.toMatchObject({
      name: ApiError.name,
      kind: 'invalid-response',
    });
  });
});
