import type { ApiClient } from './api-client';
import { isRecord } from './guards';

/** Longest backend version string accepted; the value is shown in the UI. */
const MAX_VERSION_LENGTH = 64;

/** Reply of `GET /health`. Field names are the wire format. */
export interface HealthResponse {
  status: 'ok';
  schema_version: number;
  version: string;
}

/**
 * Runtime check for the `/health` body. TypeScript types vanish at runtime and the backend is an external
 * boundary, so a reply is trusted only after this passes. Unknown extra fields are tolerated so the backend can
 * add fields without breaking the UI.
 */
export function isHealthResponse(value: unknown): value is HealthResponse {
  return (
    isRecord(value) &&
    value.status === 'ok' &&
    typeof value.schema_version === 'number' &&
    Number.isInteger(value.schema_version) &&
    typeof value.version === 'string' &&
    value.version.length > 0 &&
    value.version.length <= MAX_VERSION_LENGTH
  );
}

export function fetchHealth(client: ApiClient, signal?: AbortSignal): Promise<HealthResponse> {
  return client.get('/health', isHealthResponse, { signal });
}
