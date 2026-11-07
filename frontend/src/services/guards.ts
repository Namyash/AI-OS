/** Narrowing helper for hand-written type guards on external data (the backend is an untrusted boundary). */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
