import { VaultError, type Credentials, type RpcResult } from '../../contracts/src/index';
export const securityHeaders = { 'Cache-Control': 'no-store, max-age=0', Pragma: 'no-cache', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' };
export function validateOrigin(request: Request, origin: string): void {
  if (request.method !== 'POST' || request.headers.get('X-Coffre-Request') !== '1') throw new VaultError('INVALID', 'Use an authenticated POST request');
  const requestOrigin = request.headers.get('Origin');
  if (requestOrigin && requestOrigin !== origin) throw new VaultError('FORBIDDEN', 'Cross-origin requests are not allowed');
  const site = request.headers.get('Sec-Fetch-Site');
  if (site && !['same-origin', 'none'].includes(site)) throw new VaultError('FORBIDDEN', 'Cross-origin requests are not allowed');
}
export function credentialsFrom(request: Request): Credentials {
  const authorization = request.headers.get('Authorization');
  if (authorization && !authorization.startsWith('Bearer ')) throw new VaultError('UNAUTHENTICATED', 'Unsupported authentication');
  return { accessJwt: request.headers.get('Cf-Access-Jwt-Assertion') ?? undefined, bearer: authorization?.slice(7) };
}
export async function limitedJson(request: Request, limit = 131072): Promise<unknown> {
  if (!request.headers.get('Content-Type')?.toLowerCase().startsWith('application/json')) throw new VaultError('INVALID', 'Expected application/json');
  if (Number(request.headers.get('Content-Length') ?? 0) > limit) throw new VaultError('INVALID', 'Request is too large');
  const reader = request.body?.getReader();
  if (!reader) throw new VaultError('INVALID', 'A request body is required');
  const chunks: Uint8Array[] = []; let size = 0;
  try { while (true) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > limit) { await reader.cancel(); throw new VaultError('INVALID', 'Request is too large'); } chunks.push(value); } }
  finally { reader.releaseLock(); }
  const all = new Uint8Array(size); let at = 0; for (const chunk of chunks) { all.set(chunk, at); at += chunk.length; }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(all)); } catch { throw new VaultError('INVALID', 'Invalid JSON'); }
}
export function failure(error: unknown, requestId: string): RpcResult {
  return { ok: false, error: { code: error instanceof VaultError ? error.code : 'UNAVAILABLE', message: error instanceof VaultError ? error.message : 'The operation could not be completed. No success has been acknowledged.', requestId } };
}
export function rpcResponse(result: RpcResult): Response {
  const codes: Record<string, number> = { UNAUTHENTICATED: 401, FORBIDDEN: 403, NOT_FOUND: 404, CONFLICT: 409, INVALID: 400, PROTECTED: 409, UNAVAILABLE: 503 };
  return Response.json(result, { status: result.ok ? 200 : codes[result.error.code] ?? 503, headers: securityHeaders });
}
