import handler from '@tanstack/react-start/server-entry';
import type { ExecutionContext } from '@cloudflare/workers-types';
// Buffer bounded POST bodies before any framework parser runs, including server functions.
async function bounded(request: Request, limit: number): Promise<Request> {
  if (!request.body) return request;
  if (Number(request.headers.get('Content-Length') ?? 0) > limit) throw new Error('size');
  const reader = request.body.getReader(), chunks: Uint8Array[] = []; let length = 0;
  try { for (;;) { const part = await reader.read(); if (part.done) break; length += part.value.length; if (length > limit) { await reader.cancel(); throw new Error('size'); } chunks.push(part.value); } } finally { reader.releaseLock(); }
  const body = new Uint8Array(length); let offset = 0; for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
  return new Request(request.url, { method: request.method, headers: request.headers, body, redirect: 'error' });
}
export default {
  async fetch(request: Request, env: { PUBLIC_ORIGIN: string; STAGE: string }, _ctx: ExecutionContext) {
    if (env.STAGE !== 'local' && (!env.PUBLIC_ORIGIN?.startsWith('https://') || new URL(request.url).origin !== env.PUBLIC_ORIGIN)) return new Response('Unknown origin', { status: 421 });
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) { try { request = await bounded(request, 131072); } catch { return new Response('Request too large', { status: 413 }); } }
    const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(18))));
    const response = await handler.fetch(request, { context: { nonce } });
    const headers = new Headers(response.headers);
    headers.set('Cache-Control', 'no-store'); headers.set('X-Content-Type-Options', 'nosniff'); headers.set('Referrer-Policy', 'no-referrer'); headers.set('X-Frame-Options', 'DENY');
    if (env.STAGE !== 'local') {
      headers.set('Content-Security-Policy', `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`);
      headers.set('Strict-Transport-Security', 'max-age=31536000');
    }
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  },
};
