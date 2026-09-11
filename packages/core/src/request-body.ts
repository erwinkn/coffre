// Buffer bounded POST bodies before any framework parser runs, including server functions.
export async function bounded(request: Request, limit: number): Promise<Request> {
  if (!request.body) return request;
  if (Number(request.headers.get('Content-Length') ?? 0) > limit) throw new Error('size');
  const reader = request.body.getReader(), chunks: Uint8Array[] = []; let length = 0;
  try { for (;;) { const part = await reader.read(); if (part.done) break; length += part.value.length; if (length > limit) { await reader.cancel(); throw new Error('size'); } chunks.push(part.value); } } finally { reader.releaseLock(); }
  const body = new Uint8Array(length); let offset = 0; for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
  return new Request(request.url, { method: request.method, headers: request.headers, body, redirect: 'manual' });
}
