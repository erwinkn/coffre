import type { IncomingMessage, ServerResponse } from 'node:http';

export type Handler = (req: IncomingMessage, res: ServerResponse, url: URL) => Promise<void>;

export interface Route {
  method: 'GET' | 'POST';
  path: string | RegExp;
  handler: Handler;
}

export function sendJson(
  res: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): void {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

export function sendHtml(res: ServerResponse, status: number, html: string): void {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    // Everything is inline; nothing else may load. No form-action: browsers
    // apply it to the redirect that follows a submission, which is the point.
    'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'",
    'x-frame-options': 'DENY',
    'cache-control': 'no-store',
  });
  res.end(html);
}

export function redirect(res: ServerResponse, location: string): void {
  res.writeHead(302, { location, 'cache-control': 'no-store' });
  res.end();
}

export function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

/**
 * Read a form or JSON body as parameters. Returns null for a body that does
 * not parse, so callers can answer with their own protocol's error shape.
 */
export async function readParams(req: IncomingMessage): Promise<URLSearchParams | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > 64 * 1024) return null;
    chunks.push(chunk as Buffer);
  }
  const body = Buffer.concat(chunks).toString('utf8');
  const type = (req.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();

  if (type === 'application/json') {
    try {
      const parsed: unknown = JSON.parse(body);
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(parsed)) {
        if (typeof value === 'string') params.set(key, value);
      }
      return params;
    } catch {
      return null;
    }
  }
  if (type === 'application/x-www-form-urlencoded') return new URLSearchParams(body);
  return null;
}

/** RFC 6749 §3.1: request parameters must not be included more than once. */
export function repeatedParam(params: URLSearchParams): string | undefined {
  const seen = new Set<string>();
  for (const key of params.keys()) {
    if (seen.has(key)) return key;
    seen.add(key);
  }
  return undefined;
}

/** The token from `Authorization: <scheme> <token>`, for any of the given schemes. */
export function authorizationToken(
  req: IncomingMessage,
  schemes: readonly string[],
): string | undefined {
  const match = /^(\S+) +(\S+)$/.exec(req.headers.authorization ?? '');
  if (!match || !schemes.includes(match[1]!.toLowerCase())) return undefined;
  return match[2];
}
