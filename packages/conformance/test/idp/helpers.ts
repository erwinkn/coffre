import { createHash, randomBytes } from 'node:crypto';

export const REDIRECT_URI = 'http://127.0.0.1:3000/auth/callback';

export function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

/** Follow nothing: the tests look at every redirect themselves. */
export async function get(url: string | URL, init: RequestInit = {}): Promise<Response> {
  return fetch(url, { redirect: 'manual', ...init });
}

export function location(response: Response): URL {
  const header = response.headers.get('location');
  if (!header) throw new Error(`expected a redirect, got ${response.status}`);
  return new URL(header);
}

export function form(params: Record<string, string>): RequestInit {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params),
    redirect: 'manual',
  };
}

export function basic(clientId: string, clientSecret: string): string {
  return `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
}
