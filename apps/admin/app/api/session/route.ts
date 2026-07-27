import { NextResponse } from 'next/server';
import { DEV_TOKEN_COOKIE } from '../../../lib/api';

const DEV_IDP_URL = process.env.COFFRE_DEV_IDP_URL ?? '';
const AUD = process.env.COFFRE_ACCESS_AUD ?? 'coffre-local-dev-aud';

/**
 * Dev-only sign-in.
 *
 * In production this route does not exist in any meaningful sense: Cloudflare
 * Access authenticates the user before the request reaches this app and
 * forwards `Cf-Access-Jwt-Assertion`, which lib/api.ts prefers over any cookie.
 * This exists so the same UI can run locally against the dev IdP.
 */
export async function POST(request: Request): Promise<NextResponse> {
  if (DEV_IDP_URL === '') {
    return NextResponse.json({ error: 'dev sign-in is disabled' }, { status: 404 });
  }

  const form = await request.formData();
  const email = String(form.get('email') ?? 'erwin@equisafe.io');

  const url = new URL('/dev/mint', DEV_IDP_URL);
  url.searchParams.set('email', email);
  url.searchParams.set('aud', AUD);

  const minted = await fetch(url);
  if (!minted.ok) {
    return NextResponse.json({ error: 'dev IdP unavailable' }, { status: 502 });
  }
  const { token } = (await minted.json()) as { token: string };

  const response = NextResponse.redirect(new URL('/', request.url), 303);
  response.cookies.set(DEV_TOKEN_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 900,
  });
  return response;
}
