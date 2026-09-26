import { getRequestHeader, setCookie } from '@tanstack/react-start/server';
import { z } from 'zod';

import { DEV_TOKEN_COOKIE } from '../server/auth.ts';
import { getRuntime } from '../server/runtime.ts';
import { sessionServerFn } from '../server/server-fn.ts';
import { publicProviders } from '../server/signin.ts';
import { emailAddress } from '../shared/schemas.ts';

const DEV_SESSION_SECONDS = 8 * 60 * 60;

export const getLoginAuthState = sessionServerFn({ method: 'GET' }).handler(async () => {
  const runtime = getRuntime();
  const auth = runtime.auth;
  return {
    mode: auth.mode,
    hasForwardedAccessJwt:
      auth.mode === 'cloudflare' && Boolean(getRequestHeader('cf-access-jwt-assertion')),
    signin:
      runtime.signin === null
        ? null
        : {
            title: runtime.signin.config.page.title,
            note: runtime.signin.config.page.note,
            providers: publicProviders(runtime.signin.config),
          },
  };
});

export const devSignIn = sessionServerFn({ method: 'POST' })
  .validator(z.object({ email: emailAddress }))
  .handler(async ({ data }) => {
    const auth = getRuntime().auth;
    if (auth.mode !== 'dev') {
      return { ok: false as const, error: 'Dev sign-in is disabled.' };
    }

    const url = new URL('/dev/mint', auth.devIdpUrl);
    url.searchParams.set('email', data.email);
    url.searchParams.set('aud', auth.access.audience);
    url.searchParams.set('expires_in', String(DEV_SESSION_SECONDS));

    let minted: Response;
    try {
      minted = await fetch(url);
    } catch {
      return { ok: false as const, error: 'The dev IdP is unreachable.' };
    }
    if (!minted.ok) {
      return { ok: false as const, error: 'The dev IdP refused to mint a token.' };
    }

    const { token } = (await minted.json()) as { token: string };
    setCookie(DEV_TOKEN_COOKIE, token, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: DEV_SESSION_SECONDS,
    });
    return { ok: true as const };
  });
