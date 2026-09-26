import { z } from 'zod';

import { getRuntime } from '../server/runtime.ts';
import { registeredServerFn } from '../server/server-fn.ts';
import { publicProviders } from '../server/signin.ts';
import type { IdentityRow, ServiceTokenRow, SessionRow } from '../server/services/signin.ts';
import { principalId } from '../shared/schemas.ts';
import { currentIdentity, currentRequestContext } from './session.ts';
import { uiFailure, uiMutation, uiResult } from './result.ts';

const credentialId = z.string().uuid();
const userCode = z.string().trim().min(1).max(16);

/**
 * The account page's sign-in half: which accounts you sign in with, where
 * you are signed in, and which providers you could link. Empty outside
 * signin mode, where someone else owns sessions.
 */
export const getAccountSignin = registeredServerFn({ method: 'GET' }).handler(async () => {
  const runtime = getRuntime();
  const signin = runtime.signin;
  if (signin === null) {
    return {
      ok: true as const,
      mode: runtime.auth.mode,
      providers: [] as { id: string; label: string; brand: string }[],
      identities: [] as IdentityRow[],
      sessions: [] as SessionRow[],
    };
  }
  const ctx = currentRequestContext();
  const identity = currentIdentity();
  const current = identity !== undefined && 'credentialId' in identity ? identity.credentialId : null;
  return uiResult(async () => ({
    mode: runtime.auth.mode,
    providers: publicProviders(signin.config),
    identities: await signin.listIdentities(ctx),
    sessions: await signin.listSessions(ctx, current),
  }));
});

export const revokeSession = registeredServerFn({ method: 'POST' })
  .validator(z.object({ id: credentialId }))
  .handler(async ({ data }) => {
    const signin = getRuntime().signin;
    if (signin === null) return { ok: false as const, error: 'This instance has no sessions of its own.' };
    const ctx = currentRequestContext();
    return uiMutation(() => signin.revokeCredential(ctx, data.id));
  });

export const unlinkIdentity = registeredServerFn({ method: 'POST' })
  .validator(z.object({ id: credentialId }))
  .handler(async ({ data }) => {
    const signin = getRuntime().signin;
    if (signin === null) return { ok: false as const, error: 'This instance has no sign-in accounts.' };
    const ctx = currentRequestContext();
    return uiMutation(() => signin.unlinkIdentity(ctx, data.id));
  });

// --- device login ------------------------------------------------------------

/** What `coffre login` is asking for, so the person can check before approving. */
export const getDeviceRequest = registeredServerFn({ method: 'GET' })
  .validator(z.object({ code: userCode }))
  .handler(async ({ data }) => {
    const signin = getRuntime().signin;
    if (signin === null) return { ok: false as const, error: 'This instance has no CLI sign-in.' };
    return uiResult(async () => ({
      request: await signin.describeDevice(data.code),
      sessionDays: signin.config.cliSessionDays,
    }));
  });

export const decideDeviceRequest = registeredServerFn({ method: 'POST' })
  .validator(z.object({ code: userCode, approve: z.boolean() }))
  .handler(async ({ data }) => {
    const signin = getRuntime().signin;
    if (signin === null) return { ok: false as const, error: 'This instance has no CLI sign-in.' };
    const ctx = currentRequestContext();
    try {
      await signin.decideDevice(ctx, data.code, data.approve);
      return { ok: true as const };
    } catch (error) {
      if ((error as { statusCode?: number }).statusCode === 404) {
        return { ok: false as const, error: 'That code is unknown, already used, or expired. Run coffre login again.' };
      }
      return uiFailure(error);
    }
  });

// --- service tokens ----------------------------------------------------------

export const listServiceTokens = registeredServerFn({ method: 'GET' })
  .validator(z.object({ serviceId: principalId }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const signin = runtime.signin;
    if (signin === null) return { ok: true as const, mode: runtime.auth.mode, tokens: [] as ServiceTokenRow[] };
    const ctx = currentRequestContext();
    return uiResult(async () => ({
      mode: runtime.auth.mode,
      tokens: await signin.listServiceTokens(ctx, data.serviceId),
    }));
  });

export const issueServiceToken = registeredServerFn({ method: 'POST' })
  .validator(
    z.object({
      serviceId: principalId,
      label: z.string().trim().max(120).nullable(),
      expiresInDays: z.number().int().min(1).max(366),
    }),
  )
  .handler(async ({ data }) => {
    const signin = getRuntime().signin;
    if (signin === null) return { ok: false as const, error: 'This instance issues no tokens of its own.' };
    const ctx = currentRequestContext();
    return uiResult(async () => ({
      credential: await signin.issueServiceToken(ctx, data.serviceId, {
        label: data.label === '' ? null : data.label,
        expiresInDays: data.expiresInDays,
      }),
    }));
  });

export const revokeServiceToken = registeredServerFn({ method: 'POST' })
  .validator(z.object({ id: credentialId }))
  .handler(async ({ data }) => {
    const signin = getRuntime().signin;
    if (signin === null) return { ok: false as const, error: 'This instance issues no tokens of its own.' };
    const ctx = currentRequestContext();
    return uiMutation(() => signin.revokeCredential(ctx, data.id));
  });
