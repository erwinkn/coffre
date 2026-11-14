import { z } from 'zod';

import type { Called } from '@coffre/core/vault';

import { linkedIdentities, liveSessions, waitingDeviceLogin, type DeviceLoginRow, type IdentityRow, type SessionRow } from '../../db/queries/signin.ts';
import { normalizeUserCode } from '../../signin.ts';
import { changed } from '../change.ts';
import type { ApiContext } from '../context.ts';
import { forbidden, refusal } from '../errors.ts';
import { route } from '../route.ts';
import { signsIn } from './tokens.ts';

/** A person, signed in as themselves on a session of theirs: whom `device.decide` takes, and so whom its page shows a device login. */
const onOwnSession = (who: Called) => who.principal.startsWith('user:') && who.holds.credentialScope == null;

/** Only a person, on a session of theirs, lists their sessions and accounts: a personal token reached neither in 0.14.7, nor a workload. */
async function ownSession(ctx: ApiContext): Promise<Called> {
  signsIn(ctx);
  const who = await ctx.caller();
  if (!onOwnSession(who)) throw forbidden('only a person, signed in as themselves, lists their sessions and accounts');
  return who;
}

/**
 * A person's own sign-in through the API (docs/design/0.16.md, "Signing in
 * from the server"): their sessions and accounts listed, unlinking one of
 * their accounts, and the page `coffre login` opens, which shows a device
 * login and decides it. The browser's round trip and the device login's
 * own calls are paths outside the API, in `signin.ts`.
 */
export const signinRoutes = {
  /**
   * The caller's live sessions, browsers' and CLIs', the one last used first; `current` is this request's.
   * The 200 last used (`SESSIONS_LISTED`), `more` when there are others. One `caller` and one statement.
   */
  ...route('GET /sessions', {
    run: async (ctx): Promise<{ sessions: SessionRow[]; more: boolean }> => {
      const who = await ownSession(ctx);
      const { sessions, more } = await liveSessions(ctx.db, who.principal, new Date());
      return { sessions: sessions.map((session) => ({ ...session, current: session.id === who.credential.id })), more };
    },
  }),
  /** The caller's linked accounts, the oldest first: the 50 oldest (`IDENTITIES_LISTED`), `more` when there are others. One `caller` and one statement. */
  ...route('GET /identities', {
    run: async (ctx): Promise<{ identities: IdentityRow[]; more: boolean }> => {
      const who = await ownSession(ctx);
      return await linkedIdentities(ctx.db, who.principal);
    },
  }),
  /** One of the caller's accounts revoked, and the sessions it opened with it: one `change`, no statement. */
  ...route('DELETE /identities/:id', {
    run: async (ctx, { params }): Promise<{ unlinked: true }> => {
      await changed(ctx, { op: 'account.unlink', identity: params.id }, 'that account');
      return { unlinked: true };
    },
  }),
  /**
   * The device login a code names, while it waits for a decision, as the
   * person asked to decide it sees it; null for a code that is unknown,
   * decided or expired, as 0.14 answered. One `caller` and one statement.
   * Shown only to whom `device.decide` takes: a person on a session of
   * theirs, never a token.
   */
  ...route('GET /device-logins/:code', {
    run: async (ctx, { params }): Promise<{ request: DeviceLoginRow | null; sessionDays: number }> => {
      if (!onOwnSession(await ctx.caller())) throw refusal('no_access');
      const code = normalizeUserCode(params.code);
      const request = code === null ? null : await waitingDeviceLogin(ctx.db, code, new Date());
      return { request, sessionDays: ctx.auth.mode === 'signin' ? ctx.auth.signin.cliSessionDays : 0 };
    },
  }),
  /** A device login approved or denied, by its code as the person typed it: one `change`, no statement. */
  ...route('POST /device-logins/:code', {
    input: z.object({ approve: z.boolean() }).strict(),
    run: async (ctx, { params, input }): Promise<{ decided: true }> => {
      const code = normalizeUserCode(params.code);
      if (code === null) throw refusal('unknown_code');
      await changed(ctx, { op: 'device.decide', userCode: code, approve: input.approve }, code);
      return { decided: true };
    },
  }),
};
