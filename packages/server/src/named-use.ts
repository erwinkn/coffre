import { hashToken, tokenKind, type TokenKind } from '@coffre/core/identity';
import { newUseRequestId, USE_DEADLINE_MS, type Purpose } from '@coffre/core/vault';

import { authenticateRequest, refusedByKind, type AuthenticatedIdentity } from './auth.ts';
import { uses015 } from './api/changes.ts';
import { refusedUse, type Decided } from './api/keys.ts';
import { namedAhead, type ReadAhead } from './db/read-ahead.ts';
import type { CoffreRuntime } from './runtime.ts';

/**
 * 0.15's use by name, the vault's one call (T145, PR B; formal/Probing.tla): a request's one key, or none (`key` null:
 * the caller's standing at the place alone), at the place its path names, or the one a handle was made for (`place`
 * null). The vault answers the rows the request checks, its credential's MAC and token's hash among them, and the
 * caller as it decided them from the sealed rows it read: nothing is read, asked or kept here first.
 *
 *   Ada's `coffre secrets get market/dev/API_KEY`   one vault call   its value, her standing, the rows: no statement here
 *   the same, her grant revoked                    one vault call   403, as today, whether API_KEY was ever made or not
 *
 * Null where the vault serves none so (a token of another kind, a fork, a personal config, a handle of several
 * environments, SQLite's or 0.14's vault) or the token is none it knows: the request goes as ever, and is answered as
 * ever, or the vault's seals bear out no standing of the caller's. Busy, it throws as a use refused.
 */
export async function useByName(
  runtime: CoffreRuntime,
  request: Request,
  sourceIp: string | null,
  token: string,
  asked: {
    kinds: readonly TokenKind[]; place: { project: string; environment: string } | null; key: string | null; purpose: Purpose;
    /** With `place` null, the environments the request does not mean (`NamedUseInput.unless`). */
    unless?: readonly { project: string; environment: string }[];
  },
): Promise<{ identity: AuthenticatedIdentity | Response; ahead: ReadAhead | null; decided: Decided; place: { project: string; environment: string } | null } | null> {
  const kind = tokenKind(token);
  if (kind === null || !asked.kinds.includes(kind) || runtime.vault.useNamed === undefined || !(await uses015(runtime.vault))) return null;
  // Refused on its kind alone (a service's bearer token on a strict instance): by the credential's own check, as ever,
  // with nothing asked of the vault, nor written in its log or its cap (review r3 of #412).
  if (refusedByKind(runtime, token, { handle: kind === 'handle' }) !== null) return null;
  const at = Date.now();
  const answered = await runtime.vault.useNamed({
    tokenHash: hashToken(token).toString('base64'), place: asked.place, key: asked.key, purpose: asked.purpose, requestId: newUseRequestId(), at, deadline: at + USE_DEADLINE_MS,
    ...(asked.unless === undefined ? {} : { unless: asked.unless }),
  });
  if (!answered.served) return null;
  const { outcome } = answered;
  // No credential it knows, or one ended: refused by the credential's own check, as ever, which says why.
  if (!outcome.ok && 'code' in outcome && outcome.code === 'credential') return null;
  // Busy: nothing decided, and nothing read first, whatever the request names (StandingSharesAdmission).
  if (!outcome.ok && 'busy' in outcome) throw refusedUse(outcome);
  // No standing the vault's seals bear out (a row put back or written around the log): the request asks the vault, as
  // ever, and is answered as it would have been (review r1).
  if (answered.standing === null) return null;
  const ahead = namedAhead(runtime.db, answered.app);
  // The credential checked on the rows the use answered, its MAC and token's hash among them, as a request reads them.
  const identity = await authenticateRequest(request, runtime, crypto.randomUUID(), token, sourceIp, {
    handle: kind === 'handle', standing: answered.standing, ...(ahead?.credential === undefined ? {} : { ahead: ahead.credential }),
  });
  return { identity, ahead, decided: { secretId: answered.secretId, outcome }, place: answered.place };
}
