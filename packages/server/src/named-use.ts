import { hashToken, tokenKind, type TokenKind } from '@coffre/core/identity';
import { newUseRequestId, USE_DEADLINE_MS, type CredentialAcceptance, type Purpose } from '@coffre/core/vault';

import { authenticateRequest, refusedByKind, type AuthenticatedIdentity } from './auth.ts';
import { uses015 } from './api/changes.ts';
import { refusedUse, type Decided } from './api/keys.ts';
import { namedAhead, type ReadAhead } from './db/read-ahead.ts';
import type { CoffreRuntime } from './runtime.ts';

/** What the deployment's config accepts of a credential, as the named call carries it (`NamedUseInput.accepts`). */
export function acceptance(runtime: Pick<CoffreRuntime, 'auth' | 'signin'>): CredentialAcceptance {
  return runtime.auth.mode === 'signin' && runtime.signin != null ? { signin: true, issuers: runtime.signin.acceptedIssuers } : { signin: false, issuers: [] };
}

/**
 * 0.15's use by name, the vault's one call (T145, PR B; formal/Probing.tla): a request's one key, or none (`key` null:
 * the caller's standing at the place alone), at the place its path names, or the one a handle was made for (`place`
 * null). The vault answers the rows the request checks, its credential's MAC and token's hash among them, and the
 * caller as it decided them from the sealed rows it read: nothing is read, asked or kept here first.
 *
 *   Ada's `coffre secrets get market/dev/API_KEY`   one vault call   its value, her standing, the rows: no statement here
 *   the same, her grant revoked                    one vault call   404 `not_available`, whatever API_KEY is or was
 *   the same, API_KEY never made, or ended         one vault call   the same 404: one answer for every refusal (D153)
 *
 * Null where the vault serves none so (a token of another kind, a fork, a personal config, a handle of several
 * environments, SQLite's or 0.14's vault) or the token is none it knows: the request goes as ever, and is answered as
 * ever, or the vault's seals bear out no standing of the caller's. Busy, it throws as a use refused.
 *
 * The app checks the credential after the vault's call, on the rows it answered (`authenticateRequest`), so that the
 * named path costs one call. So the vault's "authenticated" must be the app's: whatever the app would refuse of a
 * credential, the vault refuses first, before anything that hangs on the key (a place's or a key's row read, its
 * principal's lock waited for), as a token no credential has (`unknown`); the leak would be the wait, not the answer.
 * Every check the app makes of a credential is one of (formal/Probing.tla, AcceptedFirst; docs/formal.md):
 * - what its config accepts, which the call carries (`accepts`) and the vault's statement holds the credential to before
 *   it reads anything else: the deployment signs in through coffre's own sign-in (under Cloudflare Access no coffre
 *   token is one; review r7 of D153), and a browser session's identity names a provider it configures (review r6);
 * - the token's kind, decided here before any call (`kinds`, never a workload's; `refusedByKind`: a strict instance's
 *   service token, an enrollment code);
 * - a fact the vault decides on itself, before any lock: the credential revoked, expired or of an earlier generation
 *   of its account (`credentialEnded`); its identity unlinked or the trust binding that issued it ended, each of which
 *   revokes it in the same change. Its expiry, the one of these that hangs on the clock, both judge at the use's `at`
 *   (review r8, `OneClock`): a credential live when its request began is honoured for that request, which the use's
 *   deadline (3 s) bounds; revocation and generation stay live checks (`credentialStill`);
 * - a row forged around the app (its MAC broken, its seal whole), which only a database writer makes: accepted, the
 *   request refused 401 whatever the key (D154, R64; docs/architecture.md, "Limits").
 * A check of any other kind goes in the first, or the vault learns it.
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
    tokenHash: hashToken(token).toString('base64'), place: asked.place, key: asked.key, accepts: acceptance(runtime), purpose: asked.purpose,
    requestId: newUseRequestId(), at, deadline: at + USE_DEADLINE_MS,
    ...(asked.unless === undefined ? {} : { unless: asked.unless }),
  });
  if (!answered.served) return null;
  // The route the vault picked on the credential and its account alone (`routeOf`; D153, review r2), never on the key
  // or its map. Busy: nothing decided, and nothing read first, whatever the request names (StandingSharesAdmission).
  if (answered.route === 'busy') throw refusedUse(answered.outcome);
  // No credential its seals bear out (unknown, ended, its account's row put back or written around the log, or a token
  // of 0.10's yet to be sealed): the credential's own check answers, as ever (401), the token sealed first.
  if (answered.route === 'credential') return null;
  const { outcome } = answered;
  const ahead = namedAhead(runtime.db, answered.app);
  // The credential checked on the rows the use answered, its MAC and token's hash among them, as a request reads them,
  // its expiry at the use's `at`, as the vault judged it (one clock, review r8): of what this checks, only a forged
  // row's MAC is not decided above or by the vault (D154; the comment above).
  const identity = await authenticateRequest(request, runtime, crypto.randomUUID(), token, sourceIp, {
    handle: kind === 'handle', standing: answered.standing, at, ...(ahead?.credential === undefined ? {} : { ahead: ahead.credential }),
  });
  return { identity, ahead, decided: { secretId: answered.secretId, outcome, at: answered.at }, place: answered.place };
}
