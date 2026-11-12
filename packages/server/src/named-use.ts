import { hashToken, tokenKind, type TokenKind } from '@coffre/core/identity';
import { personalOf } from '@coffre/core/schemas';
import { newUseRequestId, USE_DEADLINE_MS, type CredentialAcceptance, type Purpose, type RouteUseInput, type RouteUseOutcome } from '@coffre/core/vault';

import { authenticateRequest, refusedByKind, type AuthenticatedIdentity } from './auth.ts';
import { namesMany, uses015 } from './api/changes.ts';
import { refusedUse, type Decided, type DecidedMany } from './api/keys.ts';
import { namedAhead, namedManyAhead, type ReadAhead } from './db/read-ahead.ts';
import type { CoffreRuntime } from './runtime.ts';

/**
 * What the deployment's config accepts of a credential, as the named call carries it (`NamedUseInput.accepts`): its
 * passkey policy among it (T216), which the vault's named call holds a person's credential to as the app's own check
 * does (`passkeyStands`), and a key write's or an add's first call answers the rows of.
 */
export function acceptance(runtime: Pick<CoffreRuntime, 'auth' | 'signin'>): CredentialAcceptance {
  return runtime.auth.mode === 'signin' && runtime.signin != null
    ? { signin: true, issuers: runtime.signin.acceptedIssuers, passkeys: runtime.auth.signin.passkeys.policy }
    : { signin: false, issuers: [], passkeys: 'off' };
}

/**
 * 0.15's use by name, the vault's one call (T145, PR B; formal/Probing.tla): a request's one key, or none (`key` null:
 * the caller's standing at the place alone), at the place its path names, or the one a handle was made for (`place`
 * null). The place may be a fork, whose key the vault finds where the fork inherits it from, or `dev@me`, its caller's
 * personal config of dev, or dev while they have none (T165, B2; `forks`). The vault answers the rows the request
 * checks, its credential's MAC and token's hash among them, and the caller as it decided them from the sealed rows it
 * read: nothing is read, asked or kept here first.
 *
 *   Ada's `coffre secrets get market/dev/API_KEY`   one vault call   its value, her standing, the rows: no statement here
 *   the same, her grant revoked                    one vault call   404 `not_available`, whatever API_KEY is or was
 *   the same, API_KEY never made, or ended         one vault call   the same 404: one answer for every refusal (D153)
 *   the same at market/dev-ada, inherited from dev one vault call   decided at the fork and at dev, where it is held
 *   the same at market/dev@me                      one vault call   at her personal config of dev, or dev without one
 *
 * Null where the vault serves none so (a token of another kind, a personal config by its own slug, a handle of several
 * environments, a vault older than this app, which serves no fork, 0.14's vault) or the token is none it
 * knows: the request goes as ever, and is answered as ever, or the vault's seals bear out no standing of the caller's.
 * Busy, it throws as a use refused.
 *
 * The app checks the credential after the vault's call, on the rows it answered (`authenticateRequest`), so that the
 * named path costs one call. So the vault's "authenticated" must be the app's: whatever the app would refuse of a
 * credential, the vault refuses first, before anything that hangs on the key (a place's or a key's row read, its
 * principal's lock waited for), as a token no credential has (`unknown`); the leak would be the wait, not the answer.
 * Every check the app makes of a credential is one of (formal/Probing.tla, AcceptedFirst; docs/formal.md):
 * - what its config accepts, which the call carries (`accepts`) and the vault's statement holds the credential to before
 *   it reads anything else: the deployment signs in through coffre's own sign-in (under Cloudflare Access no coffre
 *   token is one; review r7 of D153), a browser session's identity names a provider it configures (review r6), and a
 *   person's session or token has a live passkey behind it, as the policy says (T216; docs/design/passkeys.md, section
 *   6.4): the vault answers what it read of their passkeys with the rows, whose MACs the app's check holds them to, so
 *   that a person's reveal is one call too;
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
    requestId: newUseRequestId(), at, deadline: at + USE_DEADLINE_MS, forks: true,
    ...(asked.unless === undefined ? {} : { unless: asked.unless }),
  });
  if (!answered.served) return null;
  // The route the vault picked on the credential and its account alone (`routeOf`; D153, review r2), never on the key
  // or its map. Busy: nothing decided, and nothing read first, whatever the request names (StandingSharesAdmission).
  if (answered.route === 'busy') throw refusedUse(answered.outcome);
  // No credential its seals bear out (unknown, ended, its account's row put back or written around the log, or a token
  // of 0.10's yet to be sealed), or one the app's config does not accept, no live passkey behind a person's among it:
  // the credential's own check answers, as ever (401, 401 `passkey_required`), the token sealed first, before anything
  // reads the key: the same answer, at the same cost, whatever it asked for (conformance check 19).
  if (answered.route === 'credential') return null;
  const { outcome } = answered;
  const ahead = namedAhead(answered.app, { personal: asked.place !== null && personalOf(asked.place.environment) !== null });
  // The credential checked on the rows the use answered, its MAC and token's hash among them, as a request reads them,
  // its expiry at the use's `at`, as the vault judged it (one clock, review r8): of what this checks, only a forged
  // row's MAC is not decided above or by the vault (D154; the comment above).
  const identity = await authenticateRequest(request, runtime, crypto.randomUUID(), token, sourceIp, {
    handle: kind === 'handle', standing: answered.standing, at, ...(ahead?.credential === undefined ? {} : { ahead: ahead.credential }),
  });
  return { identity, ahead, decided: { secretId: answered.secretId, outcome, at: answered.at }, place: answered.place };
}

/**
 * A request's several keys by name, the vault's one call (T165, B2's PR 2; formal/ProbingMany.tla): its keys (`keys`),
 * or every key the place holds (null), at the place its path names, an environment, a fork or `dev@me`. The vault decides
 * the caller's standing there first, from rows no key decides, and reads nothing of any key without it; for one who
 * stands, it resolves each key's name, decides them all, then uses them, all or nothing. It answers the
 * rows the request checks, the credential's, the place's and each key's, and the caller as it decided them: nothing is
 * read, asked or kept here first, and the read decides on those rows (`reveal`).
 *
 *   Ada's `coffre export market/dev`, 9 keys     one vault call   the 9 values, her standing, every key's rows
 *   the same, her grant revoked                  one vault call   403 on the place: no key listed or read, whatever dev holds
 *   the same at market/dev-ada, 2 of dev's       one vault call   each decided at the fork, dev's at dev too
 *
 * `leavesSensitive`: the read leaves out a sensitive value, naming it (a person's read), which the vault then uses not.
 * Null where the vault serves none so, as `useByName` (a vault older than this app among them): the request goes as ever.
 */
export async function useManyByName(
  runtime: CoffreRuntime,
  request: Request,
  sourceIp: string | null,
  token: string,
  asked: { kinds: readonly TokenKind[]; place: { project: string; environment: string }; keys: readonly string[] | null; purpose: Purpose; leavesSensitive: boolean },
): Promise<{ identity: AuthenticatedIdentity | Response; ahead: ReadAhead | null; decided: DecidedMany; place: { project: string; environment: string } | null } | null> {
  const kind = tokenKind(token);
  if (kind === null || !asked.kinds.includes(kind) || runtime.vault.useNamedMany === undefined || !(await namesMany(runtime.vault))) return null;
  // Refused on its kind alone: by the credential's own check, as ever, nothing asked of the vault (`useByName`).
  if (refusedByKind(runtime, token, { handle: kind === 'handle' }) !== null) return null;
  const at = Date.now();
  const answered = await runtime.vault.useNamedMany({
    tokenHash: hashToken(token).toString('base64'), place: asked.place, keys: asked.keys, accepts: acceptance(runtime), purpose: asked.purpose,
    at, deadline: at + USE_DEADLINE_MS, ...(asked.leavesSensitive ? { leavesSensitive: true } : {}),
  });
  if (!answered.served) return null;
  if (answered.route === 'busy') throw refusedUse(answered.outcome);
  if (answered.route === 'credential') return null;
  const personal = personalOf(asked.place.environment) !== null;
  // Every key's rows, the caller standing there and its chain whole; the credential's and the place's only, otherwise.
  const ahead = namedManyAhead(answered.app, answered.stands ? answered.keys : null, { personal });
  const identity = await authenticateRequest(request, runtime, crypto.randomUUID(), token, sourceIp, {
    handle: kind === 'handle', standing: answered.standing, at, ...(ahead?.credential === undefined ? {} : { ahead: ahead.credential }),
  });
  return { identity, ahead, decided: { keys: answered.keys, stands: answered.stands, outcome: answered.outcome, at: answered.at }, place: answered.place };
}

/**
 * A UI route's use by a handle (0.16, T186 PR C; docs/design/proxy-ui.md, section 3): the vault's one call (two on a
 * map miss), which reads the URL both ways it may be read, finds the route at the place, and decides each of its keys
 * for the caller and for the route's editor. As `useManyByName`, nothing is read here first: the credential is checked
 * on the rows the vault answered, and the read decides on them (`reveal`). Null where the vault serves the place not by
 * name (a handle of several environments at the stable URL, a place that is none), which the proxy answers itself.
 */
export async function useRouteByName(
  runtime: CoffreRuntime,
  request: Request,
  sourceIp: string | null,
  token: string,
  asked: Pick<RouteUseInput, 'named' | 'stable' | 'digests'>,
): Promise<
  | { credential: true; identity: AuthenticatedIdentity | Response }
  | { credential: false; identity: AuthenticatedIdentity | Response; ahead: ReadAhead | null; decided: DecidedMany; answered: Extract<RouteUseOutcome, { route: 'name' }> }
  | null
> {
  if (tokenKind(token) !== 'handle') return null;
  if (refusedByKind(runtime, token, { handle: true }) !== null) return { credential: true, identity: await authenticateRequest(request, runtime, crypto.randomUUID(), token, sourceIp, { handle: true }) };
  const at = Date.now();
  const answered = await runtime.vault.useRoute({
    caller: { kind: 'handle', tokenHash: hashToken(token).toString('base64'), accepts: acceptance(runtime) }, ...asked, purpose: 'use', at, deadline: at + USE_DEADLINE_MS,
  });
  if (!answered.served) return null;
  if (answered.route === 'busy') throw refusedUse(answered.outcome);
  // No credential its seals bear out: the credential's own check answers, as ever (401).
  if (answered.route === 'credential') return { credential: true, identity: await authenticateRequest(request, runtime, crypto.randomUUID(), token, sourceIp, { handle: true }) };
  const ahead = namedManyAhead(answered.app, answered.stands ? answered.keys : null, { personal: false });
  const identity = await authenticateRequest(request, runtime, crypto.randomUUID(), token, sourceIp, {
    handle: true, standing: answered.standing, at, ...(ahead?.credential === undefined ? {} : { ahead: ahead.credential }),
  });
  return { credential: false, identity, ahead, decided: { keys: answered.keys, stands: answered.stands, outcome: answered.outcome, at: answered.at }, answered };
}
