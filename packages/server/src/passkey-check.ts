import { hashToken, type PasskeyPolicy, type TokenKind } from '@coffre/core/identity';
import type { Queryable } from '@coffre/db';

import type { Caller } from './api/caller.ts';
import { ApiError } from './api/errors.ts';
import { formatMember } from './api/paths.ts';
import { AuthRowTampered, verifyAuthRow } from './auth-rows.ts';
import { findCredential, passkeyByToken, type PasskeyRead } from './db/queries.ts';
import { errorResponse } from './http.ts';
import type { CoffreRuntime } from './runtime.ts';

/**
 * The check every request of a person's makes of the credential it came in on (docs/design/passkeys.md, section 6.2),
 * and every issue of theirs makes, under the log's head, of the credential it would issue (section 6.1):
 *
 *   policy     it names a passkey            it names none
 *   off        taken                         taken
 *   optional   taken if that passkey is live  taken if the person holds no live passkey
 *   required   taken if that passkey is live  refused
 *
 * Live: its row not removed, and still its holder's, at the generation the credential is of. Its MAC is checked here, on
 * the one branch whose answer reads the row, so that what the check exempts (`off`, a credential of a kind it does not
 * hold) never fails on it; a row that fails throws `AuthRowTampered`, which each caller answers as it answers its own
 * row's (review r1 of #497). The revocations of section 6.1 end what a change to the person's passkeys leaves no passkey
 * behind; this is there for what no change marks: a session made while the policy was `off`, or by the previous
 * release during a rollout, for a person who holds a passkey; one made before the deployment turned `required` on
 * (formal/Factor.tla, `ServedBacked`).
 */
export function passkeyStands(
  chainKey: Buffer,
  policy: PasskeyPolicy,
  holder: { principal: string; generation: number; passkeyId: string | null },
  read: PasskeyRead,
): boolean {
  if (policy === 'off') return true;
  if (holder.passkeyId === null) return policy === 'optional' && !read.held;
  const { passkey } = read;
  if (passkey !== null) verifyAuthRow(chainKey, 'passkeys', passkey);
  return passkey !== null && passkey.id === holder.passkeyId && passkey.removedAt === null
    && passkey.principal === holder.principal && passkey.generation === holder.generation;
}

/**
 * The credentials the check holds: a person's browser and CLI sessions, and their personal tokens. An MCP connection
 * holds it in its own read (`McpService.authenticate`). A handle never: it reaches `/use` alone, which stays one
 * statement (R44, R58), and the revocations carry it (section 6.3). A service's credentials hold no passkey.
 */
export function passkeyChecked(kind: string): boolean {
  return kind === 'browser' || kind === 'cli' || kind === 'personal';
}

/** A credential the check refused (`passkeyStands`), as `verify` throws it and `authenticateRequest` answers it. */
export class PasskeyRequired extends Error {
  readonly principal: string;
  readonly credentialId: string;
  constructor(principal: string, credentialId: string) {
    super('no live passkey stands behind this credential');
    this.name = 'PasskeyRequired';
    this.principal = principal;
    this.credentialId = credentialId;
  }
}

/**
 * The answer to a credential the check refused: 401 `passkey_required`, and a line in the process log, no entry
 * (section 11): a browser page goes to the step-up, the CLI says to sign in again, a personal token or an MCP client is
 * made again by its person.
 */
export function passkeyRequired(refused: { principal: string; credentialId: string }, requestId: string): Response {
  console.warn('a credential no live passkey stands behind was refused', { principal: refused.principal, credentialId: refused.credentialId, requestId });
  return errorResponse(new ApiError('passkey_required', 'a passkey must confirm this sign-in: sign in again, and touch your passkey'));
}

/**
 * Whether the credential a request came in on still stands as its source, for an issue under the log's head (passkeys.md,
 * section 6.1): live, its person's at the generation the request was checked at, and still backed (`passkeyStands`). A
 * change to the person's passkeys revokes under the same head, so what this reads holds until the issue commits
 * (formal/Factor.tla, `AppIssueChecks`). A row that fails its MAC stands for nothing.
 */
export async function sourceStands(
  tx: Queryable,
  chainKey: Buffer,
  policy: PasskeyPolicy,
  ctx: { caller: Pick<Caller, 'principal' | 'generation'>; credentialId: string | null },
): Promise<boolean> {
  if (ctx.credentialId === null) return false;
  try {
    const row = await findCredential(tx, chainKey, { id: ctx.credentialId });
    return row !== null && row.revokedAt === null && row.expiresAt > new Date() && row.identityRevokedAt === null
      && row.principal === formatMember(ctx.caller.principal) && row.generation === ctx.caller.generation
      && row.passkeyRead !== undefined && passkeyStands(chainKey, policy, row, row.passkeyRead);
  } catch (error) {
    if (error instanceof AuthRowTampered) return false;
    throw error;
  }
}

/**
 * The passkey check of a request whose credential the vault reads, not the app (docs/design/passkeys.md, section 6.4):
 * a use by name, a key write, a member's add. The vault answers nothing of passkeys, so the app reads what stands behind
 * the credential in one statement of its own, by its token's hash, and nothing of what the request names
 * (`passkeyByToken`). A use by name asks it before the vault's call, which releases values; a write or an add, beside
 * the vault's first call, which only reads and prepares, so it costs no wait (`writeAhead`, `admitAhead`). What it read
 * goes on to the credential's check (`authenticateRequest`'s `passkey`), which reads nothing more, and refuses there,
 * 401 `passkey_required`, before anything is written. Undefined where nothing is checked: a handle, a service's token,
 * policy `off`, or no such credential (the vault's call refuses that). A passkey removed between this read and the
 * vault's revoked the credential (section 6.1), which the vault refuses itself.
 *
 * `'ordinary'`: the request goes the ordinary way, asking the vault nothing ahead, whose credential check reads and
 * decides again and answers as it answers any request: refused, 401 `passkey_required`; a passkey row that fails its
 * MAC, 401 (`AuthRowTampered`); a read that failed, 503 (`CredentialUncheckable`). Never thrown from here, where no
 * boundary translates it (review r1 of #497).
 */
export async function passkeyAhead(runtime: CoffreRuntime, token: string, kind: TokenKind): Promise<PasskeyRead | 'ordinary' | undefined> {
  if (!passkeyChecked(kind) || runtime.auth.mode !== 'signin' || runtime.auth.signin.passkeys.policy === 'off') return undefined;
  try {
    const read = await passkeyByToken(runtime.db, hashToken(token));
    if (read === null) return undefined;
    return passkeyStands(runtime.chainKey, runtime.auth.signin.passkeys.policy, read.holder, read) ? read : 'ordinary';
  } catch {
    return 'ordinary';
  }
}
