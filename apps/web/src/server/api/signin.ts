import { randomBytes, randomUUID } from 'node:crypto';

import { and, count, desc, eq, gt, inArray, isNull, lte, ne, or } from 'drizzle-orm';

import type { Principal } from '../../../../../packages/core/src/identity/types.ts';
import type { SigninConfig } from '../../../../../packages/core/src/identity/signin/config.ts';
import type { PendingSignin, SigninProfile } from '../../../../../packages/core/src/identity/signin/types.ts';
import { deriveKey, seal, unseal } from '../../../../../packages/core/src/identity/signin/sealed.ts';
import {
  generateToken,
  hashToken,
  isCoffreToken,
  tokenHint,
  type CredentialKind,
} from '../../../../../packages/core/src/identity/tokens.ts';
import type { AuditEntry } from '../../../../../packages/db/src/audit.ts';
import type { Database, Transaction } from '../../../../../packages/db/src/database.ts';
import { forUpdate, insertIfAbsent, isUniqueViolation } from '../../../../../packages/db/src/dialect.ts';
import { credentials, deviceAuthorizations, identities, principals } from '../../../../../packages/db/src/schema.ts';
import { isConfiguredRootAdmin, type PrincipalRef } from './caller.ts';
import { allowed, audited, denied, Refusal, type ApiContext } from './context.ts';
import { ApiError, badRequest, forbidden, notFound } from './errors.ts';

export type SigninServiceDeps = {
  db: Database;
  chainKey: Buffer;
  rootAdmins: readonly string[];
  signin: SigninConfig;
};

/** Who is asking, for the calls a signed-in person makes about their own sign-in. */
export type Asker = Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'>;

/** Why a provider-verified person was still not let in. */
export type SigninRefusal =
  /** No invitation matches any of the account's verified emails. */
  | 'not_registered'
  /** The matching person was removed from this instance. */
  | 'deactivated'
  /**
   * The email matches someone who already signs in with another account. A
   * second account is linked from the account page, while signed in, never
   * by email alone.
   */
  | 'account_mismatch'
  /** Linking: the account already belongs to someone else. */
  | 'already_linked';

class SigninRefused extends Error {
  readonly reason: SigninRefusal;
  constructor(reason: SigninRefusal) {
    super(reason);
    this.reason = reason;
  }
}

/** What rides in the sealed cookie between leaving for the provider and coming back. */
export type PendingState = PendingSignin & {
  /** Where to land afterwards: a path on this origin. */
  next: string;
  /** Linking: the principal who asked to add this account. */
  link: string | null;
};

const PENDING_TTL_SECONDS = 10 * 60;

export type IssuedCredential = { id: string; token: string; expiresAt: string };

export type SigninResult =
  | { ok: true; principal: PrincipalRef; credential: IssuedCredential }
  | { ok: false; reason: SigninRefusal };

/** A caller authenticated by a coffre-issued credential. */
export type CredentialPrincipal = Principal & { credentialId: string };

export type ClientMeta = {
  requestId: string;
  sourceIp: string | null;
  /** Shown in the session list, e.g. "Firefox on macOS". */
  label: string | null;
};

export type SessionRow = {
  id: string;
  kind: 'browser' | 'cli';
  label: string | null;
  hint: string;
  provider: string | null;
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  current: boolean;
};

export type IdentityRow = {
  id: string;
  provider: string;
  email: string | null;
  createdAt: string;
  lastSignInAt: string | null;
};

export type ServiceTokenRow = {
  id: string;
  label: string | null;
  hint: string;
  createdAt: string;
  createdBy: string;
  expiresAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
};

export type DeviceStart = {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string;
  expiresIn: number;
  interval: number;
};

export type DeviceRequest = {
  userCode: string;
  clientLabel: string | null;
  clientIp: string | null;
  createdAt: string;
  expiresAt: string;
};

export type DevicePoll =
  | { status: 'pending' }
  | { status: 'denied' }
  | { status: 'expired' }
  | { status: 'approved'; principal: PrincipalRef; credential: IssuedCredential };

const DEVICE_TTL_SECONDS = 10 * 60;
const DEVICE_POLL_SECONDS = 5;
const DEVICE_PENDING_PER_IP = 5;
const DEVICE_PENDING_TOTAL = 200;
/** No vowels, so a code never spells a word; no 0/O or 1/I lookalikes. */
const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';
const TOUCH_INTERVAL_MS = 5 * 60 * 1000;
export const MAX_SERVICE_TOKEN_DAYS = 366;

function userCode(): string {
  const chars: string[] = [];
  while (chars.length < 8) {
    for (const byte of randomBytes(16)) {
      // 240 is the largest multiple of 20 below 256: no modulo bias.
      if (byte < 240 && chars.length < 8) chars.push(USER_CODE_ALPHABET[byte % 20]);
    }
  }
  return `${chars.slice(0, 4).join('')}-${chars.slice(4).join('')}`;
}

/** Accept what a person types: any case, with or without the dash. */
export function normalizeUserCode(input: string): string | null {
  const letters = input.toUpperCase().replace(/[^A-Z]/g, '');
  if (letters.length !== 8 || [...letters].some((c) => !USER_CODE_ALPHABET.includes(c))) {
    return null;
  }
  return `${letters.slice(0, 4)}-${letters.slice(4)}`;
}

const isLiveCredential = (now: Date) => and(isNull(credentials.revokedAt), gt(credentials.expiresAt, now));

/**
 * coffre's own sign-in: who may come in, and the credentials they hold.
 *
 * Providers only prove control of an account. What that account may do here
 * is decided in this file, in three steps:
 *
 * 1. An account already bound to a person (an `identities` row) signs in as
 *    that person, whatever its email says today.
 * 2. Otherwise a verified email that matches an invited person binds the
 *    account to them, but only if they have no account bound yet. Taking over
 *    an existing person by email would let whoever controls a stale address
 *    at some provider walk in.
 * 3. Otherwise the answer is no, and the refusal is audited.
 *
 * Every credential is a random bearer token stored only as its SHA-256.
 *
 * Two first sign-ins of one account race on the unique index over
 * `(provider, subject)`: the loser's transaction fails, and it retries once,
 * now finding the account bound.
 */
export class SigninService {
  readonly #deps: SigninServiceDeps;
  readonly #stateKey: Buffer;

  constructor(deps: SigninServiceDeps) {
    this.#deps = deps;
    // Derived rather than configured: one fewer secret to provision, and
    // HKDF keeps it independent of the audit chain key it comes from.
    this.#stateKey = deriveKey(deps.chainKey, 'signin-state/v1');
  }

  get config(): SigninConfig {
    return this.#deps.signin;
  }

  /** Seal a sign-in in progress for its round trip through the browser. */
  sealPending(state: PendingState): { value: string; maxAge: number } {
    return { value: seal(this.#stateKey, state, PENDING_TTL_SECONDS), maxAge: PENDING_TTL_SECONDS };
  }

  openPending(value: string | null): PendingState | null {
    return unseal<PendingState>(this.#stateKey, value);
  }

  #isRoot(principalId: string): boolean {
    return isConfiguredRootAdmin({ type: 'user', id: principalId }, this.#deps.rootAdmins);
  }

  // --- signing in ---------------------------------------------------------

  async completeSignin(profile: SigninProfile, meta: ClientMeta): Promise<SigninResult> {
    try {
      return await this.#completeSignin(profile, meta);
    } catch (error) {
      if (error instanceof SigninRefused) return { ok: false, reason: error.reason };
      // Someone else bound this account, or created this root admin, first.
      if (isUniqueViolation(error)) return this.#completeSignin(profile, meta).catch(refusalOrThrow);
      throw error;
    }
  }

  async #completeSignin(profile: SigninProfile, meta: ClientMeta): Promise<SigninResult> {
    const claimed = profile.emails[0] ?? `${profile.provider}:${profile.subject}`;
    const base = {
      actorType: 'user' as const,
      action: 'auth.signin',
      requestId: meta.requestId,
      sourceIp: meta.sourceIp,
    };
    const account = { provider: profile.provider, subject: profile.subject, emails: profile.emails };
    const refuse = (reason: SigninRefusal, actorId = claimed) =>
      new Refusal(new SigninRefused(reason), {
        ...base,
        actorId,
        decision: 'deny',
        metadata: { ...account, reason },
      });

    return audited(this.#deps, async (tx, log) => {
      const now = new Date();
      const [bound] = await tx
        .select({ id: identities.id, principalId: identities.principalId, active: principals.active })
        .from(identities)
        .innerJoin(
          principals,
          and(
            eq(principals.principalType, identities.principalType),
            eq(principals.principalId, identities.principalId),
          ),
        )
        .where(
          and(eq(identities.provider, profile.provider), eq(identities.subject, profile.subject), isNull(identities.revokedAt)),
        );

      let principalId: string;
      let identityId: string;
      if (bound !== undefined) {
        principalId = bound.principalId;
        identityId = bound.id;
        if (!bound.active && !this.#isRoot(principalId)) throw refuse('deactivated', principalId);
        await this.#ensureRootRow(tx, principalId);
        await tx
          .update(identities)
          .set({ lastSignInAt: now, ...(profile.emails[0] === undefined ? {} : { email: profile.emails[0] }) })
          .where(eq(identities.id, identityId));
      } else {
        const match = await this.#principalForEmails(tx, profile.emails);
        if (match === null) throw refuse('not_registered');
        principalId = match.id;
        if (!match.active && !this.#isRoot(principalId)) throw refuse('deactivated', principalId);

        await this.#ensureRootRow(tx, principalId);
        // Locked, so two accounts cannot both bind to one person at once.
        await forUpdate(
          tx
            .select({ id: principals.principalId })
            .from(principals)
            .where(and(eq(principals.principalType, 'user'), eq(principals.principalId, principalId))),
        );
        const [existing] = await tx
          .select({ id: identities.id })
          .from(identities)
          .where(
            and(
              eq(identities.principalType, 'user'),
              eq(identities.principalId, principalId),
              isNull(identities.revokedAt),
              // This very account, bound a moment ago by a racing sign-in, is
              // no mismatch: binding it again hits the unique index, and the
              // retry finds it bound.
              or(ne(identities.provider, profile.provider), ne(identities.subject, profile.subject)),
            ),
          )
          .limit(1);
        if (existing !== undefined) throw refuse('account_mismatch', principalId);

        identityId = await this.#bind(tx, principalId, profile, principalId);
        log.push({
          ...base,
          actorId: principalId,
          action: 'identity.bind',
          decision: 'allow',
          metadata: { ...account, identityId, matchedEmail: match.email },
        });
      }

      const principal: PrincipalRef = { type: 'user', id: principalId };
      const credential = await this.#issue(tx, 'browser', principal, {
        identityId,
        label: meta.label,
        createdBy: principalId,
        expiresAt: new Date(now.getTime() + this.#deps.signin.browserSessionHours * 3_600_000),
      });
      log.push({
        ...base,
        actorId: principalId,
        decision: 'allow',
        metadata: { ...account, identityId, credentialId: credential.id },
      });
      return { ok: true as const, principal, credential };
    });
  }

  /** Bind another provider account to the signed-in person. */
  async linkIdentity(
    ctx: Asker,
    profile: SigninProfile,
  ): Promise<{ ok: true } | { ok: false; reason: SigninRefusal }> {
    const account = { provider: profile.provider, subject: profile.subject, emails: profile.emails };
    if (ctx.caller.principal.type !== 'user') throw forbidden('only people link sign-in accounts');
    return audited(this.#deps, async (tx, log) => {
      const [bound] = await tx
        .select({ principalId: identities.principalId })
        .from(identities)
        .where(
          and(eq(identities.provider, profile.provider), eq(identities.subject, profile.subject), isNull(identities.revokedAt)),
        );
      if (bound !== undefined) {
        if (bound.principalId === ctx.caller.principal.id) return { ok: true as const };
        throw new Refusal(
          new SigninRefused('already_linked'),
          denied(ctx, 'identity.bind', 'already_linked', { metadata: account }),
        );
      }
      const identityId = await this.#bind(tx, ctx.caller.principal.id, profile, ctx.caller.principal.id);
      log.push(allowed(ctx, 'identity.bind', { metadata: { ...account, identityId } }));
      return { ok: true as const };
    }).catch(refusalOrThrow);
  }

  /**
   * Configured root admins need no invitation, but identities and
   * credentials need a principals row to point at, and verify() requires it
   * to be active.
   */
  async #ensureRootRow(tx: Transaction, principalId: string): Promise<void> {
    if (!this.#isRoot(principalId)) return;
    await insertIfAbsent(tx, principals, {
      principalType: 'user',
      principalId,
      instanceRole: 'user',
      createdBy: 'system:signin',
      active: true,
    });
    await tx
      .update(principals)
      .set({ active: true })
      .where(
        and(eq(principals.principalType, 'user'), eq(principals.principalId, principalId), eq(principals.active, false)),
      );
  }

  async #bind(tx: Transaction, principalId: string, profile: SigninProfile, createdBy: string): Promise<string> {
    const id = randomUUID();
    await tx.insert(identities).values({
      id,
      provider: profile.provider,
      subject: profile.subject,
      principalType: 'user',
      principalId,
      email: profile.emails[0] ?? null,
      createdBy,
      lastSignInAt: new Date(),
    });
    return id;
  }

  /**
   * The invited person, or root admin, that one of these verified emails
   * names. The provider's primary address is tried first. Principal ids are
   * stored lowercase, and so are the emails a verified profile carries.
   */
  async #principalForEmails(
    tx: Transaction,
    emails: readonly string[],
  ): Promise<{ id: string; active: boolean; email: string } | null> {
    if (emails.length === 0) return null;
    const rows = await tx
      .select({ id: principals.principalId, active: principals.active })
      .from(principals)
      .where(and(eq(principals.principalType, 'user'), inArray(principals.principalId, [...emails])));
    for (const email of emails) {
      if (this.#isRoot(email)) return { id: email, active: true, email };
      const row = rows.find((candidate) => candidate.id === email);
      if (row !== undefined) return { id: row.id, active: row.active, email };
    }
    return null;
  }

  async #issue(
    tx: Transaction,
    kind: CredentialKind,
    principal: PrincipalRef,
    options: { identityId: string | null; label: string | null; createdBy: string; expiresAt: Date },
  ): Promise<IssuedCredential> {
    // Removing someone locks this row to revoke everything they hold, so a
    // credential is either minted first and revoked with the rest, or refused.
    const [row] = await forUpdate(
      tx
        .select({ active: principals.active })
        .from(principals)
        .where(and(eq(principals.principalType, principal.type), eq(principals.principalId, principal.id))),
    );
    if (row?.active !== true) throw new SigninRefused('deactivated');

    const token = generateToken(kind);
    const id = randomUUID();
    await tx.insert(credentials).values({
      id,
      kind,
      tokenHash: hashToken(token),
      tokenHint: tokenHint(token),
      principalType: principal.type,
      principalId: principal.id,
      identityId: options.identityId,
      label: options.label?.slice(0, 120) ?? null,
      createdBy: options.createdBy,
      expiresAt: options.expiresAt,
    });
    return { id, token, expiresAt: options.expiresAt.toISOString() };
  }

  // --- verifying ------------------------------------------------------------

  /**
   * Resolve a bearer token to its caller, or throw.
   *
   * A token dies with its person: removing someone deactivates their
   * principal, and the join on `principals.active` stops every credential
   * they hold on the next request, before any revocation sweep.
   */
  async verify(token: string, request: { sourceIp: string | null } = { sourceIp: null }): Promise<CredentialPrincipal> {
    if (!isCoffreToken(token)) throw new Error('not a coffre credential');
    const { db } = this.#deps;
    const now = new Date();

    const [row] = await db
      .select({
        id: credentials.id,
        principalType: credentials.principalType,
        principalId: credentials.principalId,
        lastUsedAt: credentials.lastUsedAt,
        subject: identities.subject,
      })
      .from(credentials)
      .innerJoin(
        principals,
        and(
          eq(principals.principalType, credentials.principalType),
          eq(principals.principalId, credentials.principalId),
        ),
      )
      .leftJoin(identities, eq(identities.id, credentials.identityId))
      .where(
        and(
          eq(credentials.tokenHash, hashToken(token)),
          isLiveCredential(now),
          eq(principals.active, true),
          or(isNull(credentials.identityId), isNull(identities.revokedAt)),
        ),
      );
    if (row === undefined) throw new Error('unknown, expired or revoked credential');

    const lastUsed = row.lastUsedAt?.getTime() ?? 0;
    if (now.getTime() - lastUsed > TOUCH_INTERVAL_MS) {
      // Coarse on purpose: one write per credential per five minutes, not
      // one per request. Losing it must never cost the request.
      await db
        .update(credentials)
        .set({ lastUsedAt: now, lastUsedIp: request.sourceIp })
        .where(eq(credentials.id, row.id))
        .catch(() => {});
    }

    return row.principalType === 'service'
      ? { type: 'service', id: row.principalId, commonName: row.principalId, credentialId: row.id }
      : {
          type: 'user',
          id: row.principalId,
          email: row.principalId,
          subject: row.subject ?? row.principalId,
          credentialId: row.id,
        };
  }

  // --- signing out and revoking ---------------------------------------------

  /** Revoke the credential this token is. Unknown tokens are a quiet no-op. */
  async signOut(token: string, meta: Omit<ClientMeta, 'label'>): Promise<void> {
    if (!isCoffreToken(token)) return;
    await audited(this.#deps, async (tx, log) => {
      const [row] = await forUpdate(
        tx
          .select({
            id: credentials.id,
            kind: credentials.kind,
            principalType: credentials.principalType,
            principalId: credentials.principalId,
          })
          .from(credentials)
          .where(and(eq(credentials.tokenHash, hashToken(token)), isNull(credentials.revokedAt))),
      );
      if (row === undefined) return;
      await tx
        .update(credentials)
        .set({ revokedAt: new Date(), revokedBy: row.principalId })
        .where(eq(credentials.id, row.id));
      log.push({
        actorType: row.principalType as PrincipalRef['type'],
        actorId: row.principalId,
        action: 'auth.signout',
        decision: 'allow',
        requestId: meta.requestId,
        sourceIp: meta.sourceIp,
        metadata: { credentialId: row.id, kind: row.kind },
      });
    });
  }

  /** Revoke one credential: your own, or anyone's if you own the instance. */
  async revokeCredential(ctx: Asker, credentialId: string): Promise<{ revoked: true }> {
    return audited(this.#deps, async (tx, log) => {
      const [row] = await forUpdate(
        tx
          .select({ kind: credentials.kind, principalType: credentials.principalType, principalId: credentials.principalId })
          .from(credentials)
          .where(and(eq(credentials.id, credentialId), isNull(credentials.revokedAt))),
      );
      if (row === undefined) {
        throw new Refusal(
          notFound('unknown credential'),
          denied(ctx, 'credential.revoke', 'unknown_credential', { metadata: { credentialId } }),
        );
      }
      const { principal } = ctx.caller;
      const own = row.principalType === principal.type && row.principalId === principal.id;
      if (!own && !ctx.caller.isOwner) {
        throw new Refusal(
          forbidden("only owners may revoke other people's credentials"),
          denied(ctx, 'credential.revoke', 'requires_instance_owner', { metadata: { credentialId } }),
        );
      }
      await tx
        .update(credentials)
        .set({ revokedAt: new Date(), revokedBy: principal.id })
        .where(eq(credentials.id, credentialId));
      log.push(
        allowed(ctx, 'credential.revoke', {
          metadata: { credentialId, kind: row.kind, principalType: row.principalType, principalId: row.principalId },
        }),
      );
      return { revoked: true as const };
    });
  }

  /** Unbind one of your sign-in accounts, ending the sessions it opened. */
  async unlinkIdentity(ctx: Asker, identityId: string): Promise<{ unlinked: true }> {
    const { principal } = ctx.caller;
    return audited(this.#deps, async (tx, log) => {
      const [row] = await forUpdate(
        tx
          .select({ provider: identities.provider, subject: identities.subject })
          .from(identities)
          .where(
            and(
              eq(identities.id, identityId),
              eq(identities.principalType, principal.type),
              eq(identities.principalId, principal.id),
              isNull(identities.revokedAt),
            ),
          ),
      );
      if (row === undefined) {
        throw new Refusal(
          notFound('unknown sign-in account'),
          denied(ctx, 'identity.unbind', 'unknown_identity', { metadata: { identityId } }),
        );
      }
      const now = new Date();
      const sessions = await tx
        .select({ id: credentials.id })
        .from(credentials)
        .where(and(eq(credentials.identityId, identityId), isNull(credentials.revokedAt)));
      await tx.update(identities).set({ revokedAt: now, revokedBy: principal.id }).where(eq(identities.id, identityId));
      if (sessions.length > 0) {
        await tx
          .update(credentials)
          .set({ revokedAt: now, revokedBy: principal.id })
          .where(inArray(credentials.id, sessions.map((session) => session.id)));
      }
      log.push(allowed(ctx, 'identity.unbind', { metadata: { identityId, ...row, sessionsEnded: sessions.length } }));
      return { unlinked: true as const };
    });
  }

  // --- listing --------------------------------------------------------------

  async listSessions(ctx: Asker, currentCredentialId: string | null): Promise<SessionRow[]> {
    const { principal } = ctx.caller;
    const rows = await this.#deps.db
      .select({
        id: credentials.id,
        kind: credentials.kind,
        label: credentials.label,
        hint: credentials.tokenHint,
        provider: identities.provider,
        createdAt: credentials.createdAt,
        expiresAt: credentials.expiresAt,
        lastUsedAt: credentials.lastUsedAt,
        lastUsedIp: credentials.lastUsedIp,
      })
      .from(credentials)
      .leftJoin(identities, eq(identities.id, credentials.identityId))
      .where(
        and(
          eq(credentials.principalType, principal.type),
          eq(credentials.principalId, principal.id),
          inArray(credentials.kind, ['browser', 'cli']),
          isLiveCredential(new Date()),
        ),
      );
    const lastSeen = (row: (typeof rows)[number]) => (row.lastUsedAt ?? row.createdAt).getTime();
    return rows
      .sort((a, b) => lastSeen(b) - lastSeen(a))
      .map((row) => ({
        ...row,
        kind: row.kind as SessionRow['kind'],
        createdAt: row.createdAt.toISOString(),
        expiresAt: row.expiresAt.toISOString(),
        lastUsedAt: row.lastUsedAt?.toISOString() ?? null,
        current: row.id === currentCredentialId,
      }));
  }

  async listIdentities(ctx: Asker): Promise<IdentityRow[]> {
    const { principal } = ctx.caller;
    const rows = await this.#deps.db
      .select({
        id: identities.id,
        provider: identities.provider,
        email: identities.email,
        createdAt: identities.createdAt,
        lastSignInAt: identities.lastSignInAt,
      })
      .from(identities)
      .where(
        and(
          eq(identities.principalType, principal.type),
          eq(identities.principalId, principal.id),
          isNull(identities.revokedAt),
        ),
      )
      .orderBy(identities.createdAt);
    return rows.map((row) => ({
      ...row,
      createdAt: row.createdAt.toISOString(),
      lastSignInAt: row.lastSignInAt?.toISOString() ?? null,
    }));
  }

  // --- service tokens -------------------------------------------------------

  async listServiceTokens(ctx: Asker, serviceId: string): Promise<ServiceTokenRow[]> {
    const { principal } = ctx.caller;
    const self = principal.type === 'service' && principal.id === serviceId;
    if (!self && !ctx.caller.isOwner) throw forbidden('only owners may see service tokens');
    const rows = await this.#deps.db
      .select({
        id: credentials.id,
        label: credentials.label,
        hint: credentials.tokenHint,
        createdAt: credentials.createdAt,
        createdBy: credentials.createdBy,
        expiresAt: credentials.expiresAt,
        lastUsedAt: credentials.lastUsedAt,
        lastUsedIp: credentials.lastUsedIp,
      })
      .from(credentials)
      .where(
        and(
          eq(credentials.principalType, 'service'),
          eq(credentials.principalId, serviceId),
          isLiveCredential(new Date()),
        ),
      )
      .orderBy(desc(credentials.createdAt));
    return rows.map((row) => ({
      ...row,
      createdAt: row.createdAt.toISOString(),
      expiresAt: row.expiresAt.toISOString(),
      lastUsedAt: row.lastUsedAt?.toISOString() ?? null,
    }));
  }

  /**
   * Mint a token for a service principal. The value is returned once and
   * exists nowhere afterwards; losing it means minting another.
   */
  async issueServiceToken(
    ctx: Asker,
    serviceId: string,
    input: { label: string | null; expiresInDays: number },
  ): Promise<IssuedCredential> {
    if (!Number.isInteger(input.expiresInDays) || input.expiresInDays < 1 || input.expiresInDays > MAX_SERVICE_TOKEN_DAYS) {
      throw badRequest(`tokens last between 1 and ${MAX_SERVICE_TOKEN_DAYS} days`);
    }
    const details = { kind: 'service', principalType: 'service', principalId: serviceId, label: input.label };
    return audited(this.#deps, async (tx, log) => {
      if (!ctx.caller.isOwner) {
        throw new Refusal(
          forbidden('only owners may issue service tokens'),
          denied(ctx, 'credential.issue', 'requires_instance_owner', { metadata: details }),
        );
      }
      const service = { type: 'service' as const, id: serviceId };
      const credential = await this.#issue(tx, 'service', service, {
        identityId: null,
        label: input.label,
        createdBy: ctx.caller.principal.id,
        expiresAt: new Date(Date.now() + input.expiresInDays * 86_400_000),
      }).catch((error: unknown) => {
        if (!(error instanceof SigninRefused)) throw error;
        throw new Refusal(
          notFound('unknown service'),
          denied(ctx, 'credential.issue', 'unknown_principal', { metadata: details }),
        );
      });
      log.push(
        allowed(ctx, 'credential.issue', {
          metadata: { ...details, credentialId: credential.id, expiresAt: credential.expiresAt },
        }),
      );
      return credential;
    });
  }

  // --- device flow (RFC 8628), for `coffre login` ---------------------------

  /**
   * Open a device authorization. Unauthenticated by nature, so it writes no
   * audit row, and the number of open requests is capped per address and
   * overall; a flood can only make `coffre login` wait, never grow a table
   * without bound. The cap is checked without a lock, so a burst of
   * simultaneous requests can overshoot it by a few.
   */
  async startDevice(input: { clientLabel: string | null; sourceIp: string | null }): Promise<DeviceStart> {
    const { db } = this.#deps;
    const now = new Date();
    const open = await db
      .select({ clientIp: deviceAuthorizations.clientIp, n: count() })
      .from(deviceAuthorizations)
      .where(and(isNull(deviceAuthorizations.decidedAt), gt(deviceAuthorizations.expiresAt, now)))
      .groupBy(deviceAuthorizations.clientIp);
    const total = open.reduce((sum, row) => sum + row.n, 0);
    const fromIp = open.find((row) => row.clientIp === input.sourceIp)?.n ?? 0;
    if (fromIp >= DEVICE_PENDING_PER_IP || total >= DEVICE_PENDING_TOTAL) {
      throw new ApiError('too_many_requests', 'too many sign-in requests are waiting; try again in a few minutes');
    }

    const deviceCode = randomBytes(32).toString('base64url');
    // A collision among live codes is astronomically unlikely, but the unique
    // index would turn it into a 500; draw again instead.
    for (let attempt = 0; ; attempt += 1) {
      const code = userCode();
      try {
        await db.insert(deviceAuthorizations).values({
          id: randomUUID(),
          deviceCodeHash: hashToken(deviceCode),
          userCode: code,
          clientLabel: input.clientLabel?.slice(0, 120) ?? null,
          clientIp: input.sourceIp,
          expiresAt: new Date(now.getTime() + DEVICE_TTL_SECONDS * 1000),
        });
      } catch (error) {
        if (isUniqueViolation(error) && attempt < 3) continue;
        throw error;
      }
      const verificationUri = `${this.#deps.signin.publicUrl}/auth/device`;
      return {
        deviceCode,
        userCode: code,
        verificationUri,
        verificationUriComplete: `${verificationUri}?code=${code}`,
        expiresIn: DEVICE_TTL_SECONDS,
        interval: DEVICE_POLL_SECONDS,
      };
    }
  }

  /** What the person approving a code is about to let in. */
  async describeDevice(userCodeInput: string): Promise<DeviceRequest | null> {
    const code = normalizeUserCode(userCodeInput);
    if (code === null) return null;
    const [row] = await this.#deps.db
      .select({
        userCode: deviceAuthorizations.userCode,
        clientLabel: deviceAuthorizations.clientLabel,
        clientIp: deviceAuthorizations.clientIp,
        createdAt: deviceAuthorizations.createdAt,
        expiresAt: deviceAuthorizations.expiresAt,
      })
      .from(deviceAuthorizations)
      .where(
        and(
          eq(deviceAuthorizations.userCode, code),
          isNull(deviceAuthorizations.decidedAt),
          gt(deviceAuthorizations.expiresAt, new Date()),
        ),
      );
    if (row === undefined) return null;
    return { ...row, createdAt: row.createdAt.toISOString(), expiresAt: row.expiresAt.toISOString() };
  }

  async decideDevice(ctx: Asker, userCodeInput: string, approve: boolean): Promise<{ decided: true }> {
    const action = approve ? 'device.approve' : 'device.deny';
    const code = normalizeUserCode(userCodeInput);
    if (ctx.caller.principal.type !== 'user') throw forbidden('only people approve sign-ins');
    return audited(this.#deps, async (tx, log) => {
      const now = new Date();
      const [row] =
        code === null
          ? []
          : await forUpdate(
              tx
                .select({
                  id: deviceAuthorizations.id,
                  clientLabel: deviceAuthorizations.clientLabel,
                  clientIp: deviceAuthorizations.clientIp,
                })
                .from(deviceAuthorizations)
                .where(
                  and(
                    eq(deviceAuthorizations.userCode, code),
                    isNull(deviceAuthorizations.decidedAt),
                    gt(deviceAuthorizations.expiresAt, now),
                  ),
                ),
            );
      if (row === undefined) {
        throw new Refusal(
          notFound('that code is unknown or has expired'),
          denied(ctx, action, 'unknown_code', { metadata: { userCode: code ?? userCodeInput.slice(0, 16) } }),
        );
      }
      await tx
        .update(deviceAuthorizations)
        .set(
          approve
            ? { decidedAt: now, decision: 'approved', principalType: 'user', principalId: ctx.caller.principal.id }
            : { decidedAt: now, decision: 'denied' },
        )
        .where(eq(deviceAuthorizations.id, row.id));
      log.push(
        allowed(ctx, action, {
          metadata: { deviceAuthorizationId: row.id, clientLabel: row.clientLabel, clientIp: row.clientIp },
        }),
      );
      return { decided: true as const };
    });
  }

  /** The CLI's poll. An approved code is exchanged for a CLI session exactly once. */
  async pollDevice(deviceCode: string, meta: Omit<ClientMeta, 'label'>): Promise<DevicePoll> {
    return audited(this.#deps, async (tx, log): Promise<DevicePoll> => {
      const now = new Date();
      const [row] = await forUpdate(
        tx
          .select({
            id: deviceAuthorizations.id,
            decision: deviceAuthorizations.decision,
            principalId: deviceAuthorizations.principalId,
            clientLabel: deviceAuthorizations.clientLabel,
            clientIp: deviceAuthorizations.clientIp,
            decidedAt: deviceAuthorizations.decidedAt,
            expiresAt: deviceAuthorizations.expiresAt,
            consumedAt: deviceAuthorizations.consumedAt,
          })
          .from(deviceAuthorizations)
          .where(eq(deviceAuthorizations.deviceCodeHash, hashToken(deviceCode))),
      );
      if (row === undefined || row.consumedAt !== null) return { status: 'expired' };
      if (row.decision === 'denied') return { status: 'denied' };
      // An approval is only good within the code's lifetime: one the CLI
      // never collected must not stay redeemable for a session indefinitely.
      if (row.expiresAt <= now) return { status: 'expired' };
      if (row.decision === null) return { status: 'pending' };

      const principalId = row.principalId!;
      await tx.update(deviceAuthorizations).set({ consumedAt: now }).where(eq(deviceAuthorizations.id, row.id));
      // An approval given before the person was last added is void: someone
      // removed and re-added in between starts with nothing from before.
      const [active] = await tx
        .select({ id: principals.principalId })
        .from(principals)
        .where(
          and(
            eq(principals.principalType, 'user'),
            eq(principals.principalId, principalId),
            eq(principals.active, true),
            lte(principals.createdAt, row.decidedAt!),
          ),
        );
      if (active === undefined) return { status: 'denied' };

      const principal: PrincipalRef = { type: 'user', id: principalId };
      const credential = await this.#issue(tx, 'cli', principal, {
        identityId: null,
        label: row.clientLabel,
        createdBy: principalId,
        expiresAt: new Date(now.getTime() + this.#deps.signin.cliSessionDays * 86_400_000),
      });
      const entry: AuditEntry = {
        actorType: 'user',
        actorId: principalId,
        action: 'credential.issue',
        decision: 'allow',
        requestId: meta.requestId,
        sourceIp: meta.sourceIp,
        metadata: {
          kind: 'cli',
          credentialId: credential.id,
          deviceAuthorizationId: row.id,
          clientLabel: row.clientLabel,
          clientIp: row.clientIp,
        },
      };
      log.push(entry);
      return { status: 'approved', principal, credential };
    });
  }
}

function refusalOrThrow(error: unknown): { ok: false; reason: SigninRefusal } {
  if (error instanceof SigninRefused) return { ok: false, reason: error.reason };
  throw error;
}
