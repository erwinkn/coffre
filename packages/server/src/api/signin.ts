import { randomBytes, randomUUID } from 'node:crypto';

import {
  deriveKey,
  generateToken,
  hashToken,
  isCoffreToken,
  seal,
  tokenHint,
  unseal,
  type CredentialKind,
  type PendingSignin,
  type Principal,
  type SigninConfig,
  type SigninProfile,
} from '@coffre/core/identity';
import type { Access, Vault } from '@coffre/core/vault';
import type { Database, Transaction } from '@coffre/db';
import { isUniqueViolation } from '@coffre/db/dialect';
import { credentials, deviceAuthorizations, identities } from '@coffre/db/schema';

import { authMac } from '../auth-rows.ts';
import type { AuditEntry } from '../db/audit.ts';
import {
  findCredential,
  findDeviceAuthorizations,
  findIdentity,
  insert,
  members,
  memberOf,
  memberStanding,
  principalOf,
  revokePriorMembership,
  update,
  updateAuth,
} from '../db/queries.ts';
import type { PrincipalRef } from './caller.ts';
import { allowed, audited, denied, Refusal, withRefusals, type ApiContext } from './context.ts';
import { ApiError, badRequest, forbidden, notFound } from './errors.ts';
import { formatMember } from './paths.ts';

export type SigninServiceDeps = {
  db: Database;
  chainKey: Buffer;
  /** Who is a member, and who is a root admin, is the vault's to say. */
  vault: Vault;
  signin: SigninConfig;
};

/** Who is asking, for the calls a signed-in person makes about their own sign-in. */
export type Asker = Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp' | 'credentialId'>;

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
  | 'already_linked'
  /** The matching person's record failed the vault's integrity check. */
  | 'tampered';

class SigninRefused extends Error {
  readonly reason: SigninRefusal;
  constructor(reason: SigninRefusal) {
    super(reason);
    this.reason = reason;
  }
}

/** A provider's profile, and the id of the provider it came through. */
export type SignedInAccount = SigninProfile & { provider: string };

/** What rides in the sealed cookie between leaving for the provider and coming back. */
export type PendingState = PendingSignin & {
  /** The provider it left for: the callback must come back from the same one. */
  provider: string;
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
export type CredentialPrincipal = Principal & { credentialId: string; credentialGeneration: number };

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
 * The app audit head serializes bindings. The unique index over
 * `(provider, issuerHash, subject)` also prevents binding an account twice.
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

  #issuerHash(providerId: string): string | null {
    const provider = this.config.providers.find((candidate) => candidate.id === providerId);
    // Fixed width keeps the identity index exact on every database engine.
    return provider === undefined ? null : hashToken(provider.issuer).toString('hex');
  }

  // --- signing in ---------------------------------------------------------

  async completeSignin(profile: SignedInAccount, meta: ClientMeta): Promise<SigninResult> {
    try {
      return await this.#completeSignin(profile, meta);
    } catch (error) {
      if (error instanceof SigninRefused) return { ok: false, reason: error.reason };
      // Someone else bound this account, or created this root admin, first.
      if (isUniqueViolation(error)) return this.#completeSignin(profile, meta).catch(refusalOrThrow);
      throw error;
    }
  }

  async #completeSignin(profile: SignedInAccount, meta: ClientMeta): Promise<SigninResult> {
    const claimed = profile.emails[0] ?? `${profile.provider}:${profile.subject}`;
    const base = {
      actorType: 'user' as const,
      action: 'sign_in',
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

    const issuerHash = this.#issuerHash(profile.provider);
    if (issuerHash === null) throw new SigninRefused('not_registered');
    return withRefusals(this.#deps, async () => {
      const previous = await findIdentity(this.#deps.db, this.#deps.chainKey, { ...profile, issuerHash });
      const match = previous === null ? await this.#principalForEmails(profile.emails) : null;
      if (previous === null && match === null) throw refuse('not_registered');
      const preparedId = previous === null ? match!.id : memberOf(previous.principal).id;
      const principal = { type: 'user' as const, id: preparedId };
      const standing = match?.access ?? await this.#standing(principal);
      if (standing.status === 'tampered') throw refuse('tampered', preparedId);
      if (standing.status !== 'active') throw refuse('deactivated', preparedId);
      return audited(this.#deps, async (tx, log) => {
        if (!(await this.#stillMember(tx, principal, standing))) throw refuse('deactivated', preparedId);
        const now = new Date();
        const bound = await findIdentity(tx, this.#deps.chainKey, { ...profile, issuerHash });
        let principalId: string;
        let identityId: string;
        let generation: number;
        if (bound !== null) {
          principalId = memberOf(bound.principal).id;
          identityId = bound.id;
          if (principalId !== preparedId || bound.generation !== standing.generation) throw refuse('deactivated', principalId);
          generation = standing.generation;
          await update(
            tx,
            identities,
            { id: identityId },
            { lastSignInAt: now, ...(profile.emails[0] === undefined ? {} : { email: profile.emails[0] }) },
          );
        } else {
          // The audit head serializes bindings to the same person.
          if (match === null) throw refuse('deactivated', preparedId);
          principalId = preparedId;
          generation = standing.generation;
          // A crashed older attempt may have committed after the removal sweep.
          await revokePriorMembership(tx, this.#deps.chainKey, principal, generation, 'system:signin');

          const [person] = await members(tx, this.#deps.chainKey, { member: { type: 'user', id: principalId } }, now);
          const other = (person?.identities ?? []).some(
            (identity) => identity.provider !== profile.provider || identity.issuerHash !== issuerHash || identity.subject !== profile.subject,
          );
          if (other) throw refuse('account_mismatch', principalId);

          identityId = await this.#bind(tx, principalId, profile, principalId, generation);
          log.push({
            ...base,
            actorId: principalId,
            action: 'account.link',
            decision: 'allow',
            metadata: { ...account, identityId, matchedEmail: match.email },
          });
        }

        const credential = await this.#issue(tx, 'browser', principal, {
          generation,
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
    });
  }

  /** Bind another provider account to the signed-in person. */
  async linkIdentity(
    ctx: Asker,
    profile: SignedInAccount,
  ): Promise<{ ok: true } | { ok: false; reason: SigninRefusal }> {
    const account = { provider: profile.provider, subject: profile.subject, emails: profile.emails };
    if (ctx.caller.principal.type !== 'user') throw forbidden('only people link sign-in accounts');
    const access = await this.#standing(ctx.caller.principal);
    return audited(this.#deps, async (tx, log) => {
      const standing = await this.#currentCaller(tx, ctx, access);
      if (standing === null) {
        throw new Refusal(new SigninRefused('deactivated'), denied(ctx, 'account.link', 'session_ended', { metadata: account }));
      }
      const issuerHash = this.#issuerHash(profile.provider);
      if (issuerHash === null) throw new SigninRefused('not_registered');
      const bound = await findIdentity(tx, this.#deps.chainKey, { ...profile, issuerHash });
      if (bound !== null) {
        if (bound.principal === principalOf(ctx.caller.principal) && bound.generation === standing.generation) return { ok: true as const };
        throw new Refusal(
          new SigninRefused('already_linked'),
          denied(ctx, 'account.link', 'already_linked', { metadata: account }),
        );
      }
      const identityId = await this.#bind(tx, ctx.caller.principal.id, profile, ctx.caller.principal.id, standing.generation);
      log.push(allowed(ctx, 'account.link', { metadata: { ...account, identityId } }));
      return { ok: true as const };
    }).catch(refusalOrThrow);
  }

  async #bind(tx: Transaction, principalId: string, profile: SignedInAccount, createdBy: string, generation: number): Promise<string> {
    const id = randomUUID();
    const row = {
      id,
      provider: profile.provider,
      issuerHash: this.#issuerHash(profile.provider)!,
      generation,
      subject: profile.subject,
      principal: principalOf({ type: 'user', id: principalId }),
      email: profile.emails[0] ?? null,
      createdBy,
      lastSignInAt: new Date(),
      revokedAt: null,
    };
    await insert(tx, identities, { ...row, authMac: authMac(this.#deps.chainKey, 'identities', row) });
    return id;
  }

  /**
   * The member, or root admin, that one of these verified emails names, as
   * the vault knows them. The provider's primary address is tried first.
   * Principal ids are lowercase, and so are the emails a verified profile
   * carries.
   */
  async #principalForEmails(
    emails: readonly string[],
  ): Promise<{ id: string; access: Access; email: string } | null> {
    for (const email of emails) {
      const access = await this.#standing({ type: 'user', id: email });
      if (access.status !== 'unknown') return { id: email, access, email };
    }
    return null;
  }

  async #standing(principal: PrincipalRef): Promise<Access> {
    return this.#deps.vault.access(formatMember(principal));
  }

  /**
   * Whether `principal` is still the member `standing` says, at the same
   * generation, read in a transaction that holds the log's head (`audited`
   * takes it first). The vault changes a member only after taking the head
   * for its entry, so a removal committed before shows here and refuses, and
   * one under way waits for this transaction. What is issued carries the
   * generation it was issued under; a later removal moves past it, and it
   * stops working, whatever its own row says.
   */
  async #stillMember(tx: Transaction, principal: PrincipalRef, standing: Access): Promise<boolean> {
    if (standing.status !== 'active') return false;
    const row = await memberStanding(tx, principal);
    return row !== null && row.generation === standing.generation && (row.status === 'active' || standing.isRootAdmin);
  }

  /** Revalidate the initiating credential under the app audit head. */
  async #currentCaller(tx: Transaction, ctx: Asker, standing: Access): Promise<Access | null> {
    if (standing.generation !== ctx.caller.generation || !(await this.#stillMember(tx, ctx.caller.principal, standing))) return null;
    if (ctx.credentialId !== null) {
      const row = await findCredential(tx, this.#deps.chainKey, { id: ctx.credentialId });
      if (!this.#liveCredential(row, standing, new Date()) || row?.principal !== principalOf(ctx.caller.principal)) return null;
    }
    return standing;
  }

  #liveCredential(row: Awaited<ReturnType<typeof findCredential>>, access: Access, now: Date): boolean {
    return row !== null && row.revokedAt === null && row.expiresAt > now && row.identityRevokedAt === null
      && access.status === 'active' && row.generation === access.generation
      && (row.kind !== 'browser' || (row.identityIssuerHash !== null
        && row.identityIssuerHash === this.#issuerHash(row.identityProvider ?? '')));
  }

  async #issue(
    tx: Transaction,
    kind: CredentialKind,
    principal: PrincipalRef,
    options: { generation: number; identityId: string | null; label: string | null; createdBy: string; expiresAt: Date },
  ): Promise<IssuedCredential> {
    const token = generateToken(kind);
    const id = randomUUID();
    const row = {
      id,
      kind,
      tokenHash: hashToken(token),
      generation: options.generation,
      tokenHint: tokenHint(token),
      principal: principalOf(principal),
      identityId: options.identityId,
      label: options.label?.slice(0, 120) ?? null,
      createdBy: options.createdBy,
      expiresAt: options.expiresAt,
      revokedAt: null,
    };
    await insert(tx, credentials, { ...row, authMac: authMac(this.#deps.chainKey, 'credentials', row) });
    return { id, token, expiresAt: options.expiresAt.toISOString() };
  }

  // --- verifying ------------------------------------------------------------

  /**
   * Resolve a bearer token to its caller, or throw.
   *
   * A token dies with its person: every request asks the vault who its
   * caller is, and a removed member is turned away on the next request
   * whatever credentials they still hold, before any revocation sweep.
   */
  async verify(token: string, request: { sourceIp: string | null } = { sourceIp: null }): Promise<CredentialPrincipal> {
    if (!isCoffreToken(token)) throw new Error('not a coffre credential');
    const { db } = this.#deps;
    const now = new Date();

    const row = await findCredential(db, this.#deps.chainKey, { tokenHash: hashToken(token) });
    if (row === null) throw new Error('unknown, expired or revoked credential');
    const access = await this.#deps.vault.access(row.principal);
    if (!this.#liveCredential(row, access, now)) throw new Error('unknown, expired or revoked credential');

    const lastUsed = row.lastUsedAt?.getTime() ?? 0;
    if (now.getTime() - lastUsed > TOUCH_INTERVAL_MS) {
      // Coarse on purpose: one write per credential per five minutes, not
      // one per request. Losing it must never cost the request.
      await update(db, credentials, { id: row.id }, { lastUsedAt: now, lastUsedIp: request.sourceIp }).catch(() => 0);
    }

    const member = memberOf(row.principal);
    return member.type === 'service'
      ? { type: 'service', id: member.id, commonName: member.id, credentialId: row.id, credentialGeneration: row.generation }
      : {
          type: 'user',
          id: member.id,
          email: member.id,
          subject: row.subject ?? member.id,
          credentialId: row.id,
          credentialGeneration: row.generation,
        };
  }

  // --- signing out and revoking ---------------------------------------------

  /** Revoke the credential this token is. Unknown tokens are a quiet no-op. */
  async signOut(token: string, meta: Omit<ClientMeta, 'label'>): Promise<void> {
    if (!isCoffreToken(token)) return;
    await audited(this.#deps, async (tx, log) => {
      const row = await findCredential(tx, this.#deps.chainKey, { tokenHash: hashToken(token) });
      if (row === null) return;
      const member = memberOf(row.principal);
      const revoked = await updateAuth(
        tx,
        this.#deps.chainKey,
        credentials,
        { id: row.id, revokedAt: null },
        { revokedAt: new Date(), revokedBy: member.id },
      );
      if (revoked === 0) return;
      log.push({
        actorType: member.type,
        actorId: member.id,
        action: 'sign_out',
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
      const row = await findCredential(tx, this.#deps.chainKey, { id: credentialId });
      const unknown = () =>
        new Refusal(
          notFound('unknown credential'),
          denied(ctx, 'token.revoke', 'unknown_credential', { metadata: { credentialId } }),
        );
      if (row === null || row.revokedAt !== null) throw unknown();
      const { principal } = ctx.caller;
      const own = row.principal === principalOf(principal);
      if (!own && !ctx.caller.isOwner) {
        throw new Refusal(
          forbidden("only owners may revoke other people's credentials"),
          denied(ctx, 'token.revoke', 'requires_instance_owner', { metadata: { credentialId } }),
        );
      }
      const revoked = await updateAuth(
        tx,
        this.#deps.chainKey,
        credentials,
        { id: credentialId, revokedAt: null },
        { revokedAt: new Date(), revokedBy: principal.id },
      );
      if (revoked === 0) throw unknown();
      log.push(
        allowed(ctx, 'token.revoke', {
          metadata: { credentialId, kind: row.kind, principalType: memberOf(row.principal).type, principalId: memberOf(row.principal).id },
        }),
      );
      return { revoked: true as const };
    });
  }

  /** Unbind one of your sign-in accounts, ending the sessions it opened. */
  async unlinkIdentity(ctx: Asker, identityId: string): Promise<{ unlinked: true }> {
    const { principal } = ctx.caller;
    return audited(this.#deps, async (tx, log) => {
      const now = new Date();
      const [self] = await members(tx, this.#deps.chainKey, { member: principal }, now);
      const identity = self?.identities.find((candidate) => candidate.id === identityId);
      const unbound =
        identity === undefined
          ? 0
          : await updateAuth(tx, this.#deps.chainKey, identities, { id: identityId, revokedAt: null }, { revokedAt: now, revokedBy: principal.id });
      if (identity === undefined || unbound === 0) {
        throw new Refusal(
          notFound('unknown sign-in account'),
          denied(ctx, 'account.unlink', 'unknown_identity', { metadata: { identityId } }),
        );
      }
      const sessionsEnded = await updateAuth(
        tx,
        this.#deps.chainKey,
        credentials,
        { identityId, revokedAt: null },
        { revokedAt: now, revokedBy: principal.id },
      );
      const row = { provider: identity.provider, subject: identity.subject };
      log.push(allowed(ctx, 'account.unlink', { metadata: { identityId, ...row, sessionsEnded } }));
      return { unlinked: true as const };
    });
  }

  // --- listing --------------------------------------------------------------

  async listSessions(ctx: Asker, currentCredentialId: string | null): Promise<SessionRow[]> {
    const [self] = await members(this.#deps.db, this.#deps.chainKey, { member: ctx.caller.principal }, new Date());
    const lastSeen = (row: { lastUsedAt: Date | null; createdAt: Date }) => (row.lastUsedAt ?? row.createdAt).getTime();
    return (self?.credentials ?? [])
      .filter((row) => row.kind === 'browser' || row.kind === 'cli')
      .sort((a, b) => lastSeen(b) - lastSeen(a))
      .map((row) => ({
        id: row.id,
        kind: row.kind as SessionRow['kind'],
        label: row.label,
        hint: row.tokenHint,
        provider: row.provider,
        createdAt: row.createdAt.toISOString(),
        expiresAt: row.expiresAt.toISOString(),
        lastUsedAt: row.lastUsedAt?.toISOString() ?? null,
        lastUsedIp: row.lastUsedIp,
        current: row.id === currentCredentialId,
      }));
  }

  async listIdentities(ctx: Asker): Promise<IdentityRow[]> {
    const [self] = await members(this.#deps.db, this.#deps.chainKey, { member: ctx.caller.principal }, new Date());
    return (self?.identities ?? [])
      .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
      .map((row) => ({
        id: row.id,
        provider: row.provider,
        email: row.email,
        createdAt: row.createdAt.toISOString(),
        lastSignInAt: row.lastSignInAt?.toISOString() ?? null,
      }));
  }

  // --- service tokens -------------------------------------------------------

  async listServiceTokens(ctx: Asker, serviceId: string): Promise<ServiceTokenRow[]> {
    const { principal } = ctx.caller;
    const self = principal.type === 'service' && principal.id === serviceId;
    if (!self && !ctx.caller.isOwner) throw forbidden('only owners may see service tokens');
    const [service] = await members(this.#deps.db, this.#deps.chainKey, { member: { type: 'service', id: serviceId } }, new Date());
    return (service?.credentials ?? [])
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .map((row) => ({
        id: row.id,
        label: row.label,
        hint: row.tokenHint,
        createdAt: row.createdAt.toISOString(),
        createdBy: row.createdBy,
        expiresAt: row.expiresAt.toISOString(),
        lastUsedAt: row.lastUsedAt?.toISOString() ?? null,
        lastUsedIp: row.lastUsedIp,
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
    return withRefusals(this.#deps, async () => {
      if (!ctx.caller.isOwner) {
        throw new Refusal(
          forbidden('only owners may issue service tokens'),
          denied(ctx, 'token.create', 'requires_instance_owner', { metadata: details }),
        );
      }
      const service = { type: 'service' as const, id: serviceId };
      const standing = await this.#standing(service);
      const refusal = () => new Refusal(
        notFound('unknown service'),
        denied(ctx, 'token.create', 'unknown_principal', { metadata: details }),
      );
      if (standing.status !== 'active') throw refusal();
      return audited(this.#deps, async (tx, log) => {
        if (!(await this.#stillMember(tx, service, standing))) throw refusal();
        const credential = await this.#issue(tx, 'service', service, {
          generation: standing.generation,
          identityId: null,
          label: input.label,
          createdBy: ctx.caller.principal.id,
          expiresAt: new Date(Date.now() + input.expiresInDays * 86_400_000),
        });
        log.push(
          allowed(ctx, 'token.create', {
            metadata: { ...details, credentialId: credential.id, expiresAt: credential.expiresAt },
          }),
        );
        return credential;
      });
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
    const open = await findDeviceAuthorizations(db, this.#deps.chainKey, { openAt: now });
    const fromIp = open.filter((row) => row.clientIp === input.sourceIp).length;
    if (fromIp >= DEVICE_PENDING_PER_IP || open.length >= DEVICE_PENDING_TOTAL) {
      throw new ApiError('too_many_requests', 'too many sign-in requests are waiting; try again in a few minutes');
    }

    const deviceCode = randomBytes(32).toString('base64url');
    // A collision among live codes is astronomically unlikely, but the unique
    // index would turn it into a 500; draw again instead.
    for (let attempt = 0; ; attempt += 1) {
      const code = userCode();
      try {
        const row = {
          id: randomUUID(),
          deviceCodeHash: hashToken(deviceCode),
          userCode: code,
          clientLabel: input.clientLabel?.slice(0, 120) ?? null,
          clientIp: input.sourceIp,
          expiresAt: new Date(now.getTime() + DEVICE_TTL_SECONDS * 1000),
          decision: null,
          decidedAt: null,
          principal: null,
          generation: 0,
          consumedAt: null,
        };
        await insert(db, deviceAuthorizations, { ...row, authMac: authMac(this.#deps.chainKey, 'device_authorizations', row) });
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
    const now = new Date();
    const [row] = (await findDeviceAuthorizations(this.#deps.db, this.#deps.chainKey, { userCode: code })).filter(isOpen(now));
    if (row === undefined) return null;
    return {
      userCode: row.userCode,
      clientLabel: row.clientLabel,
      clientIp: row.clientIp,
      createdAt: row.createdAt.toISOString(),
      expiresAt: row.expiresAt.toISOString(),
    };
  }

  async decideDevice(ctx: Asker, userCodeInput: string, approve: boolean): Promise<{ decided: true }> {
    const action = approve ? 'device.approve' : 'device.deny';
    const code = normalizeUserCode(userCodeInput);
    if (ctx.caller.principal.type !== 'user') throw forbidden('only people approve sign-ins');
    const access = await this.#standing(ctx.caller.principal);
    return audited(this.#deps, async (tx, log) => {
      const standing = await this.#currentCaller(tx, ctx, access);
      if (standing === null) {
        throw new Refusal(forbidden('that session has ended'), denied(ctx, action, 'session_ended'));
      }
      const now = new Date();
      const [row] = code === null ? [] : (await findDeviceAuthorizations(tx, this.#deps.chainKey, { userCode: code })).filter(isOpen(now));
      // Deciding only an undecided code makes two approvers racing agree on one answer.
      const decided =
        row === undefined
          ? 0
          : await updateAuth(
              tx,
              this.#deps.chainKey,
              deviceAuthorizations,
              { id: row.id, decidedAt: null },
              approve
                ? { decidedAt: now, decision: 'approved', principal: principalOf(ctx.caller.principal), generation: standing.generation }
                : { decidedAt: now, decision: 'denied' },
            );
      if (row === undefined || decided === 0) {
        throw new Refusal(
          notFound('that code is unknown or has expired'),
          denied(ctx, action, 'unknown_code', { metadata: { userCode: code ?? userCodeInput.slice(0, 16) } }),
        );
      }
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
    const [prepared] = await findDeviceAuthorizations(this.#deps.db, this.#deps.chainKey, { deviceCodeHash: hashToken(deviceCode) });
    if (prepared === undefined || prepared.consumedAt !== null || prepared.expiresAt <= new Date()) return { status: 'expired' };
    if (prepared.decision === null) return { status: 'pending' };
    if (prepared.decision === 'denied') return { status: 'denied' };
    const principal = memberOf(prepared.principal!) as PrincipalRef & { type: 'user' };
    const standing = await this.#standing(principal);
    try {
      return await audited(this.#deps, async (tx, log): Promise<DevicePoll> => {
        const now = new Date();
        const [row] = await findDeviceAuthorizations(tx, this.#deps.chainKey, { deviceCodeHash: hashToken(deviceCode) });
        if (row === undefined || row.consumedAt !== null) return { status: 'expired' };
        if (row.decision === 'denied') return { status: 'denied' };
        // An approval is only good within the code's lifetime: one the CLI
        // never collected must not stay redeemable for a session indefinitely.
        if (row.expiresAt <= now) return { status: 'expired' };
        if (row.decision === null) return { status: 'pending' };

        // Consumed only if still unconsumed: of two polls racing, one gets the session.
        const consumed = await updateAuth(tx, this.#deps.chainKey, deviceAuthorizations, { id: row.id, consumedAt: null }, { consumedAt: now });
        if (consumed === 0) return { status: 'expired' };
        const principalId = memberOf(row.principal!).id;
        // An approval given before the person was last added is void: someone
        // removed and re-added in between starts with nothing from before.
        if (standing.status !== 'active' || principalId !== principal.id || standing.generation !== row.generation) return { status: 'denied' };
        if (!(await this.#stillMember(tx, principal, standing))) {
          log.push({
            actorType: 'user', actorId: principal.id, action: 'sign_in', decision: 'deny',
            requestId: meta.requestId, sourceIp: meta.sourceIp,
            metadata: { kind: 'cli', deviceAuthorizationId: row.id, reason: 'membership_changed' },
          });
          return { status: 'denied' };
        }

        const credential = await this.#issue(tx, 'cli', principal, {
          generation: standing.generation,
          identityId: null,
          label: row.clientLabel,
          createdBy: principalId,
          expiresAt: new Date(now.getTime() + this.#deps.signin.cliSessionDays * 86_400_000),
        });
        const entry: AuditEntry = {
          actorType: 'user',
          actorId: principalId,
          action: 'sign_in',
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
    } catch (error) {
      if (error instanceof SigninRefused) return { status: 'denied' };
      throw error;
    }
  }
}

const isOpen = (now: Date) => (row: { decidedAt: Date | null; expiresAt: Date }) =>
  row.decidedAt === null && row.expiresAt > now;

function refusalOrThrow(error: unknown): { ok: false; reason: SigninRefusal } {
  if (error instanceof SigninRefused) return { ok: false, reason: error.reason };
  throw error;
}
