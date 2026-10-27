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
import { allows, DEFAULT_POLICY, DEVICE_TTL_SECONDS, holds, MAX_PERSONAL_TOKEN_MINUTES, PERMISSIONS, ROLES, runsInstance, type CredentialScope, type Holdings, type Policy, type RoleDefinition } from '@coffre/core/access';
import type { Access, ObjectChange, Vault } from '@coffre/core/vault';
import type { Database, Transaction } from '@coffre/db';
import { isUniqueViolation } from '@coffre/db/dialect';
import { credentials, deviceAuthorizations, identities } from '@coffre/db/schema';

import { authMac, AuthRowTampered, issuedBy, issuingBinding } from '../auth-rows.ts';
import type { AuditEntry } from '../db/audit.ts';
import {
  findBinding,
  findCredential,
  findDeviceAuthorizations,
  findIdentity,
  insert,
  members,
  memberOf,
  memberStanding,
  places,
  MAX_PARENTS,
  principalOf,
  resolvePath,
  type PlaceRow,
  credentialsBy,
  liveCredentialsWhere,
  priorCredentials,
  revokeCredentialsWhere,
  revokePriorMembership,
  update,
  updateAuth,
} from '../db/queries.ts';
import { callerFrom, type PrincipalRef } from './caller.ts';
import { AppChanges, COFFRE_ACTOR, credentialChange, retrying, revokes } from './changes.ts';
import { allowed, audited, credentialStill, denied, Refusal, requireInstance, withRefusals, type ApiContext } from './context.ts';
import { accessFor, type Accesses, type Recalled } from '../accesses.ts';
import { ApiError, badRequest, forbidden, notFound } from './errors.ts';
import { formatMember, parsePath } from './paths.ts';
import {
  issuedScope,
  issuerNow,
  issuerStill,
  managedAccount,
  notManager,
  personalScope,
  readScope,
  scopeByPath,
  sealCredentials,
  sealScopes,
  storedScope,
  unsealedScope,
  type ScopeByPath,
} from './services.ts';

export type SigninServiceDeps = {
  db: Database;
  chainKey: Buffer;
  /** Who is a member, and who owns the instance while nobody does, is the vault's to say. */
  vault: Vault;
  signin: SigninConfig;
  /**
   * Whether 0.4's tokens and bindings are sealed (`sealScopes`), for as long
   * as the configuration lives: the isolate's, which builds a service for
   * each request, or the process's. The service's own when left out.
   */
  scopes?: { sealed: boolean };
  /** The vault's last answer about each principal, for as long as the configuration lives (`Accesses`). */
  accesses?: Accesses;
};

/** Who is asking, for the calls a signed-in person makes about their own sign-in. */
export type Asker = Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp' | 'credentialId' | 'via'>;

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

/**
 * A credential that could not be checked, rather than one checked and
 * refused: the database or the vault did not answer. It is no sign that
 * the caller is signed out, and must not read as one (auth.ts). A row that
 * answered and failed its MAC was checked: that is a refusal.
 */
export class CredentialUncheckable extends Error {
  constructor(cause: unknown) {
    super('coffre cannot check this credential right now', { cause });
    this.name = 'CredentialUncheckable';
  }
}

class SigninRefused extends Error {
  readonly reason: SigninRefusal;
  /** With `account_mismatch`: the providers the person already signs in with, by id. */
  readonly providers: string[] | undefined;
  constructor(reason: SigninRefusal, providers?: string[]) {
    super(reason);
    this.reason = reason;
    this.providers = providers;
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

/** What a credential is issued with, beyond its kind and principal. */
/** A credential's row, as its issuer writes it; `id` chosen before the transaction, so that 0.15's change of it is too (`#issueChange`). */
type CredentialOptions = { id?: string; generation: number; identityId: string | null; label: string | null; createdBy: string; expiresAt: Date; scope?: CredentialScope; places?: readonly HandlePlace[] };

/** A service or personal token as issued: its value, once, and what it reaches, by path. */
export type IssuedToken = IssuedCredential & TokenPlan;

/**
 * What issuing a token would make: what it reaches, by path; and, a
 * service's, the places of those that hold a sensitive value it will not
 * read, which only an Owner of their project issues one that does (R32).
 */
export type TokenPlan = { scope: ScopeByPath; withheld?: string[] };

/** What a personal token is made with: all three said, none assumed. */
export type PersonalTokenInput = { label: string; expiresInMinutes: number; scope: ScopeByPath };

/** What a handle is made with: a label, which its entries name, how long it lasts, and the environments it stands in for, by path. */
export type HandleInput = { label: string; expiresInMinutes: number; paths: string[] };

/** An environment a handle was made for, by id, so that a rename keeps it, and whether as `@me`, its holder's personal config of it. */
export type HandlePlace = { environmentId: string; personal: boolean };

/** The personal token a request came in on: its row's id, its label and when it ends. */
export type PersonalToken = { id: string; label: string; expiresAt: string };

export type SigninResult =
  | { ok: true; principal: PrincipalRef; credential: IssuedCredential }
  /**
   * With `account_mismatch`, `providers`: the ids of the providers the person
   * already signs in with. Theirs to know: the provider has just verified
   * that the email they share is the visitor's. Ids only, which the sign-in
   * page shows anyone; never an account or another address.
   */
  | { ok: false; reason: SigninRefusal; providers?: string[] };

/** A caller authenticated by a coffre-issued credential. */
/**
 * Who a credential is, and what the vault said of them when it was checked:
 * the request's one vault call, which loading the caller reads rather than
 * asking again.
 */
export type CredentialPrincipal = Principal & {
  credentialId: string;
  credentialGeneration: number;
  access: Access;
  /** Set when `access` is the vault's answer kept from an earlier request (`accessFor`), for a request that `recall`s. */
  recalled?: Recalled;
  /** The newest `policy.change` as the credential was read, before the vault was asked for `access`; null for none. */
  policySeq: bigint | null;
  /** Its scope, a service or personal token's or its binding's, past which nothing it asks reaches; null for a session's. */
  credentialScope: CredentialScope | null;
  /** Whether a trust binding issued it, for a CI run: the request's entries then name it. */
  exchanged: boolean;
  /** A personal token, which acts as its person within its scope: the request's entries name it too. Null for anything else. */
  personalToken: PersonalToken | null;
  /** The environments a handle was made for; null for any other credential, or a handle of 0.8. */
  handlePlaces: readonly HandlePlace[] | null;
  /** When the credential ends, ISO 8601. */
  expiresAt: string;
};

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

/** A service account's bearer token, or a person's personal token, as its list shows it: never its value. */
export type TokenRow = {
  id: string;
  label: string | null;
  hint: string;
  createdAt: string;
  createdBy: string;
  expiresAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  /**
   * What it reaches, of what its account or person holds, by path; null for one 0.4 made and the app has not sealed
   * yet, which reaches all of it, or for a workload's session (`session`), which holds its binding's.
   */
  scope: ScopeByPath | null;
  /** A workload's key-bound session (docs/design/workload-access.md): the binding it signed in through, whose scope it holds when its own is null. */
  session?: { bindingId: string | null };
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

/** Whether a credential is a member's token, a service account's or a person's, rather than a session. */
function isToken(row: { kind: string }): boolean {
  return row.kind === 'service' || row.kind === 'personal' || row.kind === 'handle';
}

type HeldCredential = NonNullable<Awaited<ReturnType<typeof members>>[number]>['credentials'][number];

/**
 * A member's live tokens, as their list shows them, newest first: never a
 * person's session, nor what a trust binding issued a CI run for five
 * minutes; a service's workload sessions, each with its binding.
 */
export function tokenRows(held: readonly HeldCredential[], known: readonly PlaceRow[]): TokenRow[] {
  return held
    .filter((row) => (isToken(row) && issuingBinding(row.createdBy) === null) || row.kind === 'workload')
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
      scope: scopeByPath(readScope(row.scope), known),
      ...(row.kind === 'workload' ? { session: { bindingId: issuingBinding(row.createdBy) } } : {}),
    }));
}

/** A handle's places, as its row stores them under its MAC: null for one of 0.8, and none for one that does not read as them. */
function readPlaces(stored: string | null): readonly HandlePlace[] | null {
  if (stored === null) return null;
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(stored);
  } catch {}
  const isPlace = (place: unknown) => typeof place === 'object' && place !== null && typeof (place as HandlePlace).environmentId === 'string' && typeof (place as HandlePlace).personal === 'boolean';
  return Array.isArray(parsed) && parsed.every(isPlace) ? parsed : [];
}

/** Accept what a person types: any case, with or without the dash. */
export function normalizeUserCode(input: string): string | null {
  const letters = input.toUpperCase().replace(/[^A-Z]/g, '');
  if (letters.length !== 8 || [...letters].some((c) => !USER_CODE_ALPHABET.includes(c))) {
    return null;
  }
  return `${letters.slice(0, 4)}-${letters.slice(4)}`;
}

/** What a handle reads and uses, and no more: it writes nothing. */
const HANDLE_HOLDS: RoleDefinition = { name: 'Handle', description: 'Read and use, as its person does.', permissions: ['secret.read', 'secret.use'], protected: ['secret.read', 'secret.use'] };

/**
 * The roles a handle's scope is issued under (`issueHandle`): each place
 * keeps what its person holds there, in each column, of reading and using
 * (`issuedGrant`, capped by `heldColumns`), whatever an Owner made of the
 * roles. `viewer` names a place its person reads, `contributor` one they
 * only use.
 *
 *   an Owner, at a protected prod       read, use / read, use
 *   a Developer, at the same            read, use / use
 */
const HANDLE_POLICY: Policy = { ...DEFAULT_POLICY, roles: { ...ROLES, viewer: HANDLE_HOLDS, contributor: HANDLE_HOLDS } };

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
  readonly #scopes: { sealed: boolean };

  constructor(deps: SigninServiceDeps) {
    this.#deps = deps;
    // Derived rather than configured: one fewer secret to provision, and
    // HKDF keeps it independent of the audit chain key it comes from.
    this.#stateKey = deriveKey(deps.chainKey, 'signin-state/v1');
    this.#scopes = deps.scopes ?? { sealed: false };
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
      if (error instanceof SigninRefused) return refusal(error);
      // Someone else bound this account first.
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
    const refuse = (reason: SigninRefusal, actorId = claimed, providers?: string[]) =>
      new Refusal(new SigninRefused(reason, providers), {
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
      return retrying(async () => {
      // The session, and, binding a new account, the credentials of an earlier membership it revokes (`revokePriorMembership`).
      const plan = { id: randomUUID(), expiresAt: new Date(Date.now() + this.#deps.signin.browserSessionHours * 3_600_000) };
      const changes = await AppChanges.prepare(this.#deps.vault, formatMember(principal), async () => {
        const prior = previous === null ? await liveCredentialsWhere(this.#deps.db, this.#deps.chainKey, priorCredentials(principal, standing.generation, new Date())) : [];
        return [this.#issueChange('browser', principal, plan), ...revokes(prior)];
      });
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
          const ended = await revokePriorMembership(tx, this.#deps.chainKey, principal, generation, 'system:signin');
          changes?.expectRevoked(ended);

          const [person] = await members(tx, this.#deps.chainKey, { member: { type: 'user', id: principalId } }, now);
          const others = (person?.identities ?? []).filter(
            (identity) => identity.provider !== profile.provider || identity.issuerHash !== issuerHash || identity.subject !== profile.subject,
          );
          if (others.length > 0) {
            // In the order the providers are configured: the sign-in page's.
            const order = this.#deps.signin.providers.map(({ id }) => id);
            const providers = [...new Set(others.map(({ provider }) => provider))].sort((a, b) => order.indexOf(a) - order.indexOf(b));
            throw refuse('account_mismatch', principalId, providers);
          }

          identityId = await this.#bind(tx, principalId, profile, principalId, generation);
          log.push({
            ...base,
            actorId: principalId,
            action: 'account.link',
            decision: 'allow',
            metadata: { ...account, identityId, matchedEmail: match.email },
          });
        }

        if (bound !== null) changes?.expectRevoked([]);
        const credential = await this.#issue(tx, 'browser', principal, {
          ...plan,
          generation,
          identityId,
          label: meta.label,
          createdBy: principalId,
        });
        log.push({
          ...base,
          actorId: principalId,
          decision: 'allow',
          metadata: { ...account, identityId, targetCredentialId: credential.id },
        });
        return { ok: true as const, principal, credential };
      }, changes);
      });
    });
  }

  /** Bind another provider account to the signed-in person. */
  async linkIdentity(
    ctx: Asker,
    profile: SignedInAccount,
  ): Promise<{ ok: true } | { ok: false; reason: SigninRefusal }> {
    const account = { provider: profile.provider, subject: profile.subject, emails: profile.emails };
    // An account linked through a personal token would sign in with all its person holds, for good.
    if (ctx.caller.principal.type !== 'user' || ctx.caller.credentialScope !== null) throw forbidden('only people link sign-in accounts, signed in as themselves');
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
   * The member that one of these verified emails names, as the vault knows
   * them: asking makes one the vault's configuration names an Owner, if
   * they are not one yet (`owners`). The provider's primary address is tried first.
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
    const row = await memberStanding(tx, principalOf(principal));
    return row !== null && row.generation === standing.generation && row.status === 'active';
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
      // One a trust binding issued lives no longer than the binding: removed, replaced or put back, it ends.
      && row.bindingStands !== false
      && (row.kind !== 'browser' || (row.identityIssuerHash !== null
        && row.identityIssuerHash === this.#issuerHash(row.identityProvider ?? '')));
  }

  /** A live service token 0.4 made, or a run's credential its binding issued, that carries no scope yet. */
  #unsealed(row: NonNullable<Awaited<ReturnType<typeof findCredential>>>, access: Access, now: Date): boolean {
    return row.kind === 'service' && unsealedScope(row.scope) && this.#liveCredential(row, access, now);
  }

  async #issue(
    tx: Transaction,
    kind: CredentialKind,
    principal: PrincipalRef,
    options: CredentialOptions,
  ): Promise<IssuedCredential> {
    const { row, issued } = this.#credential(kind, principal, options);
    await insert(tx, credentials, row);
    return issued;
  }

  /** The change issuing a credential makes to 0.15's log: the object of the row `#credential` writes, from the same options. */
  #issueChange(kind: CredentialKind, principal: PrincipalRef, options: { id: string; expiresAt: Date; scope?: CredentialScope }): ObjectChange {
    const scope = options.scope === undefined ? null : storedScope(options.scope);
    return credentialChange(null, { id: options.id, principal: principalOf(principal), kind, scope, revokedAt: null, expiresAt: options.expiresAt });
  }

  /** A credential's row, signed, and what its holder is given: written by whoever issues it. */
  #credential(kind: CredentialKind, principal: PrincipalRef, options: CredentialOptions): { row: typeof credentials.$inferInsert; issued: IssuedCredential } {
    const token = generateToken(kind);
    const id = options.id ?? randomUUID();
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
      scope: options.scope === undefined ? null : storedScope(options.scope),
      places: options.places === undefined ? null : JSON.stringify(options.places.map(({ environmentId, personal }) => ({ environmentId, personal }))),
      revokedAt: null,
    };
    return { row: { ...row, authMac: authMac(this.#deps.chainKey, 'credentials', row) }, issued: { id, token, expiresAt: options.expiresAt.toISOString() } };
  }

  // --- verifying ------------------------------------------------------------

  /**
   * Resolve a bearer token to its caller, or throw.
   *
   * A token dies with its person: every request asks the vault who its
   * caller is, and a removed member is turned away on the next request
   * whatever credentials they still hold, before any revocation sweep.
   */
  async verify(token: string, request: { sourceIp: string | null; recall?: boolean } = { sourceIp: null }): Promise<CredentialPrincipal> {
    if (!isCoffreToken(token)) throw new Error('not a coffre credential');
    const { db, chainKey } = this.#deps;
    const now = new Date();
    const tokenHash = hashToken(token);

    let row: Awaited<ReturnType<typeof findCredential>>;
    let access: Access | null = null;
    let recalled: Recalled | null = null;
    let policySeq: bigint | null = null;
    try {
      if (!this.#scopes.sealed) {
        await sealScopes(db, chainKey, this.#deps.vault);
        this.#scopes.sealed = true;
      }
      row = await findCredential(db, chainKey, { tokenHash });
      // Read with the row, before the vault is asked: a seal below commits only while the policy it answers with is still the newest.
      policySeq = row?.policySeq ?? null;
      // A kept answer at the credential's generation, unless its scope is still to be sealed, from what the account holds now.
      const recall = request.recall === true && row !== null && !(row.kind === 'service' && unsealedScope(row.scope));
      if (row !== null) ({ access, recalled } = await accessFor(this.#deps, row.principal, recall && { generation: row.generation }));
      // A token or binding an older release made after this configuration sealed its own: sealed on its first use, with the account's grants the vault just answered.
      if (row !== null && access !== null && this.#unsealed(row, access, now)) {
        const binding = issuingBinding(row.createdBy);
        const issued = binding === null ? row : await findBinding(db, chainKey, row.principal, binding);
        if (issued !== null) {
          await sealCredentials(db, chainKey, this.#deps.vault, access, policySeq, [{ kind: binding === null ? 'token' : 'binding', id: binding ?? row.id, principal: row.principal, createdBy: issued.createdBy, scope: issued.scope }]);
        }
        row = await findCredential(db, chainKey, { tokenHash });
        if (row !== null && this.#unsealed(row, access, now)) throw new Error('its scope could not be sealed');
      }
    } catch (error) {
      if (error instanceof AuthRowTampered) throw error;
      throw new CredentialUncheckable(error);
    }
    if (row === null || access === null || !this.#liveCredential(row, access, now)) throw new Error('unknown, expired or revoked credential');

    const lastUsed = row.lastUsedAt?.getTime() ?? 0;
    if (now.getTime() - lastUsed > TOUCH_INTERVAL_MS) {
      // Coarse on purpose: one write per credential per five minutes, not
      // one per request. Losing it must never cost the request.
      await update(db, credentials, { id: row.id }, { lastUsedAt: now, lastUsedIp: request.sourceIp }).catch(() => 0);
    }

    const member = memberOf(row.principal);
    return member.type === 'service'
      ? {
          type: 'service',
          id: member.id,
          commonName: member.id,
          credentialId: row.id,
          credentialGeneration: row.generation,
          access,
          ...(recalled === null ? {} : { recalled }),
          policySeq,
          credentialScope: readScope(row.scope),
          exchanged: row.bindingStands !== null,
          personalToken: null,
          handlePlaces: null,
          expiresAt: row.expiresAt.toISOString(),
        }
      : {
          type: 'user',
          id: member.id,
          email: member.id,
          subject: row.subject ?? member.id,
          credentialId: row.id,
          credentialGeneration: row.generation,
          exchanged: false,
          access,
          ...(recalled === null ? {} : { recalled }),
          policySeq,
          // A personal token's scope is under its row's MAC; one that does not read as a scope reaches nothing.
          credentialScope: row.kind === 'personal' || row.kind === 'handle' ? readScope(row.scope) ?? [] : null,
          personalToken: row.kind === 'personal' ? { id: row.id, label: row.label ?? '', expiresAt: row.expiresAt.toISOString() } : null,
          handlePlaces: row.kind === 'handle' ? readPlaces(row.places) : null,
          expiresAt: row.expiresAt.toISOString(),
        };
  }

  // --- signing out and revoking ---------------------------------------------

  /** Revoke the credential this token is. Unknown tokens are a quiet no-op. */
  async signOut(token: string, meta: Omit<ClientMeta, 'label'>): Promise<void> {
    if (!isCoffreToken(token)) return;
    const tokenHash = hashToken(token);
    await retrying(async () => {
    // Its actor, the session's own principal: a sign-out acts for whoever holds the token.
    const changes = await AppChanges.prepare(
      this.#deps.vault,
      (read) => (read[0]?.kind === 'credential' ? read[0].after.principal : COFFRE_ACTOR),
      async () => revokes(await liveCredentialsWhere(this.#deps.db, this.#deps.chainKey, credentialsBy.tokenHash(tokenHash))),
    );
    await audited(this.#deps, async (tx, log) => {
      const row = await findCredential(tx, this.#deps.chainKey, { tokenHash });
      if (row === null) return changes?.expectRevoked([]);
      const member = memberOf(row.principal);
      const revoked = await updateAuth(
        tx,
        this.#deps.chainKey,
        credentials,
        { id: row.id, revokedAt: null },
        { revokedAt: new Date(), revokedBy: member.id },
      );
      changes?.expectRevoked(revoked === 0 ? [] : [row.id]);
      if (revoked === 0) return;
      log.push({
        actorType: member.type,
        actorId: member.id,
        action: 'sign_out',
        decision: 'allow',
        requestId: meta.requestId,
        sourceIp: meta.sourceIp,
        // A run's credential signing itself out is the run's act, too; a personal token's, the token's.
        metadata: { targetCredentialId: row.id, kind: row.kind, ...(issuingBinding(row.createdBy) !== null || row.kind === 'personal' || row.kind === 'handle' ? { credentialId: row.id } : {}) },
      });
    }, changes);
    });
  }

  /**
   * Revoke one credential: your own; or anyone's, if you run the instance;
   * or, `of` a service account the caller manages (`managedAccount`, asked
   * before: no vault call runs in a transaction), one of its tokens. With
   * `of`, a credential that is not one of the member's tokens is unknown;
   * as `'own handle'`, one that is not a handle of the caller's.
   */
  async revokeCredential(ctx: Asker, credentialId: string, of: { member: string; managed: boolean } | 'own handle' | null = null): Promise<{ revoked: true }> {
    return retrying(async () => {
    const changes = await AppChanges.prepare(this.#deps.vault, formatMember(ctx.caller.principal), async () => revokes(await liveCredentialsWhere(this.#deps.db, this.#deps.chainKey, credentialsBy.id(credentialId))));
    // Whether the caller manages the token's account (`of`) was weighed with the policy they were loaded with (`audited`).
    return audited({ ...this.#deps, caller: ctx.caller }, async (tx, log) => {
      const row = await findCredential(tx, this.#deps.chainKey, { id: credentialId });
      const unknown = () =>
        new Refusal(
          notFound('unknown credential'),
          denied(ctx, 'token.revoke', 'unknown_credential', { metadata: { targetCredentialId: credentialId } }),
        );
      if (row === null || row.revokedAt !== null) throw unknown();
      const { principal } = ctx.caller;
      const own = row.principal === principalOf(principal);
      // Of a service it manages: one of its tokens, or a workload's key-bound session, which its managers end as they revoke its tokens.
      if (of === 'own handle' ? row.kind !== 'handle' || !own : of !== null && (row.principal !== of.member || !(isToken(row) || row.kind === 'workload'))) throw unknown();
      if (!own && (of === null || of === 'own handle' || !of.managed)) requireInstance(ctx, 'token.revoke', { metadata: { targetCredentialId: credentialId } }, "revoke other people's credentials");
      const revoked = await updateAuth(
        tx,
        this.#deps.chainKey,
        credentials,
        { id: credentialId, revokedAt: null },
        { revokedAt: new Date(), revokedBy: principal.id },
      );
      if (revoked === 0) throw unknown();
      changes?.expectRevoked([credentialId]);
      log.push(
        allowed(ctx, 'token.revoke', {
          metadata: { targetCredentialId: credentialId, kind: row.kind, principalType: memberOf(row.principal).type, principalId: memberOf(row.principal).id },
        }),
      );
      return { revoked: true as const };
    }, changes);
    });
  }

  /** Unbind one of your sign-in accounts, ending the sessions it opened. */
  async unlinkIdentity(ctx: Asker, identityId: string): Promise<{ unlinked: true }> {
    const { principal } = ctx.caller;
    return retrying(async () => {
    const changes = await AppChanges.prepare(this.#deps.vault, formatMember(principal), async () => revokes(await liveCredentialsWhere(this.#deps.db, this.#deps.chainKey, credentialsBy.identity(identityId))));
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
      const ended = await revokeCredentialsWhere(tx, this.#deps.chainKey, credentialsBy.identity(identityId), { revokedAt: now, revokedBy: principal.id });
      changes?.expectRevoked(ended);
      const row = { provider: identity.provider, subject: identity.subject };
      log.push(allowed(ctx, 'account.unlink', { metadata: { identityId, ...row, sessionsEnded: ended.length } }));
      return { unlinked: true as const };
    }, changes);
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

  /**
   * A member's live tokens: a service account's bearer tokens, for the
   * account itself and those who manage it; a person's personal tokens, for
   * them and for whoever runs the instance, as their sessions are.
   */
  async listTokens(ctx: Asker, member: PrincipalRef): Promise<TokenRow[]> {
    const { principal } = ctx.caller;
    const self = principal.type === member.type && principal.id === member.id;
    if (member.type === 'service' && !self && !(await managedAccount(this.#deps, ctx.caller, member.id)).managed) {
      throw forbidden('only those who manage this service account may see its tokens');
    }
    if (member.type === 'user' && !self && !runsInstance(ctx.caller)) {
      throw forbidden("only admins and owners of the whole instance may see other people's tokens");
    }
    const [[held], known] = await Promise.all([
      members(this.#deps.db, this.#deps.chainKey, { member }, new Date()),
      places(this.#deps.db),
    ]);
    return tokenRows(held?.credentials ?? [], known);
  }

  /**
   * Mint a token for a service principal. The value is returned once and
   * exists nowhere afterwards; losing it means minting another. Its scope
   * is what the caller asks, by path, or all the account holds; never more
   * than the account holds, nor than the caller could give it
   * (`issuedScope`), and never changed after.
   */
  async issueServiceToken(
    ctx: Asker,
    serviceId: string,
    input: { label: string | null; expiresInDays: number; scope?: ScopeByPath },
  ): Promise<IssuedToken> {
    this.#bearersIssued();
    if (!Number.isInteger(input.expiresInDays) || input.expiresInDays < 1 || input.expiresInDays > MAX_SERVICE_TOKEN_DAYS) {
      throw badRequest(`tokens last between 1 and ${MAX_SERVICE_TOKEN_DAYS} days`);
    }
    const details = { kind: 'service', principalType: 'service', principalId: serviceId, label: input.label };
    return withRefusals(this.#deps, async () => {
      const service = { type: 'service' as const, id: serviceId };
      // The issuer as the vault answers now, held to under the head: demoted meanwhile, they give it nothing (`issuerStill`).
      const { caller, accessSeq } = await issuerNow(this.#deps, ctx.caller.principal, { ctx, action: 'token.create' });
      const { standing, scope, byPath, withheld, refusal } = await this.#tokenScope({ ...ctx, caller }, serviceId, input.scope, details);
      const plan = { id: randomUUID(), expiresAt: new Date(Date.now() + input.expiresInDays * 86_400_000), scope };
      const changes = await AppChanges.prepare(this.#deps.vault, formatMember(ctx.caller.principal), [this.#issueChange('service', service, plan)]);
      // Its scope was weighed with the policy and the issuer as the vault answered: committed only while still so (`audited`, `issuerStill`).
      return audited({ ...this.#deps, caller }, async (tx, log) => {
        await issuerStill(tx, caller, accessSeq);
        await credentialStill(ctx, tx, 'token.create');
        if (!(await this.#stillMember(tx, service, standing))) throw refusal();
        const credential = await this.#issue(tx, 'service', service, {
          ...plan,
          generation: standing.generation,
          identityId: null,
          label: input.label,
          createdBy: ctx.caller.principal.id,
        });
        log.push(
          allowed(ctx, 'token.create', {
            metadata: { ...details, targetCredentialId: credential.id, expiresAt: credential.expiresAt, scope },
          }),
        );
        return { ...credential, scope: byPath, withheld };
      }, changes);
    });
  }

  /**
   * A strict instance issues a service no bearer token (`useOnly`,
   * docs/design/workload-access.md, section 6.3): its workloads sign in
   * with a key, and the tokens it holds already are refused at use.
   */
  #bearersIssued(): void {
    if (this.#deps.signin.workloads?.useOnly === true) {
      throw new ApiError('forbidden', 'this instance issues no service token (useOnly): trust the workload with a binding, and it signs in with its key', 'use_only');
    }
  }

  /** What a token issued now would reach, checked as issuing one is (`issueServiceToken`); issues nothing. */
  async planServiceToken(ctx: Asker, serviceId: string, input: { label: string | null; scope?: ScopeByPath }): Promise<TokenPlan> {
    this.#bearersIssued();
    const details = { kind: 'service', principalType: 'service', principalId: serviceId, label: input.label };
    return withRefusals(this.#deps, async () => {
      const { byPath, withheld } = await this.#tokenScope(ctx, serviceId, input.scope, details);
      return { scope: byPath, withheld };
    });
  }

  /** Who may issue the service's tokens (`managesService`), and what one would reach (`issuedScope`). */
  async #tokenScope(ctx: Asker, serviceId: string, wanted: ScopeByPath | undefined, details: Record<string, unknown>) {
    // Who runs the instance, or a person who reaches every grant it holds (`managesService`).
    const { standing, managed, setting } = await managedAccount(this.#deps, ctx.caller, serviceId);
    if (!managed) throw notManager(ctx, 'token.create', details, 'issue its tokens');
    const refusal = () => new Refusal(
      notFound('unknown service'),
      denied(ctx, 'token.create', 'unknown_principal', { metadata: details }),
    );
    if (standing.status !== 'active') throw refusal();
    return { standing, refusal, ...await issuedScope(this.#deps.db, ctx, setting, standing, wanted, { action: 'token.create', metadata: details }) };
  }

  // --- personal tokens ------------------------------------------------------

  /**
   * Mint a personal token: a bearer token that acts as the caller, within
   * `scope`, until it expires or they revoke it. Each grant of its scope is
   * a role they hold all of at its place now, one that manages no access
   * (`personalScope`); a request made with it holds what both the scope
   * and its person hold then (`allows`), so their losing a grant narrows
   * it, and their leaving ends it. Made from a session only: a token never
   * makes another. The value is returned once and kept nowhere.
   */
  async issuePersonalToken(ctx: Asker, input: PersonalTokenInput): Promise<IssuedToken> {
    return withRefusals(this.#deps, async () => {
      const { access, scope, byPath, details } = await this.#personalScope(ctx, input);
      const person = ctx.caller.principal;
      const plan = { id: randomUUID(), expiresAt: new Date(Date.now() + input.expiresInMinutes * 60_000), scope };
      const changes = await AppChanges.prepare(this.#deps.vault, formatMember(person), [this.#issueChange('personal', person, plan)]);
      // Its scope was weighed with the policy as the caller was loaded: committed only while still so (`audited`).
      return audited({ ...this.#deps, caller: ctx.caller }, async (tx, log) => {
        const standing = await this.#currentCaller(tx, ctx, access);
        if (standing === null) {
          throw new Refusal(forbidden('that session has ended'), denied(ctx, 'token.create', 'session_ended', { metadata: details }));
        }
        const credential = await this.#issue(tx, 'personal', person, {
          ...plan,
          generation: standing.generation,
          identityId: null,
          label: input.label,
          createdBy: person.id,
        });
        log.push(
          allowed(ctx, 'token.create', {
            metadata: { ...details, targetCredentialId: credential.id, expiresAt: credential.expiresAt, scope },
          }),
        );
        return { ...credential, scope: byPath };
      }, changes);
    });
  }

  /**
   * Mint a handle (docs/design/credential-proxy.md): the placeholder a
   * person's app holds in place of the values of `paths`, which only the
   * credential proxy takes, to use those values for them. It reaches
   * nothing else: no API route, no page. Each place of its scope keeps
   * what its person held there of reading and using, in each column
   * (`HANDLE_POLICY`), and a request with it holds what both that and its
   * person hold then, as a personal token does, so their losing a grant
   * narrows it and their leaving ends it: an Owner's handle reads a
   * protected prod as they do, a Developer's only uses it.
   * Made by a person, on a session or a personal token of theirs: from a
   * token, within its scope, and never past its end. `coffre run` makes
   * one per run.
   */
  async issueHandle(ctx: Asker & Pick<ApiContext, 'personalToken'>, input: HandleInput): Promise<IssuedToken> {
    return withRefusals(this.#deps, async () => {
      const person = ctx.caller.principal;
      const details = { kind: 'handle', principalType: person.type, principalId: person.id, label: input.label };
      if (!Number.isInteger(input.expiresInMinutes) || input.expiresInMinutes < 1 || input.expiresInMinutes > MAX_PERSONAL_TOKEN_MINUTES) {
        throw badRequest(`a handle lasts between a minute and ${MAX_PERSONAL_TOKEN_MINUTES / 1440} days`);
      }
      // A service account reads its values: it needs no placeholder. A connected app's or a binding's scope is not a person's to hand on.
      if (person.type !== 'user' || (ctx.caller.credentialScope !== null && ctx.personalToken === null)) {
        throw new Refusal(
          forbidden('only a person makes a handle, on a session or a personal token of theirs: a service account reads its values'),
          denied(ctx, 'token.create', 'handle', { metadata: details }),
        );
      }
      const access = await this.#standing(person);
      // What the person holds now, and, on a personal token, what it does: a handle never reaches past the credential that made it.
      const holder = callerFrom(person, access, ctx.caller.policySeq, ctx.caller.credentialScope);
      const { reached, madeFor } = await this.#handlePlaces(holder, input.paths);
      // `viewer` where its person reads; `contributor` where they only use, which the proxy needs, and no more: a handle writes nothing.
      const wanted = Object.fromEntries(reached.map(({ path, reads }) => [path, reads ? 'viewer' as const : 'contributor' as const]));
      // Use is what a handle exercises: a token that only uses a place, its grant since narrowed, still makes one there.
      const { scope, byPath } = await personalScope(this.#deps.db, ctx, holder, wanted, details, {
        policy: HANDLE_POLICY,
        needs: (role, place) => (role === 'contributor' ? ['secret.use'] : PERMISSIONS.filter((permission) => holds(ROLES.viewer, permission, place, holder))),
      });
      const ends = Math.min(Date.now() + input.expiresInMinutes * 60_000, ctx.personalToken === null ? Infinity : Date.parse(ctx.personalToken.expiresAt));
      const plan = { id: randomUUID(), expiresAt: new Date(ends), scope };
      const changes = await AppChanges.prepare(this.#deps.vault, formatMember(person), [this.#issueChange('handle', person, plan)]);
      // Its scope was weighed with the policy as the caller was loaded: committed only while still so (`audited`).
      return audited({ ...this.#deps, caller: ctx.caller }, async (tx, log) => {
        const standing = await this.#currentCaller(tx, ctx, access);
        if (standing === null) {
          throw new Refusal(forbidden('that session has ended'), denied(ctx, 'token.create', 'session_ended', { metadata: details }));
        }
        const credential = await this.#issue(tx, 'handle', person, {
          ...plan,
          generation: standing.generation,
          identityId: null,
          label: input.label,
          createdBy: person.id,
          // What the proxy's stable URL, `/use/<credential>`, resolves to: the environments as asked, `@me` included.
          places: madeFor,
        });
        log.push(
          allowed(ctx, 'token.create', {
            metadata: { ...details, targetCredentialId: credential.id, expiresAt: credential.expiresAt, scope },
          }),
        );
        return { ...credential, scope: byPath };
      }, changes);
    });
  }

  /**
   * The environments a handle for `paths` reaches, by path: each named, a
   * personal config by the environment it is a config of (`dev@me`, read as
   * its owner, is held to the scope on dev), and each parent a fork inherits
   * from that the holder reads too, so that inherited keys open through it
   * as they would for its person. A parent they do not read stays out, and
   * its keys refused, as for a read. And those it was made for, once each.
   */
  async #handlePlaces(holder: Holdings, paths: readonly string[]): Promise<{ reached: { path: string; reads: boolean }[]; madeFor: HandlePlace[] }> {
    const places = new Map<string, boolean>();
    const madeFor: HandlePlace[] = [];
    const at = (place: NonNullable<Awaited<ReturnType<typeof resolvePath>>>) =>
      ({ projectId: place.project.id, environmentId: place.environment!.id, environmentSlug: place.environment!.slug });
    for (const raw of paths) {
      const path = parsePath(raw.replace(/@me$/, ''), [2]);
      let place = await resolvePath(this.#deps.db, path);
      // One it names: viewer where its person reads, and otherwise the use the proxy needs (or nothing, refused below as beyond them).
      places.set(`${path.project}/${path.environment}`, place?.environment == null || allows(holder, 'secret.read', at(place)));
      const named = { environmentId: place?.environment?.id, personal: raw.endsWith('@me') };
      if (named.environmentId != null && !madeFor.some((made) => made.environmentId === named.environmentId && made.personal === named.personal)) madeFor.push({ environmentId: named.environmentId, personal: named.personal });
      for (let depth = 0; place?.environment?.parentSlug != null && depth < MAX_PARENTS; depth += 1) {
        place = await resolvePath(this.#deps.db, { project: path.project, environment: place.environment.parentSlug });
        if (place?.environment == null) break;
        const reads = allows(holder, 'secret.read', at(place));
        if (reads || allows(holder, 'secret.use', at(place))) places.set(`${path.project}/${place.environment.slug}`, reads);
      }
    }
    return { reached: [...places].map(([path, reads]) => ({ path, reads })), madeFor };
  }

  /** What a personal token made now would reach, checked as making one is (`issuePersonalToken`); makes nothing. */
  async planPersonalToken(ctx: Asker, input: PersonalTokenInput): Promise<TokenPlan> {
    return withRefusals(this.#deps, async () => ({ scope: (await this.#personalScope(ctx, input)).byPath }));
  }

  /** Who may make a personal token, a person on a session of theirs, and what it would reach (`personalScope`). */
  async #personalScope(ctx: Asker, input: PersonalTokenInput) {
    if (!Number.isInteger(input.expiresInMinutes) || input.expiresInMinutes < 1 || input.expiresInMinutes > MAX_PERSONAL_TOKEN_MINUTES) {
      throw badRequest(`a personal token lasts between a minute and ${MAX_PERSONAL_TOKEN_MINUTES / 1440} days`);
    }
    const person = ctx.caller.principal;
    const details = { kind: 'personal', principalType: person.type, principalId: person.id, label: input.label };
    // A personal token, or a service's credential, carries a scope: what it made would outlive it.
    if (person.type !== 'user' || ctx.caller.credentialScope !== null) {
      throw new Refusal(
        forbidden('only a person makes a personal token, signed in as themselves: a token never makes another'),
        denied(ctx, 'token.create', 'personal_token', { metadata: details }),
      );
    }
    const access = await this.#standing(person);
    return { access, details, ...await personalScope(this.#deps.db, ctx, callerFrom(person, access, ctx.caller.policySeq), input.scope, details) };
  }

  /**
   * A credential for a CI run, which a trust binding vouched for
   * (`WorkloadService.exchange`): its row, which the exchange writes as it
   * spends the token (`exchangeToken`), under the log's head, its member
   * checked under it. It names its binding in `created_by`, under its MAC,
   * and dies with it.
   */
  exchangedCredential(
    service: string,
    options: { generation: number; bindingId: string; label: string | null; expiresAt: Date; scope?: CredentialScope },
  ): { row: typeof credentials.$inferInsert & { id: string; principal: string; kind: string; scope: string | null; revokedAt: null; expiresAt: Date }; issued: IssuedCredential } {
    const made = this.#credential('service', { type: 'service', id: service }, {
      generation: options.generation,
      identityId: null,
      label: options.label,
      createdBy: issuedBy(options.bindingId),
      expiresAt: options.expiresAt,
      ...(options.scope === undefined ? {} : { scope: options.scope }),
    });
    return made as typeof made & { row: { id: string; principal: string; kind: string; scope: string | null; revokedAt: null; expiresAt: Date } };
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
    // A personal token approving one would make a session with all its person holds.
    if (ctx.caller.principal.type !== 'user' || ctx.caller.credentialScope !== null) throw forbidden('only people approve sign-ins, signed in as themselves');
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
    const plan = { id: randomUUID(), expiresAt: new Date(Date.now() + this.#deps.signin.cliSessionDays * 86_400_000) };
    const changes = await AppChanges.prepare(this.#deps.vault, prepared.principal!, [this.#issueChange('cli', principal, plan)]);
    try {
      return await audited(this.#deps, async (tx, log): Promise<DevicePoll> => {
        const now = new Date();
        // Until the session is issued, no change is made: each way out before it leaves none.
        changes?.drop();
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

        changes?.keep();
        const credential = await this.#issue(tx, 'cli', principal, {
          ...plan,
          generation: standing.generation,
          identityId: null,
          label: row.clientLabel,
          createdBy: principalId,
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
            targetCredentialId: credential.id,
            deviceAuthorizationId: row.id,
            clientLabel: row.clientLabel,
            clientIp: row.clientIp,
          },
        };
        log.push(entry);
        return { status: 'approved', principal, credential };
      }, changes);
    } catch (error) {
      if (error instanceof SigninRefused) return { status: 'denied' };
      throw error;
    }
  }
}

const isOpen = (now: Date) => (row: { decidedAt: Date | null; expiresAt: Date }) =>
  row.decidedAt === null && row.expiresAt > now;

function refusalOrThrow(error: unknown): { ok: false; reason: SigninRefusal; providers?: string[] } {
  if (error instanceof SigninRefused) return refusal(error);
  throw error;
}

function refusal(error: SigninRefused): { ok: false; reason: SigninRefusal; providers?: string[] } {
  return error.providers === undefined ? { ok: false, reason: error.reason } : { ok: false, reason: error.reason, providers: error.providers };
}
