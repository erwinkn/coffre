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
  verifyAssertion,
  verifyRegistration,
  type PasskeyAlgorithm,
  type StoredPasskey,
} from '@coffre/core/identity';
import { allows, DEFAULT_POLICY, ownsInstance, DEVICE_TTL_SECONDS, HANDLE_POLICY, holds, MAX_PERSONAL_TOKEN_MINUTES, PERMISSIONS, ROLES, runsInstance, type CredentialScope, type Holdings, type Policy, type RoleDefinition } from '@coffre/core/access';
import type { Access, ObjectChange, Settings, Vault } from '@coffre/core/vault';
import type { Database, Transaction } from '@coffre/db';
import { isUniqueViolation } from '@coffre/db/dialect';
import { KeyRetired } from '@coffre/db/log';
import { credentials, deviceLogins, identities, mcpConnections } from '@coffre/db/schema';

import { authMac, AuthRowTampered, issuedBy, issuingBinding } from '../auth-rows.ts';
import { answerOf, shownActive, type Shows } from '../db/answers.ts';
import { appLogKey } from '../db/audit.ts';
import type { AuditEntry } from '../db/audit.ts';
import { MAX_BODY_NODES } from '../http.ts';
import { passkeyName, providerName } from '../passkey-names.ts';
import {
  findBinding,
  findCredential,
  findDeviceAuthorizations,
  openDeviceSources,
  findIdentity,
  passkeyCredentialTaken,
  signinMembers,
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
  type CredentialsWhere,
  priorConnections,
  revokePriorMembership,
  update,
  updateAuth,
  passkeyBehind,
  passkeyByCredentialId,
  passkeyHistory,
  livePasskeys,
  liveConnections,
  touchPasskey,
  insertPasskey,
  denyApprovals,
  passkeysOf,
  personCredentials,
  removePasskeyRow,
  renamePasskeyRow,
  unbackedCredentials,
  type CredentialRead,
  type PasskeyRead,
  type PasskeyRow,
} from '../db/queries.ts';
import { FRESH_MS } from './fresh-routes.ts';
import { CeremonyStates, challenge, creationOptions, requestOptions, responseCredentialId, userHandle, type Act, type ActState, type AddState, type CreateState, type RemoveState, type CreationOptionsJSON, type PendingFactor, type RequestOptionsJSON, type StepUpState } from './ceremony.ts';
import { passkeyChecked, PasskeyRequired, passkeyStands, sourceStands } from '../passkey-check.ts';
import { callerFrom, projectsReached, type Caller, type PrincipalRef } from './caller.ts';
import { reachedPlaces } from './render.ts';
import { AppChanges, COFFRE_ACTOR, connectionRevokes, deploymentOwners, credentialChange, ObjectMoved, retrying, revokedByVault, revokes, vaultIssuesTokens, vaultMakesCredentials, type CredentialsVault } from './changes.ts';
import { allowed, audited, credentialStill, denied, POLICY_CHANGED, Refusal, requireInstance, traceOf, withRefusals, type ApiContext, type SessionOf } from './context.ts';
import { accessFor, type Accesses, type Recalled } from '../accesses.ts';
import { ApiError, badRequest, forbidden, notFound, TouchRequired } from './errors.ts';
import { formatMember, parsePath } from './paths.ts';
import {
  ACCESS_CHANGED,
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
export type Asker = Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp' | 'credentialId' | 'passkeyId' | 'via' | 'render'> & Partial<Pick<ApiContext, 'provenance' | 'confirmed'>>;

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
  /** The matching person's record failed the vault's integrity check, or one of their passkeys' rows the app's (R64). */
  | 'tampered'
  /**
   * The person holds a live passkey, and the provider alone signed them in (docs/design/passkeys.md, section 6.1): a
   * session no passkey confirmed is never issued to them while the policy is not `off`.
   */
  | 'passkey_required'
  /** The passkey's answer did not hold: refused by the verifier, a passkey not the person's or not live, or replayed (section 7). */
  | 'passkey_failed'
  /** An enrollment's state, used after a passkey was added: only a first passkey is added at sign-in (section 3.2). */
  | 'passkey_exists'
  /** A passkey step for another person, membership or issuer than the sign-in it completes: start again. */
  | 'state_mismatch'
  /** A step-up for a session that ended, or that another touch replaced first (section 6.5). */
  | 'session_ended'
  /** Removing the person's last passkey under `required`: they add another first (section 3.6). */
  | 'last_passkey';

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
  /**
   * Signing in to add a passkey (`/auth/signin/:provider?passkey=add`): a member who holds none, under `optional`, is
   * asked to add one as they sign in, as an Owner is (passkeys.md, section 3.3). What a page asks for when an act the
   * person may do takes a passkey they do not have yet (`fresh_check_required`, `add_passkey`). Sealed by 0.16.0 and on.
   */
  addPasskey?: true;
};

const PENDING_TTL_SECONDS = 10 * 60;

export type IssuedCredential = { id: string; token: string; expiresAt: string };

/** What a credential is issued with, beyond its kind and principal. */
/** A credential's row, as its issuer writes it; `id` chosen before the transaction, so that 0.15's change of it is too (`#issueChange`). */
type CredentialOptions = {
  id?: string; generation: number; identityId: string | null; label: string | null; createdBy: string; expiresAt: Date; scope?: CredentialScope; places?: readonly HandlePlace[];
  /**
   * The passkey that stands behind it (docs/design/passkeys.md, section 5.2), which its MAC covers, null for none: the one
   * a session's touch confirmed, with `confirmedAt` when; or what the credential it is issued from names, copied with no
   * `confirmedAt`, so that a token or handle never passes a fresh check. Said by every issuer.
   */
  passkeyId: string | null;
  confirmedAt?: Date | null;
  /** Its scope as stored, verbatim, in place of `scope`: a binding's own, which the vault holds a sign-in's to (T149). */
  stored?: string | null;
};

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
  /**
   * `replaced`: the session the browser came in on, its person's, ended in the transaction that issued this one (a
   * touch, passkeys.md, section 6.5), which leaves the browser nothing to sign out.
   */
  | { ok: true; principal: PrincipalRef; credential: IssuedCredential; replaced?: true }
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
  /** Set when `access` is the app's own read of the vault's rows, for a request that only shows its caller (`answerShown`). */
  unchecked?: true;
  /** The instance's settings as the vault's rows say them, read with the credential for a request that shows them. */
  settings?: Settings;
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
  /** The passkey it names, which the check held live (`passkeyStands`); null for none. */
  passkeyId: string | null;
  /** A person's browser or terminal session, and when a touch confirmed it; null for any other credential. */
  session?: SessionOf | null;
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
/** A credential's last use, as `verify` records it once every five minutes: by the request, when it writes it itself. */
export type Touch = { credential: string; at: Date; ip: string | null };

const TOUCH_INTERVAL_MS = 5 * 60 * 1000;
export { MAX_SERVICE_TOKEN_DAYS } from '@coffre/core/access';

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
    this.#ceremonies = new CeremonyStates(deps.chainKey);
  }

  readonly #ceremonies: CeremonyStates;

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

  /**
   * The sign-in providers this deployment configures, each `<provider id>:<issuer hash>`, which a browser session's
   * identity must name for `#liveCredential` to take it: what a named use holds its credential to first, in the vault's
   * call (`NamedUseInput.accepts`; review r6 of D153).
   */
  get acceptedIssuers(): readonly string[] {
    return (this.#accepted ??= this.config.providers.map((provider) => `${provider.id}:${this.#issuerHash(provider.id)!}`));
  }

  #accepted: readonly string[] | undefined;

  #issuerHash(providerId: string): string | null {
    const provider = this.config.providers.find((candidate) => candidate.id === providerId);
    // Fixed width keeps the identity index exact on every database engine.
    return provider === undefined ? null : hashToken(provider.issuer).toString('hex');
  }

  // --- signing in ---------------------------------------------------------

  async completeSignin(profile: SignedInAccount, meta: ClientMeta): Promise<SigninResult> {
    return this.#signedIn(profile, meta, null);
  }

  async #signedIn(profile: SignedInAccount, meta: ClientMeta, factor: Factor | null, known?: Known): Promise<SigninResult> {
    try {
      return await this.#completeSignin(profile, meta, factor, known);
    } catch (error) {
      if (error instanceof SigninRefused) return refusal(error);
      if (!isUniqueViolation(error)) throw error;
      // A new passkey whose credential ID a passkey already has, anyone's: refused as a passkey that did not answer,
      // the unique index the one place that decides it, a race included (review r1 of #500).
      if (factor?.kind === 'enroll' && (await passkeyCredentialTaken(this.#deps.db, factor.row.credentialId))) {
        return passkeyRefused(meta, factor.state.principal, 'passkey_failed', 'its credential ID is a passkey\'s already');
      }
      // Someone else bound this account first: from the callback, decided again from what is there now.
      if (known !== undefined) throw new AccessMoved(error);
      return this.#completeSignin(profile, meta, factor).catch(refusalOrThrow);
    }
  }

  async #completeSignin(profile: SignedInAccount, meta: ClientMeta, factor: Factor | null, known?: Known): Promise<SigninResult> {
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
      // What the callback read and resolved, when it did, not read or asked again (review r1 of #500).
      const previous = known !== undefined ? known.previous : await findIdentity(this.#deps.db, this.#deps.chainKey, { ...profile, issuerHash });
      const match = previous !== null ? null
        : known === undefined ? await this.#principalForEmails(profile.emails)
          : known.person === null ? null
            : { ...known.person, access: await this.#standing({ type: 'user', id: known.person.id }) };
      if (previous === null && (match === null || match.access.status === 'unknown')) throw refuse('not_registered');
      const preparedId = previous === null ? match!.id : memberOf(previous.principal).id;
      const principal = { type: 'user' as const, id: preparedId };
      const standing = match?.access ?? await this.#standing(principal);
      if (standing.status === 'tampered') throw refuse('tampered', preparedId);
      if (standing.status !== 'active') throw refuse('deactivated', preparedId);
      // From the callback, the one thing it left to the vault's answer: an Owner of the whole instance adds a passkey
      // before any session (section 2). The transaction holds the answer to the access it was read at, below.
      if (known !== undefined && factor === null && ownsInstance(standing) && (previous === null || previous.generation === standing.generation)) {
        throw new StepWanted(standing);
      }
      // The passkey step was for this person, at this generation: an Owner the deployment names, admitted just now by
      // the vault's answer above, at the first one, 0, and never at a later membership (passkeys.md, section 3.1).
      if (factor !== null && (factor.state.principal !== principalOf(principal) || factor.state.generation !== standing.generation)) {
        return passkeyRefused(meta, factor.state.principal, 'state_mismatch', 'the passkey step was for another person or membership');
      }
      // What the session names: the passkey touched, or the one added (section 3.2).
      const passkeyId = factor === null ? null : factor.kind === 'touch' ? factor.passkey.id : factor.id;
      return retrying(async () => {
      // The session, and, binding a new account, the credentials of an earlier membership it revokes (`revokePriorMembership`);
      // a first passkey, everything of the person's no passkey stands behind (section 6.1).
      const plan = { id: randomUUID(), expiresAt: new Date(Date.now() + this.#deps.signin.browserSessionHours * 3_600_000), generation: standing.generation };
      const changes = await AppChanges.prepare(this.#deps.vault, formatMember(principal), async () => {
        const at = new Date();
        const prior = previous === null ? await liveCredentialsWhere(this.#deps.db, this.#deps.chainKey, priorCredentials(principal, standing.generation, at)) : [];
        const apps = previous === null ? await priorConnections(this.#deps.db, this.#deps.chainKey, principal, standing.generation, at) : [];
        const session = this.#replacing(factor, principal);
        const [unbacked, replaced] = await Promise.all([
          factor?.kind === 'enroll' ? this.#unbacked(this.#deps.db, principal, standing.generation, at) : { credentials: [], connections: [] },
          session === null ? [] : liveCredentialsWhere(this.#deps.db, this.#deps.chainKey, session),
        ]);
        const ending = new Map([...prior, ...unbacked.credentials, ...replaced].map((row) => [row.id, row]));
        return [this.#issueChange('browser', principal, plan), ...revokes([...ending.values()]), ...connectionRevokes([...apps, ...unbacked.connections])];
      });
      return audited(this.#deps, async (tx, log) => {
        // Under the head, which every change to the person's passkeys holds too: the provider alone signs in nobody who
        // holds a live passkey, while the policy is not `off`, and a touch only with a passkey still live (passkeys.md,
        // section 6.1); a first passkey only while it is still the first (section 3.2). What decides on the person
        // holding none reads every row of theirs, each held to its MAC (`passkeyHistory`): a removal forged in the
        // database refuses rather than read as none (R64). Asked together, one round trip.
        const none = () => passkeyHistory(tx, this.#deps.chainKey, principalOf(principal), standing.generation).catch((error: unknown) => {
          if (error instanceof AuthRowTampered) throw new SigninRefused('tampered');
          throw error;
        });
        const [member, backed] = await Promise.all([
          this.#stillMember(tx, principal, standing, known?.accessSeq),
          factor?.kind === 'enroll'
            ? none().then(({ ever, live }) => ever === factor.state.passkeysEver && live === 0)
            // `passkeyStands`' rule for a credential that names none, `optional` and none held, on rows checked.
            : factor === null && this.#deps.signin.passkeys.policy === 'optional'
              ? none().then(({ live }) => live === 0)
              : this.#issuedBacked(tx, { principal: principalOf(principal), generation: standing.generation, passkeyId }),
        ]);
        if (!member) throw refuse('deactivated', preparedId);
        // Whoever answered passed the provider but not the factor: no entry, as section 3.1 promises such a visitor
        // writes nothing, and the reason in the process log (section 11; review r1 of #497).
        if (!backed && factor?.kind === 'enroll') return passkeyRefused(meta, preparedId, 'passkey_exists', 'a passkey was added since this enrollment began');
        if (!backed && factor !== null) return passkeyRefused(meta, preparedId, 'passkey_failed', 'the passkey was removed meanwhile');
        if (!backed) {
          console.warn('a sign-in the provider alone answered was refused: its person holds a passkey', { principal: preparedId, reason: 'passkey_required', requestId: meta.requestId });
          throw new SigninRefused('passkey_required');
        }
        const now = new Date();
        // The touch taken: its replay mark and counter move, or nothing is issued (section 7.3). Not taken, this sign-in's
        // challenge is spent for that passkey (a commit whose answer was lost, or a newer sign-in's), or its counter
        // stood still: no touch of it answers this challenge again, so the sign-in ends, its cookie cleared, rather than
        // ask for another touch that cannot pass (review r5 of #500).
        if (factor?.kind === 'touch' && (await touchPasskey(tx, { id: factor.passkey.id, principal: principalOf(principal), generation: standing.generation, issuedAt: new Date(factor.state.issuedAt), signCount: factor.signCount })) === 0) {
          return passkeyRefused(meta, preparedId, 'state_mismatch', 'replayed, overtaken by a newer challenge, or a counter that did not move');
        }
        const bound = await findIdentity(tx, this.#deps.chainKey, { ...profile, issuerHash });
        let principalId: string;
        let identityId: string;
        let generation: number;
        const ended = { credentials: [] as string[], connections: [] as string[], approvals: [] as string[] };
        // The session the browser came in on, the person's, ends with this transaction, not after it, where a failure or
        // a crash would leave a copy of its cookie alive (section 6.5; review r3 of #500). Ended meanwhile, it is no refusal.
        const session = this.#replacing(factor, principal);
        const replaced = session === null ? [] : await revokeCredentialsWhere(tx, this.#deps.chainKey, session, { revokedAt: now, revokedBy: principal.id });
        ended.credentials.push(...replaced);
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
          const prior = await revokePriorMembership(tx, this.#deps.chainKey, principal, generation, 'system:signin');
          ended.credentials.push(...prior.credentials);
          ended.connections.push(...prior.connections);

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

        if (factor?.kind === 'enroll') {
          // The first passkey, then what no passkey stands behind, ended for good (section 6.1): under the person's
          // factor lock, which this transaction took first, so no issue of the vault's slips between the read and the end.
          await insertPasskey(tx, this.#deps.chainKey, { ...factor.row, principal: principalOf(principal), generation, createdBy: 'system:signin' });
          const unbacked = await this.#unbacked(tx, principal, generation, now);
          ended.credentials.push(...await revokeCredentialsWhere(tx, this.#deps.chainKey, credentialsBy.ids(unbacked.credentials.map(({ id }) => id)), { revokedAt: now, revokedBy: principalId }));
          for (const row of unbacked.connections) {
            if ((await updateAuth(tx, this.#deps.chainKey, mcpConnections, { id: row.id, authMac: row.authMac }, { revokedAt: now, revokedBy: principalId })) > 0) ended.connections.push(row.id);
          }
          ended.approvals.push(...await denyApprovals(tx, this.#deps.chainKey, principalOf(principal), now, { unbacked: true }));
          log.push({
            ...base,
            actorId: principalId,
            action: 'passkey.add',
            decision: 'allow',
            metadata: {
              passkeyId: factor.id, name: factor.row.name, aaguid: factor.row.aaguid === null ? null : Buffer.from(factor.row.aaguid).toString('hex'), synced: factor.row.synced,
              ended: { credentials: ended.credentials.length, connections: ended.connections.length, approvals: ended.approvals.length },
            },
          });
        }
        changes?.expectRevoked(ended.credentials);
        changes?.expectRevoked(ended.connections, 'connection');

        // At the plan's generation, which its change sealed: `generation` is the same, held to it above.
        const credential = await this.#issue(tx, 'browser', principal, {
          ...plan,
          identityId,
          label: meta.label,
          createdBy: principalId,
          // The passkey touched or added, now; the provider alone, none.
          passkeyId,
          confirmedAt: passkeyId === null ? null : now,
        });
        log.push({
          ...base,
          actorId: principalId,
          decision: 'allow',
          metadata: { ...account, identityId, targetCredentialId: credential.id, ...(passkeyId === null ? {} : { passkeyId }) },
        });
        return { ok: true as const, principal, credential, ...(replaced.length > 0 ? { replaced: true as const } : {}) };
      }, changes, factor?.kind === 'enroll' ? principalOf(principal) : null);
      });
    });
  }

  /**
   * What a first passkey ends (section 6.1): the person's live credentials and MCP connections of this membership that
   * name no passkey, each its MAC the app's. Read before the transaction for its prepared changes, and again in it.
   */
  async #unbacked(db: Database | Transaction, principal: PrincipalRef, generation: number, at: Date) {
    const [credentialRows, connections] = await Promise.all([
      liveCredentialsWhere(db, this.#deps.chainKey, unbackedCredentials(principal, generation, at)),
      liveConnections(db, this.#deps.chainKey, principalOf(principal), at),
    ]);
    return { credentials: credentialRows, connections: connections.filter((row) => row.generation === generation && row.passkeyId === null) };
  }

  /**
   * The session a touch replaces (section 6.5): the browser session whose cookie the browser answered with, if it is
   * this person's; null for none to look for. Another person's is no part of this sign-in's change, and the route signs
   * it out as today.
   */
  #replacing(factor: Factor | null, principal: PrincipalRef): CredentialsWhere | null {
    if (factor === null || factor.replaces === null || !isCoffreToken(factor.replaces)) return null;
    return credentialsBy.session(hashToken(factor.replaces), principalOf(principal));
  }

  // --- passkeys at sign-in (docs/design/passkeys.md, sections 3.1, 3.2 and 6.2) -----------------------------

  /** Sealed for the browser, or opened from it: a pending sign-in's passkey step, and a step-up's. */
  get ceremonies(): CeremonyStates {
    return this.#ceremonies;
  }

  /**
   * After the provider (section 3.1): today's sign-in when no passkey is wanted, or the passkey step a sign-in waits
   * for, to seal in the browser. The step writes nothing, the vault included: an Owner the deployment names is matched
   * against its `owners`, never asked about (which would admit them), and admitted at the post, once the passkey is added.
   *
   * A step is wanted, unless passkeys are `off`, from a person who holds a live passkey (`signin`); and from one who
   * holds none under `required`, or under `optional` an Owner of the whole instance or one the deployment names, who add
   * one before any session exists (`enroll`, sections 2 and 3.2).
   *
   * Its reads are one round trip, the identity and the members it may be with their passkeys (`signinMembers`), and
   * the vault's answer only where they leave the step undecided: a person with no passkey under `optional`, whose
   * role decides. That answer is the sign-in's own, which it completes with, and its transaction holds it to the
   * access it was read at; moved meanwhile, the step is decided again (review r1 of #500).
   */
  async afterProvider(profile: SignedInAccount, meta: ClientMeta, next: string, wants: { addPasskey?: boolean } = {}): Promise<SigninResult | { ok: 'passkey'; state: PendingFactor }> {
    const policy = this.config.passkeys.policy;
    const issuerHash = this.#issuerHash(profile.provider);
    if (policy === 'off' || issuerHash === null) return this.completeSignin(profile, meta);
    // Again, each time the person's access moved between the reads and the transaction: another change of theirs
    // committed meanwhile, so it ends when those do, with no count of its own (R70). A bind lost to another
    // sign-in is decided again once: the identities' unique index is on the subject, so the next read finds
    // the winner, and a violation that read does not resolve is no race, so it is thrown, as `#signedIn`'s own
    // retry throws its second (Fable review of #500).
    let rebound = false;
    for (;;) {
      try {
        return await this.#afterProvider(profile, meta, next, policy, issuerHash, wants.addPasskey === true);
      } catch (error) {
        if (!(error instanceof AccessMoved)) throw error;
        if (error.violation !== undefined) {
          if (rebound) throw error.violation;
          rebound = true;
        }
      }
    }
  }

  async #afterProvider(profile: SignedInAccount, meta: ClientMeta, next: string, policy: 'optional' | 'required', issuerHash: string, addPasskey: boolean): Promise<SigninResult | { ok: 'passkey'; state: PendingFactor }> {
    const account = { ...profile, issuerHash };
    const [owners, previous, members] = await Promise.all([
      deploymentOwners(this.#deps.vault).then((named) => new Set(named)),
      findIdentity(this.#deps.db, this.#deps.chainKey, account),
      signinMembers(this.#deps.db, account, profile.emails),
    ]);
    // The person: the live identity's, or the first verified email that the deployment names an Owner or the vault
    // holds a row of, in the order `#principalForEmails` asks the vault about them. Nobody: today's sign-in says why.
    const id = previous !== null ? memberOf(previous.principal).id : profile.emails.find((email) => owners.has(email) || members.has(`user:${email}`)) ?? null;
    if (id === null) return this.#signedIn(profile, meta, null, { previous, person: null, accessSeq: null });
    const principal = principalOf({ type: 'user', id });
    const row = members.get(principal);
    const active = row?.status === 'active' && (previous === null || previous.generation === row.generation) ? row : null;
    const step = (purpose: 'signin' | 'enroll', generation: number) => ({
      ok: 'passkey' as const,
      state: {
        purpose,
        account: { provider: profile.provider, issuerHash, subject: profile.subject, email: previous === null ? id : (profile.emails[0] ?? null), name: profile.name ?? null },
        principal,
        generation,
        next,
        ...challenge(),
        // Removed ones included, every generation's (`passkeyHistory`): the post adds the first only while it is still this.
        passkeysEver: purpose === 'enroll' ? (row?.ever ?? 0) : null,
      },
    });
    if (active !== null && active.live > 0) return step('signin', active.generation);
    // An Owner the deployment names, admitted or not: at their row's generation, whatever its status, and with no row,
    // at a first admission's, 0 (review r3 of #500).
    if (owners.has(id)) return step('enroll', row?.generation ?? 0);
    // Under `required`, a member who holds none adds one; under `optional`, one who asked to (`PendingState.addPasskey`).
    if (active !== null && (policy === 'required' || addPasskey)) return step('enroll', active.generation);
    try {
      return await this.#signedIn(profile, meta, null, { previous, person: previous === null ? { id, email: id } : null, accessSeq: row?.accessSeq ?? null });
    } catch (error) {
      if (error instanceof StepWanted) return step('enroll', error.access.generation);
      throw error;
    }
  }

  /**
   * What the passkey page asks the browser for (section 3.1, step 3): a touch of one of the person's live passkeys, or a
   * new one. Null when the step can no longer complete: the passkeys it would offer were removed meanwhile. A new one
   * comes with a user handle drawn for this GET alone, sealed in `state`, which the post sends back (`CreateState`): two
   * GETs, from two tabs or a reload, never hand `create()` the same one.
   */
  async passkeyStep(state: PendingFactor): Promise<PasskeyStep | null> {
    const email = memberOf(state.principal).id;
    const passkeys = await livePasskeys(this.#deps.db, this.#deps.chainKey, state.principal, state.generation);
    if (state.purpose === 'signin') {
      return passkeys.length === 0 ? null : { purpose: 'signin', email, options: requestOptions(this.config.passkeys, state, passkeys) };
    }
    const person = { email, name: state.account.name, site: this.config.page.title };
    const create: CreateState = { purpose: 'create', challenge: state.challenge, userHandle: userHandle(), issuedAt: state.issuedAt };
    // An Owner's reset of theirs, which the page says (section 3.7); rows that fail their MAC say nothing here, and the post refuses.
    const rows = await passkeysOf(this.#deps.db, this.#deps.chainKey, state.principal).catch((error: unknown) => {
      if (error instanceof AuthRowTampered) return [];
      throw error;
    });
    const reset = lastReset(state.principal, rows.filter((row) => row.generation === state.generation));
    return { purpose: 'enroll', email, options: creationOptions(this.config.passkeys, create, person, passkeys), state: this.#ceremonies.seal(create), reset };
  }

  /**
   * The passkey's answer to a pending sign-in (section 3.1, step 4): checked, then today's sign-in from what the
   * provider vouched for, which reads again and checks again everything it decides on, with the touch's replay mark
   * moved, or the passkey added, in its transaction. A refusal writes no entry: whoever answered passed the provider
   * but not the factor. It goes to the process log. A new passkey comes with `created`, the sealed `CreateState` its
   * options came with, whose user handle the row stores.
   */
  async finishPasskey(state: PendingFactor, response: unknown, meta: ClientMeta, replaces: string | null = null, created: string | null = null): Promise<SigninResult> {
    try {
      return await this.#finishPasskey(state, response, meta, replaces, created);
    } catch (error) {
      return refusalOrThrow(error);
    }
  }

  async #finishPasskey(state: PendingFactor, response: unknown, meta: ClientMeta, replaces: string | null, created: string | null): Promise<SigninResult> {
    // The issuer that verified the account, sealed at the callback, is still the one this provider ID names.
    if (this.#issuerHash(state.account.provider) !== state.account.issuerHash) {
      return passkeyRefused(meta, state.principal, 'state_mismatch', "the provider's issuer changed since the callback");
    }
    const profile: SignedInAccount = { provider: state.account.provider, subject: state.account.subject, emails: state.account.email === null ? [] : [state.account.email], name: state.account.name };
    // What the response's strings decode to (its CBOR, its client data) held to the bound its request's JSON is
    // (`MAX_BODY_NODES`), counted again on them: the work stays within twice the cap.
    const expected = { challenge: Buffer.from(state.challenge, 'base64url'), origin: this.config.passkeys.origin, rpId: this.config.passkeys.rpId, values: MAX_BODY_NODES };
    if (state.purpose === 'enroll') {
      const verified = await verifyRegistration(response, expected);
      if (!verified.ok) return passkeyRefused(meta, state.principal, 'passkey_failed', verified.reason);
      // The handle `create()` was given, for this enrollment's challenge: a response that verified answered it, so
      // another enrollment's state, or none, is no page of coffre's.
      const create = this.#ceremonies.open(created, ['create']);
      if (create === null || create.challenge !== state.challenge) return passkeyRefused(meta, state.principal, 'state_mismatch', "no user handle of this enrollment's");
      const row = {
        id: randomUUID(),
        userHandle: Buffer.from(create.userHandle, 'base64url'),
        credentialId: Buffer.from(verified.credentialId),
        publicKey: Buffer.from(verified.publicKey),
        algorithm: verified.algorithm,
        signCount: verified.signCount,
        // Its own challenge is spent: nothing issued before it is answered with it.
        lastChallengeAt: new Date(state.issuedAt),
        transports: JSON.stringify(verified.transports),
        aaguid: verified.aaguid === null ? null : Buffer.from(verified.aaguid),
        synced: verified.backupEligible,
        name: passkeyName(verified.aaguid, state.passkeysEver!),
      };
      return this.#signedIn(profile, meta, { kind: 'enroll', state, id: row.id, row, replaces });
    }
    const passkey = await this.#passkeyAnswering(response, state);
    if (passkey === null) return passkeyRefused(meta, state.principal, 'passkey_failed', 'unknown_credential');
    const verified = await verifyAssertion(response, { ...expected, passkey: storedOf(passkey) });
    if (!verified.ok) return passkeyRefused(meta, state.principal, 'passkey_failed', verified.reason);
    return this.#signedIn(profile, meta, { kind: 'touch', state, passkey, signCount: verified.signCount, replaces });
  }

  /**
   * The passkey a response names, if it is a live one of the person's at the state's generation: another member's, or
   * one removed since the options were sent, is unknown here (section 7.2, step 3). A row that fails its MAC is too.
   */
  async #passkeyAnswering(response: unknown, state: { principal: string; generation: number }): Promise<PasskeyRow | null> {
    const credentialId = responseCredentialId(response);
    if (credentialId === null) return null;
    const row = await passkeyByCredentialId(this.#deps.db, this.#deps.chainKey, credentialId).catch((error: unknown) => {
      if (error instanceof AuthRowTampered) return null;
      throw error;
    });
    return row !== null && row.removedAt === null && row.principal === state.principal && row.generation === state.generation ? row : null;
  }

  /**
   * A step-up (section 6.2): the browser session this token is, live but for its passkey, and a touch of one of its
   * person's live passkeys to replace it with, sealed and bound to it. Null when there is no such session, or its
   * person holds no passkey to touch: signing in again is the way, which asks for one under `required`.
   */
  async stepUpStep(token: string, next: string): Promise<(PasskeyStep & { state: string }) | null> {
    const row = await this.#stepUpSession(token);
    if (row === null) return null;
    const passkeys = await livePasskeys(this.#deps.db, this.#deps.chainKey, row.principal, row.generation);
    if (passkeys.length === 0) return null;
    const state: StepUpState = { purpose: 'step-up', credentialId: row.id, principal: row.principal, generation: row.generation, next, ...challenge() };
    return { purpose: 'step-up', email: memberOf(row.principal).id, options: requestOptions(this.config.passkeys, state, passkeys), state: this.#ceremonies.seal(state) };
  }

  /** A browser session by its token: live, its person still a member at its generation, whatever its passkey. */
  async #stepUpSession(token: string) {
    const row = await findCredential(this.#deps.db, this.#deps.chainKey, { tokenHash: hashToken(token) }).catch((error: unknown) => {
      if (error instanceof AuthRowTampered) return null;
      throw error;
    });
    if (row === null || row.kind !== 'browser') return null;
    const access = await this.#standing(memberOf(row.principal));
    return this.#liveCredential(row, access, new Date()) ? row : null;
  }

  /**
   * The touch of a step-up (section 6.5): a new session, confirmed now by the passkey touched, replacing the one the
   * browser came in on, once; it keeps that one's sign-in, its account and its end. Of two touches on one session, one
   * replaces it, and the other ends here. `passkey.check` entries, allowed or denied: they come from a session.
   */
  async stepUp(sealed: string, token: string, response: unknown, meta: ClientMeta): Promise<SigninResult> {
    const state = this.#ceremonies.open(sealed, ['step-up']);
    const session = state === null ? null : await this.#stepUpSession(token);
    if (state === null || session === null || session.id !== state.credentialId) return refusal(new SigninRefused('session_ended'));
    const principal = memberOf(state.principal) as PrincipalRef & { type: 'user' };
    const check = (decision: 'allow' | 'deny', metadata: Record<string, unknown>): AuditEntry => ({
      actorType: 'user', actorId: principal.id, action: 'passkey.check', decision, requestId: meta.requestId, sourceIp: meta.sourceIp,
      metadata: { purpose: 'step-up', ended: session.id, ...metadata },
    });
    const deny = (reason: string, passkeyId: string | null = null) => new Refusal(new SigninRefused('passkey_failed'), check('deny', { reason, passkeyId }));
    try {
      return await withRefusals(this.#deps, async () => {
        const passkey = await this.#passkeyAnswering(response, state);
        if (passkey === null) throw deny('unknown_credential');
        const expected = { challenge: Buffer.from(state.challenge, 'base64url'), origin: this.config.passkeys.origin, rpId: this.config.passkeys.rpId, values: MAX_BODY_NODES, passkey: storedOf(passkey) };
        const verified = await verifyAssertion(response, expected);
        if (!verified.ok) throw deny(verified.reason, passkey.id);
        const standing = await this.#standing(principal);
        return retrying(async () => {
          const plan = { id: randomUUID(), expiresAt: session.expiresAt, generation: standing.generation };
          const changes = await AppChanges.prepare(this.#deps.vault, formatMember(principal), async () => [
            this.#issueChange('browser', principal, plan),
            ...revokes(await liveCredentialsWhere(this.#deps.db, this.#deps.chainKey, credentialsBy.id(session.id))),
          ]);
          return audited(this.#deps, async (tx, log) => {
            const [member, backed] = await Promise.all([
              this.#stillMember(tx, principal, standing),
              this.#issuedBacked(tx, { principal: state.principal, generation: standing.generation, passkeyId: passkey.id }),
            ]);
            if (!member || standing.generation !== state.generation) throw new Refusal(new SigninRefused('deactivated'), check('deny', { reason: 'session_ended', passkeyId: passkey.id }));
            if (!backed) throw deny('unknown_credential', passkey.id);
            const now = new Date();
            // The session it replaces ends first, once (section 6.5).
            const ended = await revokeCredentialsWhere(tx, this.#deps.chainKey, credentialsBy.id(session.id), { revokedAt: now, revokedBy: principal.id });
            if (ended.length !== 1) throw new Refusal(new SigninRefused('session_ended'), check('deny', { reason: 'session_ended', passkeyId: passkey.id }));
            changes?.expectRevoked(ended);
            // A replay mark this challenge cannot move (a newer one signed in elsewhere since, or this one answered):
            // no touch on it will ever count, so the step ends, its rollback keeping the session (review r12 of #500).
            if ((await touchPasskey(tx, { id: passkey.id, principal: state.principal, generation: standing.generation, issuedAt: new Date(state.issuedAt), signCount: verified.signCount })) === 0) {
              throw new Refusal(new SigninRefused('state_mismatch'), check('deny', { reason: 'replay', passkeyId: passkey.id }));
            }
            const credential = await this.#issue(tx, 'browser', principal, {
              ...plan, identityId: session.identityId, label: session.label, createdBy: principal.id, passkeyId: passkey.id, confirmedAt: now,
            });
            log.push(check('allow', { passkeyId: passkey.id, issued: credential.id }));
            return { ok: true as const, principal, credential, replaced: true as const };
          }, changes);
        });
      });
    } catch (error) {
      return refusalOrThrow(error);
    }
  }

  // --- a touch for one act --------------------------------------------------

  /**
   * The touch an act takes of its own (section 4.2): approving a terminal's code, an MCP client's change, or connecting
   * an MCP client. One touch approves one act, so a session confirmed a minute ago approves none of them alone. Asked
   * before the act's transaction; the act's transaction then moves its replay mark (`touched`).
   *
   * Null when the act takes none: passkeys `off`, or a caller no passkey stands behind, a person who holds none under
   * `optional` (the per-request check turns away anyone else's such credential). Without a touch, or with a state that
   * does not open as this act's, on this session (one that expired, say), the act is refused `403 touch_required`,
   * which carries a touch of the person's live passkeys, sealed and bound to both: a prompt, which writes no entry. With
   * one that does not check, `403 touch_failed`, a `passkey.check` entry.
   */
  async touchFor(ctx: Toucher, act: Act, answer: TouchAnswer | undefined): Promise<ActTouch | null> {
    if (this.config.passkeys.policy === 'off' || ctx.passkeyId === null) return null;
    if (ctx.caller.principal.type !== 'user' || ctx.credentialId === null) throw forbidden('only people approve this, signed in as themselves');
    const principal = principalOf(ctx.caller.principal);
    const state = answer === undefined ? null : this.#ceremonies.open(answer.state, ['act']);
    if (state === null || state.credentialId !== ctx.credentialId || state.principal !== principal || state.generation !== ctx.caller.generation || !sameAct(state.act, act)) {
      const asked: ActState = { purpose: 'act', act, credentialId: ctx.credentialId, principal, generation: ctx.caller.generation, ...challenge() };
      const passkeys = await livePasskeys(this.#deps.db, this.#deps.chainKey, principal, ctx.caller.generation);
      throw new TouchRequired(TOUCH_ASKED[act.kind], { options: requestOptions(this.config.passkeys, asked, passkeys), state: this.#ceremonies.seal(asked) });
    }
    return withRefusals(this.#deps, async () => {
      const passkey = await this.#passkeyAnswering(answer!.response, state);
      if (passkey === null) throw touchFailed(ctx, act, 'unknown_credential', null);
      const expected = { challenge: Buffer.from(state.challenge, 'base64url'), origin: this.config.passkeys.origin, rpId: this.config.passkeys.rpId, values: MAX_BODY_NODES, passkey: storedOf(passkey) };
      const verified = await verifyAssertion(answer!.response, expected);
      if (!verified.ok) throw touchFailed(ctx, act, verified.reason, passkey.id);
      return { state, passkeyId: passkey.id, signCount: verified.signCount };
    });
  }

  /**
   * In the act's transaction, under the log's head: the touch's replay mark moved past its challenge, once, on a passkey
   * still live and the person's at that generation, and its `passkey.check` entry. A touch counted already (the same
   * answer sent twice), or a passkey removed since, refuses the act, `403 touch_failed`.
   */
  async touched(tx: Transaction, log: AuditEntry[], ctx: Toucher, touch: ActTouch): Promise<void> {
    const { state, passkeyId, signCount } = touch;
    const moved = await touchPasskey(tx, { id: passkeyId, principal: state.principal, generation: state.generation, issuedAt: new Date(state.issuedAt), signCount });
    if (moved === 0) throw touchFailed(ctx, state.act, 'replay', passkeyId);
    log.push(allowed(ctx, 'passkey.check', { metadata: { purpose: state.act.kind, passkeyId } }));
  }

  // --- managing passkeys (docs/design/passkeys.md, sections 3.6 and 3.7) ---------------------------------------

  /**
   * A person's live passkeys, as their Passkeys tab lists them, with what removing one ends and the newest reset of
   * theirs (section 3.7): their own, or, for an Owner of the whole instance, anyone's, whose reset they weigh. Rows that
   * fail their MAC refuse the read (`tampered`) rather than list as fewer (R64).
   */
  async listPasskeys(ctx: Asker, member: PrincipalRef): Promise<PasskeyList> {
    const self = ownPasskeys(ctx, member);
    // A read: a refusal is no attempt at a reset, and the log records none (review: Fable, #529).
    if (!self && !instanceOwner(ctx)) throw forbidden("only an Owner of the whole instance sees someone's passkeys");
    if (!self && member.type !== 'user') throw notFound('only people hold passkeys');
    const standing = self ? null : await this.#standing(member);
    if (standing !== null && standing.status !== 'active') throw notFound('no such member');
    const generation = standing?.generation ?? ctx.caller.generation;
    const principal = principalOf(member);
    const now = new Date();
    const [rows, [held], apps] = await Promise.all([
      passkeysOf(this.#deps.db, this.#deps.chainKey, principal).catch((error: unknown) => {
        throw error instanceof AuthRowTampered ? tamperedPasskeys() : error;
      }),
      members(this.#deps.db, this.#deps.chainKey, { member, standing: false }, now),
      liveConnections(this.#deps.db, this.#deps.chainKey, principal, now),
    ]);
    const mine = rows.filter((row) => row.generation === generation);
    const live = mine.filter((row) => row.removedAt === null);
    // What a removal or a reset ends: everything of theirs, but the session asking, which a removal replaces.
    const others = (held?.credentials ?? []).filter((row) => row.id !== (self ? ctx.credentialId : null));
    const count = (...kinds: string[]) => others.filter((row) => kinds.includes(row.kind)).length;
    return {
      passkeys: live.map(passkeyView),
      ends: { sessions: count('browser', 'cli'), tokens: count('personal'), handles: count('handle'), apps: apps.filter((row) => row.refreshHash !== null).length },
      reset: lastReset(principal, mine),
      max: MAX_PASSKEYS,
    };
  }

  /**
   * The options of a `create()` for another passkey of the person's, from their browser session (section 3.6), which
   * the router held to a touch in the last five minutes: bound to that session, with a user handle drawn for this
   * `create()` alone, and the person's live passkeys excluded. A first passkey is added at sign-in instead
   * (`?passkey=add`), which the router's `add_passkey` asks of a person who holds none.
   */
  async addStep(ctx: Asker & Pick<ApiContext, 'session'>, member: PrincipalRef): Promise<{ options: CreationOptionsJSON; state: string }> {
    this.#adding(ctx, member);
    const principal = principalOf(member);
    const rows = await passkeysOf(this.#deps.db, this.#deps.chainKey, principal).catch((error: unknown) => {
      throw error instanceof AuthRowTampered ? tamperedPasskeys() : error;
    });
    const live = rows.filter((row) => row.generation === ctx.caller.generation && row.removedAt === null);
    addable(live.length);
    const state: AddState = { purpose: 'add', credentialId: ctx.credentialId!, principal, generation: ctx.caller.generation, userHandle: userHandle(), passkeysEver: rows.length, ...challenge() };
    const person = { email: member.id, name: null, site: this.config.page.title };
    const options = creationOptions(this.config.passkeys, state, person, live);
    // No longer than the session stays fresh, which its answer's POST is held to too: a `create()` answered after would
    // reach a step-up, which replaces the session these options name, and leave on the device a passkey coffre never
    // stored. When it lapses, the page asks for new options, after the step-up (review r1 of #539).
    const confirmedAt = ctx.session?.confirmedAt;
    if (confirmedAt != null) options.timeout = Math.min(options.timeout, Math.max(0, confirmedAt.getTime() + FRESH_MS - state.issuedAt));
    return { options, state: this.#ceremonies.seal(state) };
  }

  /**
   * Another passkey added (section 3.6): the answer to `addStep`'s `create()`, checked, then, under the person's factor
   * lock and the log's head, the session it was asked on still live and still backed, the person's passkeys as they
   * were when it was asked (none added or removed since), and room for one more. It ends nothing: every credential of
   * theirs names a passkey already, or none while they held none, which this does not reach (section 6.1).
   */
  async addPasskey(ctx: Asker & Pick<ApiContext, 'session'>, member: PrincipalRef, answer: TouchAnswer): Promise<{ passkey: PasskeyView }> {
    this.#adding(ctx, member);
    const principal = principalOf(member);
    const state = this.#ceremonies.open(answer.state, ['add']);
    if (state === null || state.credentialId !== ctx.credentialId || state.principal !== principal || state.generation !== ctx.caller.generation) {
      throw new ApiError('conflict', 'this passkey was asked for on another session, or too long ago: add it again', 'state_mismatch');
    }
    const fail = (reason: string) => new Refusal(new ApiError('touch_failed', 'that passkey could not be added: try again'), denied(ctx, 'passkey.add', reason));
    try {
      return await withRefusals(this.#deps, async () => {
        const expected = { challenge: Buffer.from(state.challenge, 'base64url'), origin: this.config.passkeys.origin, rpId: this.config.passkeys.rpId, values: MAX_BODY_NODES };
        const verified = await verifyRegistration(answer.response, expected);
        if (!verified.ok) throw fail(verified.reason);
        const standing = await this.#standing(member);
        return audited({ ...this.#deps, caller: ctx.caller }, async (tx, log) => {
          const [caller, rows] = await Promise.all([this.#currentCaller(tx, ctx, standing), passkeysOf(tx, this.#deps.chainKey, principal)]);
          if (caller === null) throw fail('session_ended');
          // This answer added already, its reply lost: said so before the count, which that add moved, would call it a
          // change and have the page make another (review r1 of #539).
          const credentialId = Buffer.from(verified.credentialId);
          if (rows.some((row) => row.generation === state.generation && row.removedAt === null && row.credentialId.equals(credentialId))) {
            throw new ApiError('conflict', 'that passkey is added already', 'passkey_exists');
          }
          if (rows.length !== state.passkeysEver) throw new ApiError('conflict', 'your passkeys changed meanwhile: add it again', 'state_mismatch');
          addable(rows.filter((row) => row.generation === state.generation && row.removedAt === null).length);
          const row = {
            id: randomUUID(),
            principal,
            generation: state.generation,
            userHandle: Buffer.from(state.userHandle, 'base64url'),
            credentialId,
            publicKey: Buffer.from(verified.publicKey),
            algorithm: verified.algorithm,
            signCount: verified.signCount,
            // Its own challenge is spent: nothing issued before it is answered with it.
            lastChallengeAt: new Date(state.issuedAt),
            transports: JSON.stringify(verified.transports),
            aaguid: verified.aaguid === null ? null : Buffer.from(verified.aaguid),
            synced: verified.backupEligible,
            name: passkeyName(verified.aaguid, state.passkeysEver),
            createdBy: member.id,
          };
          await insertPasskey(tx, this.#deps.chainKey, row);
          log.push(allowed(ctx, 'passkey.add', { metadata: { passkeyId: row.id, name: row.name, aaguid: row.aaguid === null ? null : row.aaguid.toString('hex'), synced: row.synced } }));
          return { passkey: passkeyView({ ...row, createdAt: new Date(), lastUsedAt: null }) };
        }, null, principal);
      });
    } catch (error) {
      if (error instanceof AuthRowTampered) throw tamperedPasskeys();
      // A credential ID a passkey has already, anyone's: the unique index decides it, a race included.
      if (isUniqueViolation(error)) throw new ApiError('conflict', 'that passkey is added already', 'passkey_exists');
      throw error;
    }
  }

  /** A passkey of the person's renamed (section 3.6): no check, since a name grants nothing and sits outside every MAC. */
  async renamePasskey(ctx: Asker, member: PrincipalRef, id: string, name: string): Promise<{ passkey: { id: string; name: string } }> {
    if (!ownPasskeys(ctx, member)) throw forbidden('a person renames their own passkeys');
    return audited({ ...this.#deps, caller: ctx.caller }, async (tx, log) => {
      if ((await renamePasskeyRow(tx, { id, principal: principalOf(member), generation: ctx.caller.generation }, name)) === 0) throw notFound('no such passkey');
      log.push(allowed(ctx, 'passkey.rename', { metadata: { passkeyId: id, name } }));
      return { passkey: { id, name } };
    });
  }

  /**
   * An Owner's reset of someone's passkeys (section 3.7): every live one removed, and everything the person is signed in
   * with ended, sessions, terminals, personal tokens, handles, connected apps and approved terminal codes not yet
   * redeemed, under their factor lock and the log's head (section 6.1; formal/Factor.tla's `reset`). Only an Owner of
   * the whole instance, signed in as themselves, resets anyone's, and never their own, which they remove with a touch;
   * the router held them to a touch in the last five minutes. Their next sign-in asks for a new one under `required`,
   * and the provider alone signs them in under `optional`.
   */
  async resetPasskeys(ctx: Asker, member: PrincipalRef): Promise<PasskeyReset> {
    const principal = principalOf(member);
    try {
      return await withRefusals(this.#deps, async () => {
        // The Owner as the vault answers now, held to under the head: demoted meanwhile, they reset no one (`issuerStill`;
        // review r1 of #529), as an issuer demoted meanwhile gives a token nothing.
        const { caller, accessSeq } = await issuerNow(this.#deps, ctx.caller.principal, { ctx, action: 'passkey.reset' });
        const asker = { ...ctx, caller };
        mayReset(asker, member);
        if (caller.principal.id === member.id) {
          throw new Refusal(forbidden('your own passkeys are removed from Account → Passkeys, with a touch of one you keep'), denied(ctx, 'passkey.reset', 'own_passkeys', { metadata: { principalType: 'user', principalId: member.id } }));
        }
        const standing = await this.#standing(member);
        if (standing.status !== 'active') throw notFound('no such member');
        const credentialEnded = () => new Refusal(new ApiError('unauthenticated', 'that credential is unknown, expired or revoked'), denied(ctx, 'passkey.reset', 'credential_ended', { metadata: { principalType: 'user', principalId: member.id } }));
        return await retrying(async () => {
          const changes = await AppChanges.prepare(this.#deps.vault, formatMember(caller.principal), async () => {
            const at = new Date();
            const [held, connected] = await Promise.all([
              liveCredentialsWhere(this.#deps.db, this.#deps.chainKey, personCredentials(member, at)),
              liveConnections(this.#deps.db, this.#deps.chainKey, principal, at),
            ]);
            return [...revokes(held), ...connectionRevokes(connected)];
          });
          return audited({ ...this.#deps, caller }, async (tx, log) => {
            // Read together, one round trip: the Owner's access as it was weighed, the session they asked on still live and
            // still backed by the passkey it names, the person still the member they were, and their passkeys.
            const [, , stands, still, rows] = await Promise.all([
              issuerStill(tx, caller, accessSeq),
              credentialStill(asker, tx, 'passkey.reset'),
              sourceStands(tx, this.#deps.chainKey, this.#deps.signin.passkeys.policy, asker),
              this.#stillMember(tx, member, standing),
              passkeysOf(tx, this.#deps.chainKey, principal),
            ]);
            if (!stands) throw credentialEnded();
            if (!still) throw notFound('no such member');
            const live = rows.filter((row) => row.generation === standing.generation && row.removedAt === null);
            if (live.length === 0) throw new ApiError('conflict', `${member.id} has no passkey to reset`, 'no_passkeys');
            const now = new Date();
            const by = { removedAt: now, removedBy: caller.principal.id };
            // Every write at once, under the person's factor lock, which no issue or sign-in of theirs passes meanwhile:
            // the removals' compare-and-sets and the revocations, each checked after (review r1 of #529).
            const [moved, ended] = await Promise.all([
              Promise.all(live.map((row) => removePasskeyRow(tx, this.#deps.chainKey, row, by))),
              this.#endEverything(tx, member, now, caller.principal.id, changes),
            ]);
            if (moved.some((count) => count === 0)) throw new ObjectMoved();
            log.push(allowed(asker, 'passkey.reset', {
              metadata: { principalType: 'user', principalId: member.id, passkeys: live.map((row) => row.id), ended: countsOf(ended) },
            }));
            return { reset: live.length, ended: countsOf(ended) };
          }, changes, principal);
        });
      });
    } catch (error) {
      if (error instanceof AuthRowTampered) throw tamperedPasskeys();
      throw error;
    }
  }

  /**
   * What removing one of their passkeys asks the person's browser for (section 3.6): a touch of another live passkey of
   * theirs, which the new session will name; under `optional`, a touch of the last one, which leaves them none; under
   * `off`, none. Bound to the browser session it was asked on, which the removal replaces. Null when there is no such
   * session or passkey; `last_passkey` under `required` for their last one, which they add another before removing.
   */
  async removeStep(token: string, passkeyId: string): Promise<{ purpose: 'remove'; email: string; name: string; options: RequestOptionsJSON | null; state: string } | { refused: 'last_passkey' | 'tampered' } | null> {
    const session = await this.#stepUpSession(token);
    if (session === null) return null;
    const rows = await passkeysOf(this.#deps.db, this.#deps.chainKey, session.principal).catch((error: unknown) => {
      if (error instanceof AuthRowTampered) return null;
      throw error;
    });
    if (rows === null) return { refused: 'tampered' };
    const live = rows.filter((row) => row.generation === session.generation && row.removedAt === null);
    const target = live.find((row) => row.id === passkeyId);
    if (target === undefined) return null;
    const kept = live.filter((row) => row.id !== passkeyId);
    const policy = this.config.passkeys.policy;
    if (policy === 'required' && kept.length === 0) return { refused: 'last_passkey' };
    const touch: RemoveState['touch'] = policy === 'off' ? 'none' : kept.length > 0 ? 'kept' : 'last';
    const state: RemoveState = { purpose: 'remove', credentialId: session.id, principal: session.principal, generation: session.generation, passkeyId, touch, ...challenge() };
    const options = touch === 'none' ? null : requestOptions(this.config.passkeys, state, touch === 'kept' ? kept : [target]);
    return { purpose: 'remove', email: memberOf(session.principal).id, name: target.name, options, state: this.#ceremonies.seal(state) };
  }

  /**
   * A passkey removed by its person (section 3.6), from the browser session `removeStep` bound it to: the touch it
   * asked for checked, then, under the person's factor lock and the log's head, the passkey removed, everything the
   * person is signed in with ended, the session it came in on included, and a new session issued to this browser
   * (rule 1): confirmed now by the passkey touched, or, removing the last one under `optional`, or under `off`, naming
   * none. Signed out everywhere else: "everywhere else" is a rule a person can predict, since any of their sessions may
   * have been confirmed by any of their passkeys (section 6.1). `passkey.remove` entries, and `passkey.check` denials.
   */
  async removePasskey(sealed: string, token: string, response: unknown, meta: ClientMeta): Promise<SigninResult> {
    const state = this.#ceremonies.open(sealed, ['remove']);
    const session = state === null ? null : await this.#stepUpSession(token);
    if (state === null || session === null || session.id !== state.credentialId) return refusal(new SigninRefused('session_ended'));
    // The policy it was asked under, still: a redeploy between the two asks again.
    if ((this.config.passkeys.policy === 'off') !== (state.touch === 'none')) return refusal(new SigninRefused('state_mismatch'));
    const principal = memberOf(state.principal) as PrincipalRef & { type: 'user' };
    const entry = (action: string, decision: 'allow' | 'deny', metadata: Record<string, unknown>): AuditEntry => ({
      actorType: 'user', actorId: principal.id, action, decision, requestId: meta.requestId, sourceIp: meta.sourceIp, metadata: { passkeyId: state.passkeyId, ...metadata },
    });
    const deny = (reason: string, touched: string | null = null) => new Refusal(new SigninRefused('passkey_failed'), entry('passkey.check', 'deny', { purpose: 'remove', reason, touched }));
    try {
      return await withRefusals(this.#deps, async () => {
        let touched: { passkey: PasskeyRow; signCount: number } | null = null;
        if (state.touch !== 'none') {
          const passkey = await this.#passkeyAnswering(response, state);
          // The one it asked for: another the person keeps, or, for their last, that one.
          if (passkey === null || (state.touch === 'kept') === (passkey.id === state.passkeyId)) throw deny('unknown_credential', passkey?.id ?? null);
          const expected = { challenge: Buffer.from(state.challenge, 'base64url'), origin: this.config.passkeys.origin, rpId: this.config.passkeys.rpId, values: MAX_BODY_NODES, passkey: storedOf(passkey) };
          const verified = await verifyAssertion(response, expected);
          if (!verified.ok) throw deny(verified.reason, passkey.id);
          touched = { passkey, signCount: verified.signCount };
        }
        const standing = await this.#standing(principal);
        return retrying(async () => {
          const plan = { id: randomUUID(), expiresAt: session.expiresAt, generation: standing.generation };
          const changes = await AppChanges.prepare(this.#deps.vault, formatMember(principal), async () => {
            const at = new Date();
            const [held, connected] = await Promise.all([
              liveCredentialsWhere(this.#deps.db, this.#deps.chainKey, personCredentials(principal, at)),
              liveConnections(this.#deps.db, this.#deps.chainKey, state.principal, at),
            ]);
            return [this.#issueChange('browser', principal, plan), ...revokes(held), ...connectionRevokes(connected)];
          });
          return audited(this.#deps, async (tx, log) => {
            const [member, rows] = await Promise.all([this.#stillMember(tx, principal, standing), passkeysOf(tx, this.#deps.chainKey, state.principal)]);
            if (!member || standing.generation !== state.generation) throw new Refusal(new SigninRefused('session_ended'), entry('passkey.remove', 'deny', { reason: 'session_ended' }));
            const live = rows.filter((row) => row.generation === state.generation && row.removedAt === null);
            const target = live.find((row) => row.id === state.passkeyId);
            // Removed meanwhile, or their last one now, or no longer: what the person was asked to touch no longer holds.
            if (target === undefined) throw new Refusal(new SigninRefused('state_mismatch'), entry('passkey.remove', 'deny', { reason: 'removed' }));
            if (live.length === 1 && this.config.passkeys.policy === 'required') throw new Refusal(new SigninRefused('last_passkey'), entry('passkey.remove', 'deny', { reason: 'last_passkey' }));
            if ((state.touch === 'last') !== (live.length === 1) && state.touch !== 'none') throw new Refusal(new SigninRefused('state_mismatch'), entry('passkey.remove', 'deny', { reason: 'passkeys_changed' }));
            const now = new Date();
            // Three compare-and-sets asked together (two round trips: the session's revoke reads its row first), each
            // checked after, in this order: the session it replaces ended, once (section 6.5: of two removals on one
            // session, one goes); the touch taken, once, on a passkey still live (section 7.3); the passkey removed. Any
            // of them not moving rolls everything back.
            const [replaced, took, moved] = await Promise.all([
              revokeCredentialsWhere(tx, this.#deps.chainKey, credentialsBy.id(session.id), { revokedAt: now, revokedBy: principal.id }),
              touched === null ? 1 : touchPasskey(tx, { id: touched.passkey.id, principal: state.principal, generation: state.generation, issuedAt: new Date(state.issuedAt), signCount: touched.signCount }),
              removePasskeyRow(tx, this.#deps.chainKey, target, { removedAt: now, removedBy: principal.id }),
            ]);
            if (replaced.length !== 1) throw new Refusal(new SigninRefused('session_ended'), entry('passkey.remove', 'deny', { reason: 'session_ended' }));
            if (took === 0) throw new Refusal(new SigninRefused('state_mismatch'), entry('passkey.check', 'deny', { purpose: 'remove', reason: 'replay', touched: touched!.passkey.id }));
            if (moved === 0) throw new ObjectMoved();
            // The passkey touched, if it is one the person keeps; none otherwise, and no window opens.
            const passkeyId = state.touch === 'kept' ? touched!.passkey.id : null;
            // Everything else of theirs ended before the new session is written, which that would end too.
            const ended = await this.#endEverything(tx, principal, now, principal.id, changes, replaced);
            const credential = await this.#issue(tx, 'browser', principal, {
              ...plan, identityId: session.identityId, label: session.label, createdBy: principal.id, passkeyId, confirmedAt: passkeyId === null ? null : now,
            });
            log.push(entry('passkey.remove', 'allow', { name: target.name, touched: touched?.passkey.id ?? null, ended: countsOf(ended), issued: credential.id }));
            return { ok: true as const, principal, credential, replaced: true as const };
          }, changes, state.principal);
        });
      });
    } catch (error) {
      if (error instanceof AuthRowTampered) return refusal(new SigninRefused('tampered'));
      return refusalOrThrow(error);
    }
  }

  /** Who may add a passkey here: the person, from their own browser session, while passkeys are on. */
  #adding(ctx: Asker & Pick<ApiContext, 'session'>, member: PrincipalRef): void {
    if (!ownPasskeys(ctx, member) || ctx.session?.kind !== 'browser') throw forbidden('a person adds their own passkeys, from the browser they sign in with');
    if (this.config.passkeys.policy === 'off') throw new ApiError('conflict', 'passkeys are off on this instance', 'passkeys_off');
  }

  /**
   * Everything a person is signed in with, ended (section 6.1): every live credential of theirs, their MCP connections,
   * and the terminal codes they approved that no CLI redeemed yet. In a transaction holding their factor lock and the
   * head, whose prepared changes it holds to what it ends (`changes`). `already`: a session the caller ended first.
   */
  async #endEverything(tx: Transaction, principal: PrincipalRef, at: Date, by: string, changes: AppChanges | null, already: readonly string[] = []): Promise<Ended> {
    // Independent, so asked together: the revocations and the two reads in one round trip, the compare-and-sets those
    // reads lead to in a second (review r1 of #529; change-cost.test.ts).
    const endConnections = async () => {
      const rows = await liveConnections(tx, this.#deps.chainKey, principalOf(principal), at);
      const moved = await Promise.all(rows.map(async (row) => ((await updateAuth(tx, this.#deps.chainKey, mcpConnections, { id: row.id, authMac: row.authMac }, { revokedAt: at, revokedBy: by })) > 0 ? row.id : null)));
      return moved.filter((id) => id !== null);
    };
    const [credentials, connections, approvals] = await Promise.all([
      revokeCredentialsWhere(tx, this.#deps.chainKey, personCredentials(principal, at), { revokedAt: at, revokedBy: by }),
      endConnections(),
      denyApprovals(tx, this.#deps.chainKey, principalOf(principal), at, { unbacked: false }),
    ]);
    const ended: Ended = { credentials: [...already, ...credentials], connections, approvals };
    changes?.expectRevoked(ended.credentials);
    changes?.expectRevoked(ended.connections, 'connection');
    return ended;
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
   *
   * With `accessSeq`, the vault's newest entry about their access as the callback read it, before the vault answered:
   * moved since (a role, a grant, a scope), the callback's decision whether to ask for a passkey first was made on an
   * answer no longer theirs, and it decides again (`AccessMoved`; review r1 of #500), as `issuerStill` holds an issue.
   */
  async #stillMember(tx: Transaction, principal: PrincipalRef, standing: Access, accessSeq?: bigint | null): Promise<boolean> {
    if (standing.status !== 'active') return false;
    const row = await memberStanding(tx, principalOf(principal));
    if (accessSeq !== undefined && (row?.accessSeq ?? null) !== accessSeq) throw new AccessMoved();
    return row !== null && row.generation === standing.generation && row.status === 'active';
  }

  /**
   * Revalidate the initiating credential, or MCP connection, under the app audit head: live, and still backed by what it
   * names (passkeys.md, section 6.1), as what it issues names the same. A change to the person's passkeys revokes under the same head.
   */
  async #currentCaller(tx: Transaction, ctx: Asker, standing: Access): Promise<Access | null> {
    if (standing.generation !== ctx.caller.generation) return null;
    // Read together, one round trip: the member's row, and the credential's.
    const [member, row] = await Promise.all([
      this.#stillMember(tx, ctx.caller.principal, standing),
      ctx.credentialId === null ? null : findCredential(tx, this.#deps.chainKey, { id: ctx.credentialId }),
    ]);
    if (!member) return null;
    if (ctx.credentialId !== null) {
      if (!this.#liveCredential(row, standing, new Date()) || row?.principal !== principalOf(ctx.caller.principal)) return null;
      if (passkeyChecked(row.kind) && !this.#backed(row, row.passkeyRead!)) return null;
    } else if (ctx.via !== null && !(await sourceStands(tx, this.#deps.chainKey, this.#deps.signin.passkeys.policy, ctx))) {
      // An MCP connection, held as the request held it: live, and its passkey too (review of #497 by Fable 5.1).
      return null;
    }
    return standing;
  }

  /** Whether a live passkey stands behind a credential of a person's, or none needs to (`passkeyStands`). */
  #backed(row: { principal: string; generation: number; passkeyId: string | null }, read: PasskeyRead): boolean {
    return passkeyStands(this.#deps.chainKey, this.#deps.signin.passkeys.policy, row, read);
  }

  /**
   * Whether what an issue would name stands behind it now (section 6.1): the live passkey it names, or none while the
   * person holds none, as the request's own check decides (`passkeyStands`). Read under the log's head, which every
   * change to their passkeys holds too (formal/Factor.tla, `AppIssueChecks`); nothing read under `off`.
   */
  async #issuedBacked(tx: Transaction, holder: { principal: string; generation: number; passkeyId: string | null }): Promise<boolean> {
    if (this.#deps.signin.passkeys.policy === 'off') return true;
    return this.#backed(holder, await passkeyBehind(tx, this.#deps.chainKey, holder));
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

  /**
   * A token issued by the vault itself, with 0.15's log (T149, PR 2): the
   * row `#credential` makes, its scope as the app worked it out, and the
   * policy it was weighed on (`weighed`'s), in one call. The vault reads
   * the issuer, the account and the credential the request came in on,
   * weighs the scope itself, and writes it in one statement; no 0.14 head,
   * and no 0.14 entry: its change records the issue (D147). What it read
   * moving meanwhile, it weighs again itself; still moving after that, 409
   * (`ObjectMoved`). Each refusal is logged as the app's are. On a
   * credential 0.14 made, which the vault cannot authenticate, null: the
   * caller issues as before.
   */
  async #issuedByVault(
    ctx: Asker,
    weighed: Pick<Caller, 'policy' | 'policySeq'>,
    kind: 'service' | 'personal' | 'handle',
    principal: PrincipalRef,
    options: CredentialOptions & { id: string },
    details: Record<string, unknown>,
    held: { accessSeq: bigint | null; refusal?: () => Refusal },
  ): Promise<IssuedCredential | null> {
    // The vault holds `via` to a credential it reads, and an MCP connection is none: what one issues, the app issues,
    // holding the connection and its passkey under its head (`sourceStands`; review of #497 by Fable 5.1).
    if (ctx.credentialId === null && ctx.via !== null) return null;
    const { row, issued } = this.#credential(kind, principal, options);
    const outcome = await this.#deps.vault.issueToken!({
      actor: formatMember(ctx.caller.principal),
      via: ctx.credentialId,
      trace: traceOf(ctx),
      ...(ctx.confirmed == null ? {} : { confirmed: ctx.confirmed }),
      principal: principalOf(principal),
      generation: options.generation,
      actorAccess: held.accessSeq?.toString() ?? null,
      credential: {
        id: row.id!, kind, tokenHash: row.tokenHash.toString('base64'), tokenHint: row.tokenHint, label: row.label ?? null, scope: row.scope!, places: row.places ?? null,
        expiresAt: row.expiresAt.getTime(), createdBy: row.createdBy, authMac: row.authMac.toString('base64'),
        // The passkey of the credential it comes in on, which the row's MAC covers: the vault issues only while `via`
        // names this same one, live (migration 0064).
        passkeyId: row.passkeyId ?? null,
      },
      policy: {
        seq: weighed.policySeq?.toString() ?? null,
        protected: Object.values(weighed.policy.protectedIn).flat().map(({ environmentId, slug }) => ({ environmentId, slug })),
      },
      appKey: appLogKey(this.#deps.chainKey).keyId,
    });
    if (outcome.ok) return issued;
    switch (outcome.refused) {
      case 'unlogged': return null;
      case 'moved': throw new ObjectMoved();
      // The issuer's access moved since the scope was weighed: asked again, weighed as they are now (as `issuerStill`).
      case 'access': throw new ApiError('conflict', 'your access changed while this ran: try again', ACCESS_CHANGED);
      // The account it is for is not the member it was weighed as: removed, or admitted again since.
      case 'gone':
        throw held.refusal?.() ?? new Refusal(new ApiError('unauthenticated', 'that credential is unknown, expired or revoked'), denied(ctx, 'token.create', 'credential_ended', { metadata: details }));
      // The issuer's credential, or their membership, ended: a person's own token says their session did, as before.
      case 'ended':
        throw kind === 'service'
          ? new Refusal(new ApiError('unauthenticated', 'that credential is unknown, expired or revoked'), denied(ctx, 'token.create', 'credential_ended', { metadata: details }))
          : new Refusal(forbidden('that session has ended'), denied(ctx, 'token.create', 'session_ended', { metadata: details }));
      case 'refused':
        throw new Refusal(forbidden(outcome.why ?? 'not allowed to issue this token'), denied(ctx, 'token.create', 'vault_refused', { metadata: { ...details, why: outcome.why ?? null } }));
      case 'policy': throw new ApiError('conflict', "the instance's roles or protected environments changed while this ran: try again", POLICY_CHANGED);
      case 'busy': throw new ApiError('unavailable', 'coffre is busy: try again shortly', 'busy', '1');
      case 'retired': throw new KeyRetired('the app\'s key is one it rotated from: a newer deployment replaces this one');
    }
  }

  /** The change issuing a credential makes to 0.15's log: the object of the row `#credential` writes, from the same options. */
  #issueChange(kind: CredentialKind, principal: PrincipalRef, options: { id: string; expiresAt: Date; scope?: CredentialScope; generation: number }): ObjectChange {
    const scope = options.scope === undefined ? null : storedScope(options.scope);
    return credentialChange(null, { id: options.id, principal: principalOf(principal), kind, scope, revokedAt: null, expiresAt: options.expiresAt, generation: options.generation });
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
      label: options.label ?? null,
      createdBy: options.createdBy,
      expiresAt: options.expiresAt,
      scope: options.stored !== undefined ? options.stored : options.scope === undefined ? null : storedScope(options.scope),
      places: options.places === undefined ? null : JSON.stringify(options.places.map(({ environmentId, personal }) => ({ environmentId, personal }))),
      revokedAt: null,
      passkeyId: options.passkeyId,
      confirmedAt: options.passkeyId === null ? null : options.confirmedAt ?? null,
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
  async verify(
    token: string,
    /**
     * `ahead`: the credential as `app_read` read it already for this request (db/read-ahead.ts), null for none.
     * `shows`: what the request shows of its caller, read with the credential from the vault's rows (`Shows`).
     * `standing`: the caller as the vault's named use decided them, from the sealed rows it read (`Vault.useNamed`,
     * T145): taken as the vault's answer, nothing asked or kept.
     * `at`: the instant that use was asked at (`NamedUseInput.at`), at which the vault judged the credential's end: its
     * expiry is judged at it here too, one clock for both (review r8 of D153; formal/Probing.tla, OneClock). A
     * credential live when its request began is that request's, which the use's deadline bounds; its revocation and
     * generation stay as they are now.
     */
    request: {
      sourceIp: string | null; recall?: boolean; ahead?: CredentialRead | null; shows?: Shows; standing?: Access; at?: number;
      /** `touch`: the request writes the touch itself, with what it writes, at no round trip of its own (a key write's held statement, T179 PR 3). */
      touch?: (touched: Touch) => void;
    } = { sourceIp: null },
  ): Promise<CredentialPrincipal> {
    if (!isCoffreToken(token)) throw new Error('not a coffre credential');
    const { db, chainKey } = this.#deps;
    const now = new Date();
    const asked = request.at === undefined ? now : new Date(request.at);
    const tokenHash = hashToken(token);
    // Under `off` nothing behind the credential is read, as nothing below decides on it (review r1 of #528).
    const checked = this.#deps.signin.passkeys.policy !== 'off';

    let row: Awaited<ReturnType<typeof findCredential>>;
    let access: Access | null = null;
    let recalled: Recalled | null = null;
    let unchecked: true | undefined;
    let settings: Settings | undefined;
    let policySeq: bigint | null = null;
    try {
      if (!this.#scopes.sealed) {
        await sealScopes(db, chainKey, this.#deps.vault);
        this.#scopes.sealed = true;
      }
      row = await findCredential(db, chainKey, { tokenHash }, request.shows === 'caller' ? 'answer' : request.shows ?? request.ahead, checked);
      const shown = row === null || request.shows !== 'caller' ? null : answerOf(row.principal, row.answer);
      settings = shown?.settings ?? row?.settings;
      // Read with the row, before the vault is asked: a seal below commits only while the policy it answers with is still the newest.
      policySeq = row?.policySeq ?? null;
      // A kept answer at the credential's generation, unless its scope is still to be sealed, from what the account holds now.
      const unsealed = row !== null && row.kind === 'service' && unsealedScope(row.scope);
      const recall = request.recall === true && row !== null && !unsealed;
      // Only shown, read from the vault's rows, for an active member (`shownActive`); a scope still to be sealed is sealed from the vault's answer, asked.
      if (shown !== null && !unsealed && shownActive(shown.access)) [access, unchecked] = [shown.access, true];
      // Decided by the use this request made, on the sealed rows (a token still to be sealed asks, as it seals from the answer).
      else if (row !== null && request.standing !== undefined && !unsealed) access = request.standing;
      else if (row !== null) ({ access, recalled } = await accessFor(this.#deps, row.principal, recall && { generation: row.generation }));
      // A token or binding an older release made after this configuration sealed its own: sealed on its first use, with the account's grants the vault just answered.
      if (row !== null && access !== null && this.#unsealed(row, access, asked)) {
        const binding = issuingBinding(row.createdBy);
        const issued = binding === null ? row : await findBinding(db, chainKey, row.principal, binding);
        if (issued !== null) {
          await sealCredentials(db, chainKey, this.#deps.vault, access, policySeq, [{ kind: binding === null ? 'token' : 'binding', id: binding ?? row.id, principal: row.principal, createdBy: issued.createdBy, scope: issued.scope }]);
        }
        row = await findCredential(db, chainKey, { tokenHash }, undefined, checked);
        if (row !== null && this.#unsealed(row, access, asked)) throw new Error('its scope could not be sealed');
      }
    } catch (error) {
      if (error instanceof AuthRowTampered) throw error;
      throw new CredentialUncheckable(error);
    }
    if (row === null || access === null || !this.#liveCredential(row, access, asked)) throw new Error('unknown, expired or revoked credential');
    // What stands behind a person's credential (passkeys.md, section 6.2): read with it, by the app's own statement or
    // by the vault's call that read the row (T216: a use by name, a key write's and an add's first call answer the
    // passkey rows with the credential's). Nothing read under `off`. A row read without them (`app_read`'s, which only a
    // handle's request reads ahead, never checked here) is a read this check cannot decide on: 503, never taken.
    if (passkeyChecked(row.kind) && this.#deps.signin.passkeys.policy !== 'off') {
      if (row.passkeyRead === undefined) throw new CredentialUncheckable(new Error('the credential was read without what stands behind it'));
      if (!this.#backed(row, row.passkeyRead)) throw new PasskeyRequired(row.principal, row.id);
    }

    const lastUsed = row.lastUsedAt?.getTime() ?? 0;
    if (now.getTime() - lastUsed > TOUCH_INTERVAL_MS) {
      // Coarse on purpose: one write per credential per five minutes, not
      // one per request. Losing it must never cost the request.
      if (request.touch !== undefined) request.touch({ credential: row.id, at: now, ip: request.sourceIp });
      else await update(db, credentials, { id: row.id }, { lastUsedAt: now, lastUsedIp: request.sourceIp }).catch(() => 0);
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
          ...(unchecked === undefined ? {} : { unchecked }),
          ...(settings === undefined ? {} : { settings }),
          policySeq,
          credentialScope: readScope(row.scope),
          exchanged: row.bindingStands !== null,
          personalToken: null,
          handlePlaces: null,
          expiresAt: row.expiresAt.toISOString(),
          passkeyId: null,
          session: null,
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
          ...(unchecked === undefined ? {} : { unchecked }),
          ...(settings === undefined ? {} : { settings }),
          policySeq,
          // A personal token's scope is under its row's MAC; one that does not read as a scope reaches nothing.
          credentialScope: row.kind === 'personal' || row.kind === 'handle' ? readScope(row.scope) ?? [] : null,
          personalToken: row.kind === 'personal' ? { id: row.id, label: row.label ?? '', expiresAt: row.expiresAt.toISOString() } : null,
          handlePlaces: row.kind === 'handle' ? readPlaces(row.places) : null,
          expiresAt: row.expiresAt.toISOString(),
          passkeyId: row.passkeyId,
          // A browser's or a terminal's, with when a touch confirmed it, for the fresh check (`freshness`).
          session: row.kind === 'browser' || row.kind === 'cli' ? { kind: row.kind, confirmedAt: row.confirmedAt } : null,
        };
  }

  // --- signing out and revoking ---------------------------------------------

  /** Revoke the credential this token is. Unknown tokens are a quiet no-op. */
  async signOut(token: string, meta: Omit<ClientMeta, 'label'>): Promise<void> {
    if (!isCoffreToken(token)) return;
    const tokenHash = hashToken(token);
    if (await vaultMakesCredentials(this.#deps.vault)) {
      const vault = this.#deps.vault as CredentialsVault;
      // With 0.15's log, the vault revokes it (T149): its row read, one call. Its change records the sign-out (D147). A row
      // 0.14 made, which the log never held, is signed out as below, with 0.14's entry.
      for (let tries = 0; ; tries++) {
        const [row] = await liveCredentialsWhere(this.#deps.db, this.#deps.chainKey, credentialsBy.tokenHash(tokenHash));
        if (row === undefined) return;
        if (row.seal === null) break;
        // A run's credential signing itself out is the run's act, a personal token's the token's, as 0.14's entry says.
        const trace = issuingBinding(row.createdBy) !== null || row.kind === 'personal' || row.kind === 'handle' ? { credentialId: row.id, mcp: null } : null;
        if (await revokedByVault(vault, this.#deps.chainKey, row, { actor: row.principal, revokedBy: memberOf(row.principal).id, reason: 'sign_out', via: row.id, trace, caller: null })) return;
        if (tries === 2) throw new ObjectMoved();
      }
    }
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
    const byVault = (await vaultMakesCredentials(this.#deps.vault)) ? await this.#revokedByVault(this.#deps.vault as CredentialsVault, ctx, credentialId, of) : null;
    if (byVault !== null) return byVault;
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

  /**
   * `revokeCredential` with 0.15's log: the vault revokes it (T149), in one
   * call, once the row as read says the caller may, as above, holding the
   * policy that weighed it to the newest under the fence (as `audited`
   * holds it under 0.14's head). Its change records the revoke; a refusal
   * is logged as one. Null for a row 0.14 made, which the log never held:
   * revoked as above, with 0.14's entry.
   */
  async #revokedByVault(
    vault: CredentialsVault,
    ctx: Asker,
    credentialId: string,
    of: { member: string; managed: boolean } | 'own handle' | null,
  ): Promise<{ revoked: true } | null> {
    const { db, chainKey } = this.#deps;
    return withRefusals(this.#deps, async () => {
      for (let tries = 0; tries < 3; tries++) {
        const [row] = await liveCredentialsWhere(db, chainKey, credentialsBy.id(credentialId));
        const unknown = () =>
          new Refusal(
            notFound('unknown credential'),
            denied(ctx, 'token.revoke', 'unknown_credential', { metadata: { targetCredentialId: credentialId } }),
          );
        if (row === undefined) throw unknown();
        const { principal } = ctx.caller;
        const own = row.principal === principalOf(principal);
        if (of === 'own handle' ? row.kind !== 'handle' || !own : of !== null && (row.principal !== of.member || !(isToken(row) || row.kind === 'workload'))) throw unknown();
        if (!own && (of === null || of === 'own handle' || !of.managed)) requireInstance(ctx, 'token.revoke', { metadata: { targetCredentialId: credentialId } }, "revoke other people's credentials");
        if (row.seal === null) return null;
        if (await revokedByVault(vault, chainKey, row, { actor: formatMember(principal), revokedBy: principal.id, reason: 'revoke', via: ctx.credentialId, trace: traceOf(ctx), caller: ctx.caller })) return { revoked: true as const };
      }
      throw new ObjectMoved();
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
    const [self] = await members(this.#deps.db, this.#deps.chainKey, { member: ctx.caller.principal, standing: false }, new Date());
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
    const [self] = await members(this.#deps.db, this.#deps.chainKey, { member: ctx.caller.principal, standing: false }, new Date());
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
      members(this.#deps.db, this.#deps.chainKey, { member, standing: false }, new Date()),
      // Every place: in a render, what whoever reaches them all read.
      projectsReached(ctx.caller) === null ? reachedPlaces({ db: this.#deps.db, caller: ctx.caller, render: ctx.render }) : places(this.#deps.db),
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
    this.#serviceTokenLifetime(input.expiresInDays);
    const details = { kind: 'service', principalType: 'service', principalId: serviceId, label: input.label };
    return withRefusals(this.#deps, async () => {
      const service = { type: 'service' as const, id: serviceId };
      // The issuer as the vault answers now, held to under the head: demoted meanwhile, they give it nothing (`issuerStill`).
      const { caller, accessSeq } = await issuerNow(this.#deps, ctx.caller.principal, { ctx, action: 'token.create' });
      const { standing, scope, byPath, withheld, refusal } = await this.#tokenScope({ ...ctx, caller }, serviceId, input.scope, details);
      const plan = { id: randomUUID(), expiresAt: new Date(Date.now() + input.expiresInDays * 86_400_000), scope, generation: standing.generation };
      // With 0.15's log, the vault issues it, weighing the issuer itself (T149, PR 2): one call.
      if (await vaultIssuesTokens(this.#deps.vault)) {
        // It names the issuer's passkey, as the vault holds `via` to (section 6.3).
        const credential = await this.#issuedByVault(ctx, caller, 'service', service, { ...plan, identityId: null, label: input.label, createdBy: ctx.caller.principal.id, passkeyId: ctx.passkeyId }, details, { accessSeq, refusal });
        if (credential !== null) return { ...credential, scope: byPath, withheld };
      }
      const changes = await AppChanges.prepare(this.#deps.vault, formatMember(ctx.caller.principal), [this.#issueChange('service', service, plan)]);
      // Its scope was weighed with the policy and the issuer as the vault answered: committed only while still so (`audited`, `issuerStill`).
      return audited({ ...this.#deps, caller }, async (tx, log) => {
        await issuerStill(tx, caller, accessSeq);
        await credentialStill(ctx, tx, 'token.create');
        // The session it comes from, still backed by what it names, which the token names too (section 6.1).
        if ((ctx.credentialId !== null || ctx.via !== null) && !(await sourceStands(tx, this.#deps.chainKey, this.#deps.signin.passkeys.policy, ctx))) {
          throw new Refusal(new ApiError('unauthenticated', 'that credential is unknown, expired or revoked'), denied(ctx, 'token.create', 'credential_ended', { metadata: details }));
        }
        if (!(await this.#stillMember(tx, service, standing))) throw refusal();
        const credential = await this.#issue(tx, 'service', service, {
          ...plan,
          identityId: null,
          label: input.label,
          createdBy: ctx.caller.principal.id,
          passkeyId: ctx.passkeyId,
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

  /**
   * A service token's lifetime, held to the deployment's maximum (`serviceTokenMaxDays`), never above
   * `MAX_SERVICE_TOKEN_DAYS`, which the vault holds. Issuing checks it, and so does planning: an approval MCP shows
   * from a plan is one issuing then accepts.
   */
  #serviceTokenLifetime(days: number): void {
    const most = this.#deps.signin.serviceTokenMaxDays;
    if (!Number.isInteger(days) || days < 1 || days > most) throw badRequest(`tokens last between 1 and ${most} days here`);
  }

  /** What a token issued now would reach, checked as issuing one is (`issueServiceToken`); issues nothing. */
  async planServiceToken(ctx: Asker, serviceId: string, input: { label: string | null; expiresInDays: number; scope?: ScopeByPath }): Promise<TokenPlan> {
    this.#bearersIssued();
    this.#serviceTokenLifetime(input.expiresInDays);
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
      const plan = { id: randomUUID(), expiresAt: new Date(Date.now() + input.expiresInMinutes * 60_000), scope, generation: access.generation };
      if (await vaultIssuesTokens(this.#deps.vault)) {
        // At the generation the request was made at: a person removed and admitted again since is refused (`#currentCaller`).
        const credential = await this.#issuedByVault(ctx, ctx.caller, 'personal', person, { ...plan, generation: ctx.caller.generation, identityId: null, label: input.label, createdBy: person.id, passkeyId: ctx.passkeyId }, details, { accessSeq: null });
        if (credential !== null) return { ...credential, scope: byPath };
      }
      const changes = await AppChanges.prepare(this.#deps.vault, formatMember(person), [this.#issueChange('personal', person, plan)]);
      // Its scope was weighed with the policy as the caller was loaded: committed only while still so (`audited`).
      return audited({ ...this.#deps, caller: ctx.caller }, async (tx, log) => {
        const standing = await this.#currentCaller(tx, ctx, access);
        if (standing === null) {
          throw new Refusal(forbidden('that session has ended'), denied(ctx, 'token.create', 'session_ended', { metadata: details }));
        }
        const credential = await this.#issue(tx, 'personal', person, {
          ...plan,
          identityId: null,
          label: input.label,
          createdBy: person.id,
          // The session's passkey, copied: the token holds at most what the session does, and never passes a fresh check.
          passkeyId: ctx.passkeyId,
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
      const plan = { id: randomUUID(), expiresAt: new Date(ends), scope, generation: access.generation };
      if (await vaultIssuesTokens(this.#deps.vault)) {
        const credential = await this.#issuedByVault(ctx, ctx.caller, 'handle', person, { ...plan, generation: ctx.caller.generation, identityId: null, label: input.label, createdBy: person.id, places: madeFor, passkeyId: ctx.passkeyId }, details, { accessSeq: null });
        if (credential !== null) return { ...credential, scope: byPath };
      }
      const changes = await AppChanges.prepare(this.#deps.vault, formatMember(person), [this.#issueChange('handle', person, plan)]);
      // Its scope was weighed with the policy as the caller was loaded: committed only while still so (`audited`).
      return audited({ ...this.#deps, caller: ctx.caller }, async (tx, log) => {
        const standing = await this.#currentCaller(tx, ctx, access);
        if (standing === null) {
          throw new Refusal(forbidden('that session has ended'), denied(ctx, 'token.create', 'session_ended', { metadata: details }));
        }
        const credential = await this.#issue(tx, 'handle', person, {
          ...plan,
          identityId: null,
          label: input.label,
          createdBy: person.id,
          // What the proxy's stable URL, `/use/<credential>`, resolves to: the environments as asked, `@me` included.
          places: madeFor,
          passkeyId: ctx.passkeyId,
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
   * and dies with it. Its label is a copy of its binding's, whatever its
   * length: an accepted consequence of the 2026-11-06 decision (no length of
   * a label's own), since only an Owner's binding sets it and its bytes land
   * on that service's sign-ins, each credential and `issue` entry one copy
   * (docs/design/workload-access.md, section 3, "What an Owner's bindings
   * cost"). Naming the binding by its ID instead is a follow-up.
   */
  exchangedCredential(
    service: string,
    options: { generation: number; bindingId: string; label: string | null; expiresAt: Date; scope?: CredentialScope; stored?: string | null },
  ): { row: typeof credentials.$inferInsert & { id: string; principal: string; kind: string; scope: string | null; revokedAt: null; expiresAt: Date }; issued: IssuedCredential } {
    const made = this.#credential('service', { type: 'service', id: service }, {
      generation: options.generation,
      identityId: null,
      label: options.label,
      createdBy: issuedBy(options.bindingId),
      expiresAt: options.expiresAt,
      // A service's: no passkey.
      passkeyId: null,
      ...(options.scope === undefined ? {} : { scope: options.scope }),
      ...(options.stored === undefined ? {} : { stored: options.stored }),
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
    const open = await openDeviceSources(db, this.#deps.chainKey, now);
    const fromIp = open.filter((source) => source === input.sourceIp).length;
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
          clientLabel: input.clientLabel ?? null,
          clientIp: input.sourceIp,
          expiresAt: new Date(now.getTime() + DEVICE_TTL_SECONDS * 1000),
          decision: null,
          decidedAt: null,
          principal: null,
          generation: 0,
          consumedAt: null,
          passkeyId: null,
        };
        await insert(db, deviceLogins, { ...row, authMac: authMac(this.#deps.chainKey, 'device_authorizations', row) });
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

  async decideDevice(ctx: Asker, userCodeInput: string, approve: boolean, answer?: TouchAnswer): Promise<{ decided: true }> {
    const action = approve ? 'device.approve' : 'device.deny';
    const code = normalizeUserCode(userCodeInput);
    // A personal token approving one would make a session with all its person holds.
    if (ctx.caller.principal.type !== 'user' || ctx.caller.credentialScope !== null) throw forbidden('only people approve sign-ins, signed in as themselves');
    // Approving takes a touch for this code (section 3.5): the terminal gets a credential for 30 days, and the touch is
    // the moment its person says yes to it. Denying takes none, nor a code no terminal could hold: that one is refused
    // unknown below, with no authenticator asked first.
    const touch = approve && code !== null ? await this.touchFor(ctx, { kind: 'device', code }, answer) : null;
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
              deviceLogins,
              { id: row.id, decidedAt: null },
              approve
                // The passkey touched for it, which the CLI session it redeems names in turn, confirmed when this was
                // decided (passkeys.md, sections 3.5 and 5.2); none without a touch: under `off`, or a person who holds none.
                ? { decidedAt: now, decision: 'approved', principal: principalOf(ctx.caller.principal), generation: standing.generation, passkeyId: touch?.passkeyId ?? null }
                : { decidedAt: now, decision: 'denied' },
            );
      if (row === undefined || decided === 0) {
        throw new Refusal(
          notFound('that code is unknown or has expired'),
          denied(ctx, action, 'unknown_code', { metadata: { userCode: code ?? userCodeInput.slice(0, 16) } }),
        );
      }
      if (touch !== null) await this.touched(tx, log, ctx, touch);
      log.push(
        allowed(ctx, action, {
          metadata: { deviceAuthorizationId: row.id, clientLabel: row.clientLabel, clientIp: row.clientIp, ...(touch === null ? {} : { passkeyId: touch.passkeyId }) },
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
    const plan = { id: randomUUID(), expiresAt: new Date(Date.now() + this.#deps.signin.cliSessionDays * 86_400_000), generation: standing.generation };
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
        const consumed = await updateAuth(tx, this.#deps.chainKey, deviceLogins, { id: row.id, consumedAt: null }, { consumedAt: now });
        if (consumed === 0) return { status: 'expired' };
        const principalId = memberOf(row.principal!).id;
        // An approval given before the person was last added is void: someone
        // removed and re-added in between starts with nothing from before.
        if (standing.status !== 'active' || principalId !== principal.id || standing.generation !== row.generation) return { status: 'denied' };
        // Under the head, as every change to the person's passkeys: the approval's passkey still live, or, naming none, a
        // person who holds none (section 6.1). Asked together, one round trip.
        const [member, backed] = await Promise.all([
          this.#stillMember(tx, principal, standing),
          this.#issuedBacked(tx, { principal: row.principal!, generation: standing.generation, passkeyId: row.passkeyId }),
        ]);
        if (!member || !backed) {
          log.push({
            actorType: 'user', actorId: principal.id, action: 'sign_in', decision: 'deny',
            requestId: meta.requestId, sourceIp: meta.sourceIp,
            metadata: { kind: 'cli', deviceAuthorizationId: row.id, reason: member ? 'passkey_required' : 'membership_changed' },
          });
          return { status: 'denied' };
        }

        changes?.keep();
        const credential = await this.#issue(tx, 'cli', principal, {
          ...plan,
          identityId: null,
          label: row.clientLabel,
          createdBy: principalId,
          // The passkey touched to approve it (section 3.5), and when: an approval names one only with its touch, so the
          // terminal starts inside that touch's window, as a browser does after its own.
          passkeyId: row.passkeyId,
          confirmedAt: row.passkeyId === null ? null : row.decidedAt,
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

/** A touch an act carries (section 4.2): the sealed state its `403 touch_required` asked with, and `get()`'s answer. */
export type TouchAnswer = { state: string; response: Record<string, unknown> };

/** Who an act's touch is asked of: a person, by the session the request came in on. */
type Toucher = Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp' | 'credentialId' | 'passkeyId'>;

/** A touch checked for an act, before the act's transaction moves its replay mark (`SigninService.touched`). */
export type ActTouch = { state: ActState; passkeyId: string; signCount: number };

/** What each act's `403 touch_required` says. */
const TOUCH_ASKED: Record<Act['kind'], string> = {
  device: 'approving a terminal takes a touch of your passkey',
  approval: "approving an app's change takes a touch of your passkey",
  connect: 'connecting an app takes a touch of your passkey',
};

/** Whether a sealed act is the one being done: the same kind, target and answer. */
function sameAct(sealed: Act, act: Act): boolean {
  return actKey(sealed) === actKey(act);
}

const actKey = (act: Act): string =>
  act.kind === 'device' ? `device ${act.code}` : act.kind === 'approval' ? `approval ${act.id} ${act.answer}` : `connect ${act.answer}`;

/** A touch for an act that did not check: refused, with its `passkey.check` entry, since it came from a session. */
function touchFailed(ctx: Toucher, act: Act, reason: string, passkeyId: string | null): Refusal {
  return new Refusal(
    new ApiError('touch_failed', 'that passkey did not confirm it: try again'),
    denied(ctx, 'passkey.check', reason, { metadata: { purpose: act.kind, passkeyId } }),
  );
}

const isOpen = (now: Date) => (row: { decidedAt: Date | null; expiresAt: Date }) =>
  row.decidedAt === null && row.expiresAt > now;

/**
 * What completes a sign-in after the provider (passkeys.md, sections 3.1 and 3.2): a touch of a live passkey of the
 * person's, whose counter it moves; or a first passkey, added with the session, its row made ready but for whose and
 * which generation, which the sign-in decides.
 */
/** `replaces`: the session cookie the browser answered with, if any, which a touch replaces when it is the person's (section 6.5). */
type Factor =
  | { kind: 'touch'; state: PendingFactor; passkey: PasskeyRow; signCount: number; replaces: string | null }
  | {
      kind: 'enroll';
      state: PendingFactor;
      replaces: string | null;
      id: string;
      row: {
        id: string; userHandle: Buffer; credentialId: Buffer; publicKey: Buffer; algorithm: number; signCount: number; lastChallengeAt: Date;
        transports: string; aaguid: Buffer | null; synced: boolean; name: string;
      };
    };

/** What the passkey page asks the browser to do, for whom: a touch (`get()`), or a new passkey (`create()`). */
export type PasskeyStep =
  | { purpose: 'signin' | 'step-up'; email: string; options: RequestOptionsJSON }
  | { purpose: 'enroll'; email: string; options: CreationOptionsJSON; state: string; reset: { by: string; at: string } | null };

/** What the callback read and resolved, for the sign-in it completes (`#afterProvider`). */
type Known = {
  previous: Awaited<ReturnType<typeof findIdentity>>;
  /** The member a first sign-in binds, by the verified email that matched: the vault is asked about them alone. */
  person: { id: string; email: string } | null;
  /** The vault's newest entry about their access, read before it answered (`signinMembers`); null for no row. */
  accessSeq: bigint | null;
};

/** The person's access moved between the callback's reads and its transaction: decided again, from the reads. */
class AccessMoved extends Error {
  /** The unique violation of a bind another sign-in won, when that is what moved. */
  readonly violation: unknown;
  constructor(violation?: unknown) {
    super("the person's access changed while they signed in");
    this.violation = violation;
  }
}

/** The vault's answer, asked once, says an Owner of the whole instance: they add a passkey first. Thrown before any write. */
class StepWanted extends Error {
  readonly access: Access;
  constructor(access: Access) {
    super('a passkey is wanted first');
    this.access = access;
  }
}

/**
 * A passkey step refused with no entry (section 11): whoever answered passed the provider but not the factor, and wrote
 * nothing. The reason goes to the process log, as a provider's failures do.
 */
function passkeyRefused(meta: Pick<ClientMeta, 'requestId'>, principal: string, reason: 'passkey_failed' | 'passkey_exists' | 'state_mismatch', why: string): never {
  console.warn('a sign-in stopped at its passkey', { principal, reason, why, requestId: meta.requestId });
  throw new SigninRefused(reason);
}

// --- managing passkeys ---------------------------------------------------------------------------------------------

/**
 * How many live passkeys a person holds at most: ten, as the design Erwin approved sets (passkeys.md, section 3.6;
 * 2026-11-03), a list a person can still read (R70: a policy he set).
 */
export const MAX_PASSKEYS = 10;

/** A passkey as the Passkeys tab shows it: its name, its provider's where its AAGUID names one, whether it syncs, and when. */
export type PasskeyView = { id: string; name: string; provider: string | null; synced: boolean; createdAt: string; lastUsedAt: string | null };

/**
 * A person's passkeys (`GET /members/:member/passkeys`): the live ones; what removing one, or a reset, ends, the session
 * asking left out; the newest reset of theirs by someone else, while no passkey was added since; and how many they may hold.
 */
export type PasskeyList = {
  passkeys: PasskeyView[];
  ends: { sessions: number; tokens: number; handles: number; apps: number };
  reset: { by: string; at: string } | null;
  max: number;
};

/** What a reset did: how many passkeys it removed, and what it ended. */
export type PasskeyReset = { reset: number; ended: { credentials: number; connections: number; approvals: number } };

/** What a change to a person's passkeys ended, by id. */
type Ended = { credentials: string[]; connections: string[]; approvals: string[] };

const countsOf = (ended: Ended) => ({ credentials: ended.credentials.length, connections: ended.connections.length, approvals: ended.approvals.length });

function passkeyView(row: Pick<PasskeyRow, 'id' | 'name' | 'aaguid' | 'synced' | 'createdAt' | 'lastUsedAt'>): PasskeyView {
  return {
    id: row.id, name: row.name, provider: providerName(row.aaguid), synced: row.synced,
    createdAt: row.createdAt.toISOString(), lastUsedAt: row.lastUsedAt?.toISOString() ?? null,
  };
}

/**
 * The newest reset of a person's passkeys at this membership (section 3.7), while they hold none since: their newest
 * removal, by someone else than them. What their next pages say ("Ada reset your passkeys on 31 Oct"). Removals alone
 * are weighed, each dated by the app's clock that wrote it, never against a row's `created_at`, the database's.
 */
function lastReset(principal: string, rows: readonly PasskeyRow[]): { by: string; at: string } | null {
  if (rows.some((row) => row.removedAt === null)) return null;
  let newest: PasskeyRow | null = null;
  for (const row of rows) {
    if (row.removedAt !== null && (newest === null || row.removedAt > newest.removedAt!)) newest = row;
  }
  if (newest === null || newest.removedBy === memberOf(principal).id) return null;
  return { by: newest.removedBy!, at: newest.removedAt!.toISOString() };
}

/** Whether the caller is this person, signed in as themselves: a session, not a token's scope, nor a connection. */
function ownPasskeys(ctx: Asker, member: PrincipalRef): boolean {
  return member.type === 'user' && ctx.caller.principal.type === 'user' && ctx.caller.principal.id === member.id
    && ctx.caller.credentialScope === null && ctx.via === null && ctx.credentialId !== null;
}

/** An Owner of the whole instance, signed in as themselves: who sees and resets anyone's passkeys (section 3.7). */
function instanceOwner(ctx: Asker): boolean {
  return ctx.caller.principal.type === 'user' && ctx.caller.credentialScope === null && ctx.via === null && ownsInstance(ctx.caller);
}

/** Only an Owner of the whole instance resets anyone's passkeys, and a refusal is logged as an attempt (section 3.7). */
function mayReset(ctx: Asker, member: PrincipalRef): void {
  if (!instanceOwner(ctx)) {
    throw new Refusal(forbidden("only an Owner of the whole instance resets someone's passkeys"), denied(ctx, 'passkey.reset', 'not_owner', { metadata: { principalType: member.type, principalId: member.id } }));
  }
  if (member.type !== 'user') throw notFound('only people hold passkeys');
}

/** Room for another passkey: one held already (a first is added at sign-in), and fewer than `MAX_PASSKEYS`. */
function addable(live: number): void {
  if (live === 0) throw new ApiError('conflict', 'a first passkey is added at sign-in: sign in again to add it', 'first_passkey');
  if (live >= MAX_PASSKEYS) throw new ApiError('conflict', `you hold ${MAX_PASSKEYS} passkeys, the most there may be: remove one first`, 'too_many_passkeys');
}

/** A passkey row of the person's that fails its MAC: nothing about their passkeys is changed or shown as fewer (R64). */
function tamperedPasskeys(): ApiError {
  return new ApiError('conflict', "one of this person's passkey rows fails its signature: coffre changes none of them", 'tampered');
}

/** A passkey row as the verifier checks an assertion against it. */
function storedOf(row: PasskeyRow): StoredPasskey {
  return { credentialId: row.credentialId, publicKey: row.publicKey, algorithm: row.algorithm as PasskeyAlgorithm, userHandle: row.userHandle };
}

function refusalOrThrow(error: unknown): { ok: false; reason: SigninRefusal; providers?: string[] } {
  if (error instanceof SigninRefused) return refusal(error);
  throw error;
}

function refusal(error: SigninRefused): { ok: false; reason: SigninRefusal; providers?: string[] } {
  return error.providers === undefined ? { ok: false, reason: error.reason } : { ok: false, reason: error.reason, providers: error.providers };
}
