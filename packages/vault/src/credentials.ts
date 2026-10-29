import { randomUUID } from 'node:crypto';

import {
  DEFAULT_POLICY,
  definitionOf,
  delegable,
  HANDLE_POLICY,
  heldColumns,
  issuesCredential,
  MAX_PERSONAL_TOKEN_MINUTES,
  MAX_SERVICE_TOKEN_DAYS,
  ownsProject,
  readScope,
  scopeDefinition,
  sealedSessionScope,
  type CredentialScope,
  type Holdings,
  type Place,
  type Policy,
  type ScopeGrant,
  type ServiceAccount,
  type ServiceSetting,
} from '@coffre/core/access';
import { EXCHANGED_CREDENTIAL_MS, POLICY_DEFAULTS, POLICY_FIELDS, SESSION_MS, type BindingPolicy, type WorkloadProfile } from '@coffre/core/identity';
import type { BindingColumns, ChangeBindingsInput, CredentialColumns, IssueTokenInput, MadeBinding, IssueTokenRefusal, RevokeCredentialInput, SignInCredential, SignInInput, SignInRefusal } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { engineOf } from '@coffre/db/dialect';

import { NotLogged, payloadOf, type ChangeKeys } from './changes.ts';
import { applyOp, canonical, objectKey, sealed, sealOf, type Op, type Ref } from './inputs.ts';
import { bindingsOnPostgres, issueOnPostgres, revokeOnPostgres, signInOnPostgres } from './credentials.postgres.ts';
import { bindingsOnSqlite, issueOnSqlite, revokeOnSqlite, signInOnSqlite } from './credentials.sqlite.ts';
import { entryMac } from './log-entry.ts';
import { bindingObject, credentialObject } from './objects.ts';

/**
 * The vault makes and ends credentials itself, each in one statement
 * (T149, D146; docs/design/credential-lifecycle.md; formal/Lifecycle.tla):
 * a sign-in through a trust binding (`sign_in`, migration 0034) and a
 * revoke (`revoke_credential`). It decides here, on the columns the app
 * names, and seals what it decides; the statement goes ahead only while
 * those columns are the rows', under their locks, and numbers the change.
 * Then the caller waits for the seal (R51).
 *
 * The app still verifies the proof (the ID token's signature and claims,
 * against the binding it read): the vault's own check of it is D148's,
 * next (Lifecycle.tla's VaultVerifiesToken, BindingSealed).
 */

/** How many credentials a binding makes a window, and the window: `EXCHANGES_PER_BINDING_MINUTE`, as 0.14 counts them. */
export const SIGN_INS_PER_WINDOW = 60;
export const SIGN_IN_WINDOW_MS = 60_000;


/** The longest a session's hard end may be, past its sign-in: the most `sessionHours` takes (workloads.ts's policy check). */
const LONGEST_SESSION_HOURS = 168;

/** What the change of a sign-in records besides its op (D147): its binding, proof, issuer, the run's claims, and a session's key and hard end. */
type SignInRecord = { binding: string; proof: string; issuer: string; run: Record<string, string | number>; jkt?: string; notAfter?: number };

/** A sign-in as the vault decided it: the statement's arguments. */
export type SignInCall = {
  requestId: string; at: number; actor: string; payload: string; mac: Buffer; seal: Buffer;
  /** The binding's columns as the vault checked its seal (`bindingSeal`): the statement holds the row to both. */
  binding: BindingColumns; bindingSeal: Buffer; principal: string; appKey: string; spent: Buffer | null; validUntil: number | null; frozen: boolean; longest: number;
  /** At most `rate` credentials a binding makes in `window` ms. */
  rate: number; window: number;
  credential: SignInCredential & { createdBy: string; tokenHashBytes: Buffer; authMacBytes: Buffer };
};

/** The statement's answer: its change's number, or why it made nothing. */
export type Answer = { number?: string | null; state?: SignInRefusal | IssueTokenRefusal | 'moved' | 'stale' | 'policy' | 'unbound' | 'full' };

/** A lock not had within the functions' `lock_timeout`, or a statement cancelled: overloaded, refused at once (R44). */
const BUSY_CODES = new Set(['55P03', '57014']);

function isBusy(error: unknown): boolean {
  for (let cause = error; typeof cause === 'object' && cause !== null; cause = (cause as { cause?: unknown }).cause) {
    if (BUSY_CODES.has(String((cause as { code?: unknown }).code))) return true;
  }
  return false;
}

/**
 * A sign-in, decided and made: the credential's object from the binding's
 * columns as named (its scope, a workload's reads with it), its seal, its
 * change, then one statement. Throws on an input no app of this release
 * sends.
 */
export async function signIn(db: Database, keys: ChangeKeys, at: number, input: SignInInput): Promise<Answer> {
  let call: SignInCall;
  try {
    call = decideSignIn(keys, at, input);
  } catch (error) {
    if (error instanceof SignInRefused) return { state: error.state };
    throw error;
  }
  if (engineOf(db) === 'sqlite') return db.transaction((tx) => signInOnSqlite(tx, call));
  try {
    return await signInOnPostgres(db, call);
  } catch (error) {
    if (isBusy(error)) return { state: 'busy' };
    throw error;
  }
}

function decideSignIn(keys: ChangeKeys, at: number, input: SignInInput): SignInCall {
  const { principal, credential, appKey, spent, validUntil, record } = input ?? ({} as SignInInput);
  if (typeof principal !== 'string' || !/^token:[a-z0-9][a-z0-9._-]{0,99}$/.test(principal)) throw new Error('a sign-in is a service account\'s, token:<id>');
  const binding = checkBinding(input?.binding?.columns);
  if (input.binding.seal !== null && !isBase64(input.binding.seal, 16)) throw new Error('a binding\'s seal is 16 bytes, in base64, or none');
  // Only a binding the vault sealed, live, of this account (BindingSealed): one 0.14 made, or a row not its object, signs nobody in.
  const bindingSeal = input.binding.seal === null ? null : Buffer.from(input.binding.seal, 'base64');
  if (bindingSeal === null || binding.revoked || binding.principal !== principal || !sealed(keys.seals, { kind: 'binding', id: binding.id }, bindingObject(binding), bindingSeal)) {
    throw new SignInRefused('unsealed');
  }
  checkCredential(credential);
  if (typeof appKey !== 'string' || !/^app:[A-Za-z0-9_-]{1,64}$/.test(appKey)) throw new Error('a sign-in names the app\'s log key it signed the row under');
  if (spent !== null && !isBase64(spent, 32)) throw new Error('a sign-in spends its token by its signing input\'s hash, 32 bytes, or nothing');
  if (validUntil !== null && (typeof validUntil !== 'number' || !Number.isSafeInteger(validUntil))) throw new Error('a proof holds until a time, in ms, or its credential\'s end bounds it');
  if (typeof record?.proof !== 'string' || typeof record.issuer !== 'string' || !isRun(record.run)) throw new Error('a sign-in records its proof, issuer and run');
  // What the credential reaches, holds and lives, by its kind: the binding's own scope, or a session's with its binding's reads.
  let scope: string | null;
  let longest: number;
  if (credential.kind === 'service') {
    if (binding.policy !== null || spent === null || credential.jkt !== null || credential.notAfter !== null || credential.places !== null) {
      throw new Error('a CI run\'s credential comes of a binding with no policy, spends its token, and is bound to no key');
    }
    scope = binding.scope;
    longest = EXCHANGED_CREDENTIAL_MS;
  } else {
    if (binding.policy === null || credential.jkt === null || credential.notAfter === null) throw new Error('a workload\'s session comes of a binding with a policy, bound to a key, with a hard end');
    const policy = JSON.parse(binding.policy) as BindingPolicy;
    scope = sealedSessionScope(null, binding, policy);
    longest = SESSION_MS;
    const fields: readonly string[] = POLICY_FIELDS[binding.profile as WorkloadProfile] ?? [];
    const hours = fields.includes('sessionHours') ? policy.sessionHours ?? POLICY_DEFAULTS.sessionHours : LONGEST_SESSION_HOURS;
    if (credential.notAfter > at + hours * 3_600_000 + 60_000) throw new SignInRefused('expired');
  }
  if (credential.scope !== scope) throw new Error('a credential a binding makes reaches what its binding does: its scope, as the vault makes it from the binding');
  const id = credential.id;
  const ref: Ref = { kind: 'credential', id };
  const columns: CredentialColumns = {
    id, principal, kind: credential.kind, scope, revoked: false, generation: binding.generation,
    expiresAt: Math.min(credential.expiresAt, credential.notAfter ?? Infinity),
  };
  const object = credentialObject(columns);
  const op: Op = { op: 'credential.issue', principal, caller: object.caller, scope: object.scope, expiresAt: object.expiresAt, generation: object.generation };
  // A workload's session's key and hard end too: what its proofs are signed by, and when it ends whatever renews it.
  const signedIn: SignInRecord = {
    binding: binding.id, proof: record.proof, issuer: record.issuer, run: record.run,
    ...(credential.jkt === null ? {} : { jkt: credential.jkt }), ...(credential.notAfter === null ? {} : { notAfter: credential.notAfter }),
  };
  const payload = canonical({ ...JSON.parse(payloadOf(ref, op)), signIn: signedIn });
  const seal = sealOf(keys.seals[0]!, ref, object);
  const row = { at, requestId: randomUUID(), object: objectKey(ref), actor: principal, payload, seal };
  return {
    ...row, mac: entryMac(keys.mac, { tree: 'changes', row }),
    binding, bindingSeal, principal, appKey, spent: spent === null ? null : Buffer.from(spent, 'base64'), validUntil, frozen: credential.kind === 'workload', longest, rate: SIGN_INS_PER_WINDOW, window: SIGN_IN_WINDOW_MS,
    credential: { ...credential, createdBy: `binding:${binding.id}`, tokenHashBytes: Buffer.from(credential.tokenHash, 'base64'), authMacBytes: Buffer.from(credential.authMac, 'base64') },
  };
}

/** A binding's columns as the app names them; throws on a shape no app of this release sends. */
export function checkBinding(columns: BindingColumns | undefined): BindingColumns {
  const c = columns ?? ({} as BindingColumns);
  const text = (value: unknown) => typeof value === 'string';
  if (!text(c.id) || !UUID.test(c.id) || !text(c.principal) || !Number.isInteger(c.generation) || !text(c.profile) || !text(c.issuer) || !text(c.origin) || !webUrl(c.origin) || !text(c.jwksUri)
    || !text(c.claims) || (c.scope !== null && !text(c.scope)) || (c.policy !== null && !text(c.policy)) || typeof c.revoked !== 'boolean') {
    throw new Error('a binding is named by its columns as its row keeps them: id, account, generation, profile, issuer, origin (an http(s) URL), keys, claims, scope, policy, revoked');
  }
  return c;
}

/** An instance's public URL, http or https, as a binding's `origin` must be: checked where it enters, so a sign-in never parses a bad one (Fable on PR 3b). */
function webUrl(value: string): boolean {
  try {
    const { protocol } = new URL(value);
    return protocol === 'https:' || protocol === 'http:';
  } catch {
    return false;
  }
}

/** A sign-in the vault refuses before any statement: its own check of the times. */
class SignInRefused extends Error {
  readonly state: SignInRefusal;
  constructor(state: SignInRefusal) {
    super(`sign-in refused: ${state}`);
    this.state = state;
  }
}

function checkCredential(c: SignInCredential): void {
  const text = (value: unknown, max: number) => typeof value === 'string' && value.length > 0 && value.length <= max;
  const optional = (value: unknown, max: number) => value === null || text(value, max);
  const time = (value: unknown) => typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
  if (typeof c?.id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(c.id)
    || (c.kind !== 'service' && c.kind !== 'workload') || !isBase64(c.tokenHash, 32) || !isBase64(c.authMac, 32) || !text(c.tokenHint, 64)
    || !optional(c.label, 120) || (c.scope !== null && typeof c.scope !== 'string') || (c.places !== null && typeof c.places !== 'string')
    || !time(c.expiresAt) || (c.notAfter !== null && !time(c.notAfter)) || !optional(c.jkt, 128)) {
    throw new Error('a sign-in\'s credential is its row: an id, its kind, its token\'s hash and hint, its times, and the app\'s MAC');
  }
}

function isBase64(value: unknown, bytes: number): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9+/]+={0,2}$/.test(value) && Buffer.from(value, 'base64').length === bytes;
}

/** A run's claims as the change records them: short strings and numbers, at most as many as `runClaims` keeps (23 today). */
function isRun(run: unknown): run is Record<string, string | number> {
  if (typeof run !== 'object' || run === null || Array.isArray(run)) return false;
  const entries = Object.entries(run);
  return entries.length <= 32 && entries.every(([key, value]) => key.length <= 64 && ((typeof value === 'string' && value.length <= 256) || (typeof value === 'number' && Number.isFinite(value))));
}

/**
 * A revoke, decided and made: the object as the app read it, checked
 * against its seal (`NotLogged`, tampered, if the vault never made it), the
 * revoke applied and sealed, then one statement. A row 0.14 made and the
 * log never held is revoked with no change, as `prepare` leaves one.
 */
export async function revokeCredential(db: Database, keys: ChangeKeys, at: number, input: RevokeCredentialInput): Promise<Answer> {
  const { actor, before, authMacFrom, authMac, revokedAt, revokedBy, reason, via, policy } = input ?? ({} as RevokeCredentialInput);
  const columns = before?.columns;
  if (typeof actor !== 'string' || actor.length === 0 || typeof columns?.id !== 'string' || typeof columns.principal !== 'string' || columns.revoked !== false
    || !isBase64(before.seal, 16) || !isBase64(authMacFrom, 32) || !isBase64(authMac, 32)
    || typeof revokedAt !== 'number' || !Number.isSafeInteger(revokedAt) || typeof revokedBy !== 'string' || (reason !== 'revoke' && reason !== 'sign_out')
    || (via !== null && typeof via !== 'string') || !isPolicy(policy)) {
    throw new Error('a revoke names the credential as read, live, its seal, the app\'s MACs before and after, and the policy it was weighed on');
  }
  const ref: Ref = { kind: 'credential', id: columns.id };
  const now = credentialObject(columns);
  const sealFrom = Buffer.from(before.seal, 'base64');
  if (!sealed(keys.seals, ref, now, sealFrom)) throw new NotLogged(ref, 'tampered');
  const after = applyOp(now, ref, { op: 'credential.revoke' })!;
  const seal = sealOf(keys.seals[0]!, ref, after);
  // What a revoke's record says besides (D147): why, the credential the request came in on, and whose credential of what kind it ends.
  const payload = canonical({ ...JSON.parse(payloadOf(ref, { op: 'credential.revoke' })), revoke: { reason, via, kind: columns.kind, principal: columns.principal } });
  const row = { at, requestId: randomUUID(), object: objectKey(ref), actor, payload, seal };
  const call: RevokeCall = {
    ref, macFrom: Buffer.from(authMacFrom, 'base64'), mac: Buffer.from(authMac, 'base64'), revokedAt, revokedBy, policy,
    change: { ...row, sealFrom, mac: entryMac(keys.mac, { tree: 'changes', row }) },
  };
  if (engineOf(db) === 'sqlite') return db.transaction((tx) => revokeOnSqlite(tx, call));
  try {
    return await revokeOnPostgres(db, call);
  } catch (error) {
    if (isBusy(error)) return { state: 'busy' };
    throw error;
  }
}

/** A policy a revoke was weighed on, as the app names it: the newest change's sequence number, the protected environments' slugs. */
function isPolicy(policy: unknown): policy is RevokeCredentialInput['policy'] {
  if (policy === null) return true;
  const { seq, protected: guarded } = (policy ?? {}) as { seq?: unknown; protected?: unknown };
  return (seq === null || (typeof seq === 'string' && /^-?[0-9]{1,19}$/.test(seq)))
    && Array.isArray(guarded) && guarded.every((place) => typeof place?.environmentId === 'string' && (place.slug === null || typeof place.slug === 'string'));
}

/** A revoke as the vault decided it: the statement's arguments. */
export type RevokeCall = {
  ref: Ref; macFrom: Buffer; mac: Buffer; revokedAt: number; revokedBy: string; policy: RevokeCredentialInput['policy'];
  change: { at: number; actor: string; requestId: string; object: string; payload: string; seal: Buffer; sealFrom: Buffer; mac: Buffer };
};

// --- a token's issue (PR 2) -----------------------------------------------------

/** What an issue was weighed on, read by the vault before its statement: the rows the statement then holds to. */
export type IssueRead = {
  at: number;
  actor: { generation: number; accessSeq: bigint };
  principal: { generation: number; accessSeq: bigint };
  /** The credential the request came in on, as read, and its seal; null for none. */
  via: { columns: CredentialColumns; seal: Buffer | null } | null;
  /**
   * The environments whose slugs it was weighed on, which the statement holds under the issue lock: the policy's
   * protected ones, as the app named them, and the scope's, as the vault read them (a scoped role matches by slug).
   */
  slugs: { environmentId: string; slug: string | null }[];
};

/** An issue as the vault decided it: the statement's arguments. */
export type IssueCall = {
  change: { at: number; actor: string; requestId: string; object: string; payload: string; seal: Buffer; mac: Buffer };
  input: IssueTokenInput;
  read: IssueRead;
  tokenHash: Buffer;
  authMac: Buffer;
};

/** The shape of an issue as the app sends it; throws on one no app of this release sends. */
export function checkIssue(input: IssueTokenInput): CredentialScope {
  const { actor, via, principal, generation, credential: c, policy, appKey } = input ?? ({} as IssueTokenInput);
  const member = /^(user:[^\s]{1,320}|token:[a-z0-9][a-z0-9._-]{0,99})$/;
  if (typeof actor !== 'string' || !member.test(actor) || typeof principal !== 'string' || !member.test(principal) || !Number.isInteger(generation)
    || (via !== null && (typeof via !== 'string' || !UUID.test(via))) || !isPolicy(policy)
    || (input.actorAccess !== null && (typeof input.actorAccess !== 'string' || !/^-?[0-9]{1,19}$/.test(input.actorAccess))) || typeof appKey !== 'string' || !/^app:[A-Za-z0-9_-]{1,64}$/.test(appKey)) {
    throw new Error('an issue names its issuer, the credential it came in on, whom it acts as at which generation, the policy weighed, and the app\'s key');
  }
  if (typeof c?.id !== 'string' || !UUID.test(c.id) || (c.kind !== 'service' && c.kind !== 'personal' && c.kind !== 'handle') || !isBase64(c.tokenHash, 32)
    || !isBase64(c.authMac, 32) || typeof c.tokenHint !== 'string' || c.tokenHint.length === 0 || c.tokenHint.length > 64
    || (c.label !== null && (typeof c.label !== 'string' || c.label.length > 120)) || typeof c.scope !== 'string' || (c.places !== null && typeof c.places !== 'string')
    || typeof c.expiresAt !== 'number' || !Number.isSafeInteger(c.expiresAt) || typeof c.createdBy !== 'string') {
    throw new Error('an issue\'s token is its row: an id, its kind, its token\'s hash and hint, its scope as stored, its end, its maker, and the app\'s MAC');
  }
  if ((c.kind === 'handle') !== (c.places !== null)) throw new Error('a handle, and only a handle, names the places it stands in for');
  const scope = readScope(c.scope);
  if (scope === null || scope.length === 0) throw new Error('an issued token reaches what its stored scope names, at least one place');
  return scope;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * How far past its longest a token's end may be: the app sets it by its own
 * clock, the vault weighs it by the database's, and a host a minute or two
 * ahead should not have every longest token refused (Fable on PR 2).
 */
const CLOCK_SLACK_MS = 5 * 60_000;

/**
 * Whether the issuer, as the vault read them (`holder`, its credential's
 * scope and kind through it), may give `principal` a token of this kind,
 * scope and end: null if so, or why not. The app's own checks, made
 * again on the vault's reads, with the same rules (`@coffre/core/access`):
 * - a service account's (R15, R32): its issuer, a person, manages it, and could give
 *   it each grant, which the account holds (`issuesCredential`); sensitive
 *   reads only where the issuer is an Owner of the project (`ownsProject`);
 *   each grant's columns within its role; at most `MAX_SERVICE_TOKEN_DAYS`;
 * - a personal token: its person's own, made on a session, each role one
 *   that manages no access (`delegable`), no column past what that role
 *   holds as the policy defines it nor what they hold there
 *   (`issuedGrant`'s bound); at most `MAX_PERSONAL_TOKEN_MINUTES`;
 * - a handle: its person's own, each place a `viewer` or a `contributor`,
 *   no column past reading and using (`HANDLE_POLICY`) nor what they hold
 *   there through the credential it came in on; never past that
 *   credential's end when it is a scoped one, a personal token's.
 * A grant's columns are what a use decides on (`scopeDefinition`), its role
 * only a name: they are held to the role, never the name alone.
 */
export function weighIssue(
  input: IssueTokenInput,
  scope: CredentialScope,
  holder: Holdings,
  places: readonly (Place | null)[],
  via: CredentialColumns | null,
  at: number,
  service: { setting: ServiceSetting | null; account: ServiceAccount } | null,
): string | null {
  const { actor, principal, credential } = input;
  if (credential.createdBy !== actor.slice(actor.indexOf(':') + 1)) return 'a token names who made it, its issuer';
  if (places.some((place) => place === null)) return 'a place the token names is no longer there';
  const at_ = places as readonly Place[];
  const policy = holder.policy ?? DEFAULT_POLICY;
  // Each column within the role, and, for a person's own, within what the holder holds at the place, through the credential it came in on.
  const held = (grant: ScopeGrant, place: Place, roles: Policy) => {
    const columns = heldColumns(holder, place);
    const { permissions, protected: guarded } = scopeDefinition(grant);
    return ofRole(grant, roles) && permissions.every((p) => columns.normal.includes(p)) && guarded.every((p) => columns.protected.includes(p));
  };
  // Whether it came in on a scoped credential (a personal token's, a handle's, a connected app's) or a session: the
  // credential's object seals its scope, never its row's kind, so the vault decides on that (R53).
  const scoped = holder.credentialScope != null;
  switch (credential.kind) {
    case 'service':
      if (credential.expiresAt > at + MAX_SERVICE_TOKEN_DAYS * 86_400_000 + CLOCK_SLACK_MS) return `a service token lasts at most ${MAX_SERVICE_TOKEN_DAYS} days`;
      return weighService(actor, principal, scope, holder, at_, service);
    case 'personal': {
      if (principal !== actor || !actor.startsWith('user:')) return 'a personal token is its person\'s own';
      if (scoped) return 'a personal token is made on a session: a token never makes another';
      if (credential.expiresAt > at + MAX_PERSONAL_TOKEN_MINUTES * 60_000 + CLOCK_SLACK_MS) return 'a personal token lasts at most a week';
      if (scope.some((grant) => !delegable(grant.role, policy))) return 'a personal token never manages access';
      if (scope.some((grant, i) => !held(grant, at_[i]!, policy))) return 'a personal token reaches at most what its role and its person hold';
      return null;
    }
    case 'handle': {
      if (principal !== actor || !actor.startsWith('user:')) return 'a handle is its person\'s own';
      // A scoped credential's end bounds it (the app makes one on a personal token alone); a session's does not: a
      // handle a run holds outlives the sign-in that made it.
      if (credential.expiresAt > at + MAX_PERSONAL_TOKEN_MINUTES * 60_000 + CLOCK_SLACK_MS || (scoped && via !== null && via.expiresAt !== null && credential.expiresAt > via.expiresAt)) {
        return 'a handle lasts at most a week, and never past the token that made it';
      }
      if (scope.some((grant) => grant.role !== 'viewer' && grant.role !== 'contributor')) return 'a handle reads or uses, as a viewer or a contributor';
      // Made for environments, each named: never a project's, which would reach the environments it gains later.
      if (scope.some((grant) => grant.environmentId == null)) return 'a handle reaches environments, each by name';
      const reached = new Set(scope.map((grant) => grant.environmentId));
      const places = handlePlaces(credential.places);
      if (places === null || places.some(({ environmentId }) => !reached.has(environmentId))) return 'a handle stands in for environments its scope reaches';
      if (scope.some((grant, i) => !held(grant, at_[i]!, HANDLE_POLICY))) return 'a handle reads and uses at most what its person holds, through what it was made on';
      return null;
    }
  }
}

/** Each column of `grant` within its role as `roles` defines it: what `issuedGrant` keeps of it at most. */
function ofRole(grant: ScopeGrant, roles: Policy): boolean {
  const role = definitionOf(roles, grant.role);
  const { permissions, protected: guarded } = scopeDefinition(grant);
  return role !== undefined && permissions.every((p) => role.permissions.includes(p)) && guarded.every((p) => role.protected.includes(p));
}

/**
 * Whether `actor`, as the vault read them (`holder`), may give service
 * account `principal` a grant of `scope` (`places`, by its environments'
 * slugs): a service token's issue, or a trust binding's, whose sign-ins
 * reach the same (PR 3a). Null if so, or why not. A person gives it, as the
 * app's `managedAccount` has it, who manages the account and could give it
 * each grant, which the account holds (`issuesCredential`; R15); each
 * grant's columns within its role; sensitive reads only where they are an
 * Owner of the project (`ownsProject`, R32).
 */
export function weighService(
  actor: string,
  principal: string,
  scope: CredentialScope,
  holder: Holdings,
  places: readonly Place[],
  service: { setting: ServiceSetting | null; account: ServiceAccount } | null,
): string | null {
  if (!principal.startsWith('token:') || service === null) return 'a service account\'s access is a service account\'s';
  // No service account or workload sets one up.
  if (!actor.startsWith('user:')) return 'only a person gives a service account its access';
  const policy = holder.policy ?? DEFAULT_POLICY;
  if (scope.some((grant) => !ofRole(grant, policy))) return 'a service account\'s grant keeps at most what each of its roles holds';
  const grants = scope.map((grant, i) => ({ role: grant.role, place: places[i]!, kept: scopeDefinition(grant) }));
  if (!issuesCredential(holder, service.setting, actor, service.account, grants)) return 'a credential reaches at most what its account holds and what its issuer could give it';
  if (scope.some((grant) => grant.sensitive === true && !ownsProject(holder, grant.projectId!))) return 'only an Owner of its project gives a service account sensitive reads (R32)';
  return null;
}

/** A handle's places as the app writes them (`HandlePlace[]`: each environment it was made for, by id, and whether as `@me`), or null for none such. */
function handlePlaces(stored: string | null): { environmentId: string; personal: boolean }[] | null {
  let parsed: unknown = null;
  try {
    parsed = stored === null ? null : JSON.parse(stored);
  } catch {}
  if (!Array.isArray(parsed) || parsed.length === 0) return null;
  const places = parsed as { environmentId?: unknown; personal?: unknown }[];
  return places.every((place) => typeof place === 'object' && place !== null && typeof place.environmentId === 'string' && UUID.test(place.environmentId) && typeof place.personal === 'boolean')
    ? (places as { environmentId: string; personal: boolean }[])
    : null;
}

/** The issue, sealed: the credential's object, its seal, its change's payload and MAC. */
export function issueCall(keys: ChangeKeys, input: IssueTokenInput, read: IssueRead): IssueCall {
  const { credential: c } = input;
  const ref: Ref = { kind: 'credential', id: c.id };
  const object = credentialObject({ id: c.id, principal: input.principal, kind: c.kind, scope: c.scope, revoked: false, expiresAt: c.expiresAt, generation: input.generation });
  const op: Op = { op: 'credential.issue', principal: input.principal, caller: object.caller, scope: object.scope, expiresAt: object.expiresAt, generation: object.generation };
  // What the change records of the issue besides (D147): who, on which credential, which kind, its label.
  const payload = canonical({ ...JSON.parse(payloadOf(ref, op)), issue: { by: input.actor, via: input.via, kind: c.kind, label: c.label } });
  const seal = sealOf(keys.seals[0]!, ref, object);
  const row = { at: read.at, requestId: randomUUID(), object: objectKey(ref), actor: input.actor, payload, seal };
  return {
    change: { ...row, mac: entryMac(keys.mac, { tree: 'changes', row }) }, input, read,
    tokenHash: Buffer.from(c.tokenHash, 'base64'), authMac: Buffer.from(c.authMac, 'base64'),
  };
}

/** The issue's statement, on the engine `db` is. */
export async function issueToken(db: Database, call: IssueCall): Promise<Answer> {
  if (engineOf(db) === 'sqlite') return db.transaction((tx) => issueOnSqlite(tx, call));
  try {
    return await issueOnPostgres(db, call);
  } catch (error) {
    if (isBusy(error)) return { state: 'busy' };
    throw error;
  }
}

// --- a service's bindings (PR 3a) -----------------------------------------------

/** A change of bindings as the vault decided it: the statement's arguments, and each object's change in order. */
export type BindingsCall = {
  at: number;
  actor: string;
  principal: string;
  /** The binding made, its seal; and its maker's standing as read (`IssueRead`): null for an unbind. */
  make: { row: MadeBinding; authMac: Buffer; seal: Buffer; read: IssueRead; via: string | null; connection: ChangeBindingsInput['connection'] } | null;
  /** A binding with no seal (`sealFrom` null) is ended with no change, its `seal` null. */
  ends: { id: string; macFrom: Buffer; sealFrom: Buffer | null; authMac: Buffer; seal: Buffer | null }[];
  /** A credential with no seal (`sealFrom` null) is ended with no change, its `seal` null. */
  credentials: { id: string; binding: string; macFrom: Buffer; sealFrom: Buffer | null; authMac: Buffer; seal: Buffer | null }[];
  live: string[] | null;
  reads: { id: string; key: string }[];
  revokedAt: number;
  revokedBy: string;
  policy: { seq: string | null; slugs: { environmentId: string; slug: string | null }[] };
  appKey: string;
  changes: { requestId: string; object: string; payload: string; seal: Buffer; mac: Buffer }[];
};

/** The shape of a change of bindings as the app sends it; throws on one no app of this release sends. */
export function checkChangeBindings(input: ChangeBindingsInput): void {
  const { actor, via, actorAccess, make, live, reads, ends, reason, revokedAt, revokedBy, policy, appKey } = input ?? ({} as ChangeBindingsInput);
  const member = /^(user:[^\s]{1,320}|token:[a-z0-9][a-z0-9._-]{0,99})$/;
  const named = (before: { columns?: unknown; seal?: unknown } | undefined) => before !== undefined && isBase64(before.seal, 16);
  if (typeof actor !== 'string' || !member.test(actor) || (via !== null && (typeof via !== 'string' || !UUID.test(via)))
    || (actorAccess !== null && (typeof actorAccess !== 'string' || !/^-?[0-9]{1,19}$/.test(actorAccess)))
    || !Array.isArray(ends) || (make === null && ends.length === 0) || !['replaced', 'keys_moved', 'unbound'].includes(reason)
    || typeof revokedAt !== 'number' || !Number.isSafeInteger(revokedAt) || typeof revokedBy !== 'string' || !isPolicy(policy) || policy === null
    || typeof appKey !== 'string' || !/^app:[A-Za-z0-9_-]{1,64}$/.test(appKey)
    || (make === null) !== (live === null) || (live !== null && (!Array.isArray(live) || !live.every((id) => typeof id === 'string' && UUID.test(id))))
    || !Array.isArray(reads) || !reads.every((read) => typeof read?.id === 'string' && UUID.test(read.id) && typeof read.key === 'string')
    || (input.connection !== null && (typeof input.connection?.id !== 'string' || !UUID.test(input.connection.id) || !Number.isInteger(input.connection.generation)))) {
    throw new Error('a change of bindings names who makes it, on what, the binding it makes and those beside it, those it ends, why, when, the policy weighed, and the app\'s key');
  }
  // Each object once: a binding or a credential named twice would be two changes of it, the second one the replay refuses.
  const ids = [...(make === null ? [] : [make.id]), ...ends.map((end) => end?.before?.columns?.id), ...ends.flatMap((end) => (end?.credentials ?? []).map((credential) => credential?.before?.columns?.id))];
  if (new Set(ids).size !== ids.length) throw new Error('a change of bindings names each binding and credential once');
  if (make !== null) {
    checkBinding(make);
    if (make.revoked || (make.jwks !== null && typeof make.jwks !== 'string') || (make.label !== null && typeof make.label !== 'string') || typeof make.createdBy !== 'string'
      || !isBase64(make.authMac, 32) || make.scope === null || !Number.isSafeInteger(make.createdAt)) {
      throw new Error('a binding made is live, has a scope, names its keys, label and maker, and carries the app\'s MAC');
    }
  }
  for (const end of ends) {
    if (end?.before === undefined || (end.before.seal !== null && !isBase64(end.before.seal, 16)) || !isBase64(end.authMacFrom, 32) || !isBase64(end.authMac, 32) || !Array.isArray(end.credentials)) {
      throw new Error('a binding ended is named as read, with its seal, the app\'s MACs before and after, and the credentials it issued');
    }
    checkBinding(end.before.columns);
    for (const credential of end.credentials) {
      const before = credential?.before;
      if (before === undefined || (before.seal !== null && !isBase64(before.seal, 16)) || typeof before.columns?.id !== 'string' || !isBase64(credential.authMacFrom, 32) || !isBase64(credential.authMac, 32)) {
        throw new Error('a credential a binding ended issued is named as read, with its seal and the app\'s MACs before and after');
      }
    }
  }
}

/**
 * The change, sealed: the binding made (`binding.make`), each ended
 * (`binding.revoke`), and each credential they issued (`credential.revoke`),
 * each object's seal over what it becomes and its change's MAC. A binding
 * or credential with no seal (0.14's, which the log never held) is ended
 * with no change, which the statement holds to its having none; one whose
 * seal is not the vault's, or not over its columns, is `tampered`, and so
 * is a credential of another binding, or account.
 */
export function bindingsCall(
  keys: ChangeKeys, input: ChangeBindingsInput, at: number, read: IssueRead | null,
): BindingsCall | { refused: 'tampered' } {
  const { actor, make, ends, reason } = input;
  const principal = make?.principal ?? ends[0]!.before.columns.principal;
  const changes: BindingsCall['changes'] = [];
  const change = (ref: Ref, payload: string, seal: Buffer) => {
    const row = { at, requestId: randomUUID(), object: objectKey(ref), actor, payload, seal };
    changes.push({ requestId: row.requestId, object: row.object, payload, seal, mac: entryMac(keys.mac, { tree: 'changes', row }) });
  };
  let made: BindingsCall['make'] = null;
  if (make !== null) {
    const ref: Ref = { kind: 'binding', id: make.id };
    const value = bindingObject(make);
    const seal = sealOf(keys.seals[0]!, ref, value);
    // What the change records besides (D147): who made it, on which credential, its label, and those it replaces.
    change(ref, canonical({ ...JSON.parse(payloadOf(ref, { op: 'binding.make', value })), bind: { by: actor, via: input.via, label: make.label, replaces: ends.map((end) => end.before.columns.id) } }), seal);
    made = { row: make, authMac: Buffer.from(make.authMac, 'base64'), seal, read: read!, via: input.via, connection: input.connection };
  }
  const ended: BindingsCall['ends'] = [];
  const swept: BindingsCall['credentials'] = [];
  const sweeps: (() => void)[] = [];
  for (const end of ends) {
    const { columns } = end.before;
    const ref: Ref = { kind: 'binding', id: columns.id };
    if (columns.principal !== principal || columns.revoked) return { refused: 'tampered' };
    if (end.before.seal === null) {
      // One 0.14 made, which the log never held: its row ended, with no change; the statement holds it to having none (review r2).
      ended.push({ id: columns.id, macFrom: Buffer.from(end.authMacFrom, 'base64'), sealFrom: null, authMac: Buffer.from(end.authMac, 'base64'), seal: null });
    } else {
      const sealFrom = Buffer.from(end.before.seal, 'base64');
      const before = bindingObject(columns);
      if (!sealed(keys.seals, ref, before, sealFrom)) return { refused: 'tampered' };
      const seal = sealOf(keys.seals[0]!, ref, applyOp(before, ref, { op: 'binding.revoke' })!);
      change(ref, canonical({ ...JSON.parse(payloadOf(ref, { op: 'binding.revoke' })), unbind: { by: actor, reason, replacedBy: make?.id ?? null } }), seal);
      ended.push({ id: columns.id, macFrom: Buffer.from(end.authMacFrom, 'base64'), sealFrom, authMac: Buffer.from(end.authMac, 'base64'), seal });
    }
    for (const credential of end.credentials) {
      const cref: Ref = { kind: 'credential', id: credential.before.columns.id };
      if (credential.before.columns.principal !== principal || credential.before.columns.revoked) return { refused: 'tampered' };
      // One with no seal is none of the log's: ended, its row revoked, with no change (the statement holds it to having none).
      if (credential.before.seal === null) {
        swept.push({ id: cref.id, binding: columns.id, macFrom: Buffer.from(credential.authMacFrom, 'base64'), sealFrom: null, authMac: Buffer.from(credential.authMac, 'base64'), seal: null });
        continue;
      }
      const cfrom = Buffer.from(credential.before.seal, 'base64');
      const now = credentialObject(credential.before.columns);
      if (!sealed(keys.seals, cref, now, cfrom)) return { refused: 'tampered' };
      const cseal = sealOf(keys.seals[0]!, cref, applyOp(now, cref, { op: 'credential.revoke' })!);
      // Each after the bindings', in the order named.
      sweeps.push(() => change(cref, canonical({
        ...JSON.parse(payloadOf(cref, { op: 'credential.revoke' })),
        revoke: { reason: 'unbound', via: null, kind: credential.before.columns.kind, principal, binding: columns.id },
      }), cseal));
      swept.push({ id: cref.id, binding: columns.id, macFrom: Buffer.from(credential.authMacFrom, 'base64'), sealFrom: cfrom, authMac: Buffer.from(credential.authMac, 'base64'), seal: cseal });
    }
  }
  for (const sweep of sweeps) sweep();
  return {
    at, actor, principal, make: made, ends: ended, credentials: swept, live: input.live, reads: input.reads, revokedAt: input.revokedAt, revokedBy: input.revokedBy,
    policy: { seq: input.policy.seq, slugs: read?.slugs ?? input.policy.protected }, appKey: input.appKey, changes,
  };
}

/** The change's statement, on the engine `db` is. */
export async function changeBindings(db: Database, call: BindingsCall): Promise<Answer> {
  if (engineOf(db) === 'sqlite') return db.transaction((tx) => bindingsOnSqlite(tx, call));
  try {
    return await bindingsOnPostgres(db, call);
  } catch (error) {
    if (isBusy(error)) return { state: 'busy' };
    throw error;
  }
}
