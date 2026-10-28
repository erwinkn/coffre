import { randomUUID } from 'node:crypto';

import { sealedSessionScope } from '@coffre/core/access';
import { POLICY_DEFAULTS, POLICY_FIELDS, type BindingPolicy, type WorkloadProfile } from '@coffre/core/identity';
import type { CredentialColumns, RevokeCredentialInput, RevokeCredentialOutcome, SignInCredential, SignInInput, SignInOutcome, SignInRefusal } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { engineOf } from '@coffre/db/dialect';

import { NotLogged, payloadOf, type ChangeKeys } from './changes.ts';
import { applyOp, canonical, objectKey, sealed, sealOf, type Op, type Ref } from './inputs.ts';
import { revokeOnPostgres, signInOnPostgres } from './credentials.postgres.ts';
import { revokeOnSqlite, signInOnSqlite } from './credentials.sqlite.ts';
import { entryMac } from './log-entry.ts';
import { credentialObject } from './objects.ts';

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

/** How long a CI run's credential lives (`EXCHANGED_CREDENTIAL_MS`), and a workload's session past each renewal (`SESSION_MS`). */
export const RUN_CREDENTIAL_MS = 5 * 60 * 1000;
export const SESSION_MS = 60 * 60 * 1000;

/** The longest a session's hard end may be, past its sign-in: the most `sessionHours` takes (workloads.ts's policy check). */
const LONGEST_SESSION_HOURS = 168;

/** What the change of a sign-in records besides its op (D147): its binding, proof, issuer, the run's claims, and a session's key and hard end. */
type SignInRecord = { binding: string; proof: string; issuer: string; run: Record<string, string | number>; jkt?: string; notAfter?: number };

/** A sign-in as the vault decided it: the statement's arguments. */
export type SignInCall = {
  requestId: string; at: number; actor: string; payload: string; mac: Buffer; seal: Buffer;
  binding: SignInInput['binding']; principal: string; spent: Buffer | null; validUntil: number | null; frozen: boolean; longest: number;
  /** At most `rate` credentials a binding makes in `window` ms. */
  rate: number; window: number;
  credential: SignInCredential & { createdBy: string; tokenHashBytes: Buffer; authMacBytes: Buffer };
};

/** The statement's answer: its change's number, or why it made nothing. */
export type Answer = { number?: string | null; state?: SignInRefusal | 'moved' | 'stale' };

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
  const { principal, binding, credential, spent, validUntil, record } = input ?? ({} as SignInInput);
  if (typeof principal !== 'string' || !/^token:[a-z0-9][a-z0-9._-]{0,99}$/.test(principal)) throw new Error('a sign-in is a service account\'s, token:<id>');
  if (typeof binding?.id !== 'string' || !Number.isInteger(binding.generation) || typeof binding.profile !== 'string'
    || (binding.scope !== null && typeof binding.scope !== 'string') || (binding.policy !== null && typeof binding.policy !== 'string')) {
    throw new Error('a sign-in names its binding: its id, generation, profile, scope and policy as read');
  }
  checkCredential(credential);
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
    longest = RUN_CREDENTIAL_MS;
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
    binding, principal, spent: spent === null ? null : Buffer.from(spent, 'base64'), validUntil, frozen: credential.kind === 'workload', longest, rate: SIGN_INS_PER_WINDOW, window: SIGN_IN_WINDOW_MS,
    credential: { ...credential, createdBy: `binding:${binding.id}`, tokenHashBytes: Buffer.from(credential.tokenHash, 'base64'), authMacBytes: Buffer.from(credential.authMac, 'base64') },
  };
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

/** A run's claims as the change records them: a few short strings and numbers (workloads.ts's `runClaims`). */
function isRun(run: unknown): run is Record<string, string | number> {
  if (typeof run !== 'object' || run === null || Array.isArray(run)) return false;
  const entries = Object.entries(run);
  return entries.length <= 16 && entries.every(([key, value]) => key.length <= 64 && ((typeof value === 'string' && value.length <= 256) || (typeof value === 'number' && Number.isFinite(value))));
}

/**
 * A revoke, decided and made: the object as the app read it, checked
 * against its seal (`NotLogged`, tampered, if the vault never made it), the
 * revoke applied and sealed, then one statement. A row 0.14 made and the
 * log never held is revoked with no change, as `prepare` leaves one.
 */
export async function revokeCredential(db: Database, keys: ChangeKeys, at: number, input: RevokeCredentialInput): Promise<Answer> {
  const { actor, before, authMacFrom, authMac, revokedAt, revokedBy, reason, via } = input ?? ({} as RevokeCredentialInput);
  const columns = before?.columns;
  if (typeof actor !== 'string' || actor.length === 0 || typeof columns?.id !== 'string' || typeof columns.principal !== 'string' || columns.revoked !== false
    || (before.seal !== null && !isBase64(before.seal, 16)) || !isBase64(authMacFrom, 32) || !isBase64(authMac, 32)
    || typeof revokedAt !== 'number' || !Number.isSafeInteger(revokedAt) || typeof revokedBy !== 'string' || (reason !== 'revoke' && reason !== 'sign_out')
    || (via !== null && typeof via !== 'string')) {
    throw new Error('a revoke names the credential as read, live, its seal, and the app\'s MACs before and after');
  }
  const ref: Ref = { kind: 'credential', id: columns.id };
  let change: { payload: string; seal: Buffer; sealFrom: Buffer; mac: Buffer; requestId: string } | null = null;
  if (before.seal !== null) {
    const now = credentialObject(columns);
    const sealFrom = Buffer.from(before.seal, 'base64');
    if (!sealed(keys.seals, ref, now, sealFrom)) throw new NotLogged(ref, 'tampered');
    const after = applyOp(now, ref, { op: 'credential.revoke' })!;
    const seal = sealOf(keys.seals[0]!, ref, after);
    // What a revoke's record says besides (D147): why, the credential the request came in on, and whose credential of what kind it ends.
    const payload = canonical({ ...JSON.parse(payloadOf(ref, { op: 'credential.revoke' })), revoke: { reason, via, kind: columns.kind, principal: columns.principal } });
    const row = { at, requestId: randomUUID(), object: objectKey(ref), actor, payload, seal };
    change = { payload, seal, sealFrom, requestId: row.requestId, mac: entryMac(keys.mac, { tree: 'changes', row }) };
  }
  const call: RevokeCall = { at, actor, ref, change, macFrom: Buffer.from(authMacFrom, 'base64'), mac: Buffer.from(authMac, 'base64'), revokedAt, revokedBy };
  if (engineOf(db) === 'sqlite') return db.transaction((tx) => revokeOnSqlite(tx, call));
  try {
    return await revokeOnPostgres(db, call);
  } catch (error) {
    if (isBusy(error)) return { state: 'busy' };
    throw error;
  }
}

export type RevokeCall = {
  at: number; actor: string; ref: Ref; macFrom: Buffer; mac: Buffer; revokedAt: number; revokedBy: string;
  change: { payload: string; seal: Buffer; sealFrom: Buffer; mac: Buffer; requestId: string } | null;
};


