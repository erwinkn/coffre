import { createHash, createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

import { INSTANCE_ROLES, normalDefinition, ROLES, type CallerKind, type CredentialScope, type InstanceRole, type RoleDefinition, type Scope } from '@coffre/core/access';
import type { WrappedKey } from '@coffre/core/vault';

import { MAX_BULK_WINDOW_MINUTES, type BulkLimit } from './config.ts';

/**
 * Every input a decision reads, as one object of the log, sealed (0.15,
 * docs/design/sealed-inputs.md). Nothing calls this yet: it is the pure
 * code that the change path, the use path and the verifier will share.
 *
 * - **principal:** a member, their instance role and its scope, and every
 *   grant they hold, lapsed ones included.
 * - **credential:** a session, token or binding: whose it is, what kind,
 *   its scope, its end, and whether it was revoked.
 * - **secret:** a key's current version: where it is, its nature, its
 *   wrapped data key, or, for a reference, its source.
 * - **environment:** its project and slug, whether it is protected, a
 *   fork's parent, a personal config's owner, and whether it was deleted.
 * - **roles:** the role tables, as an Owner edited them.
 * - **policy:** what the deployment set that every decision reads: the
 *   bulk cap's count and window (R52).
 *
 * Each object's row carries its **seal**, the vault's HMAC-SHA256 over it
 * cut to 16 bytes, and each change records the seal it leaves. A row is
 * `tampered` if its seal is not the vault's over it, and `stale` if it is
 * not the seal of its object's newest change: a row put back from before a
 * revoke, validly sealed once, is refused.
 */

/** A principal's grant, as its object holds it: where, which role, and until when (null: for good). */
export type InputGrant = {
  projectId: string | null;
  environmentId: string | null;
  /** A grant on every project of 0.4: the one environment slug it covers in each, if any. */
  environmentSlug: string | null;
  role: string;
  expiresAt: number | null;
};

export type PrincipalInput = {
  kind: 'principal';
  principal: string;
  status: 'active' | 'removed';
  role: InstanceRole;
  scope: Scope;
  grants: readonly InputGrant[];
};

export type CredentialInput = {
  kind: 'credential';
  id: string;
  principal: string;
  caller: CallerKind;
  /** Past which nothing reaches; null for a session's. */
  scope: CredentialScope | null;
  expiresAt: number | null;
  revoked: boolean;
};

export type Nature = 'plain' | 'secret' | 'sensitive';

export type SecretInput = {
  kind: 'secret';
  id: string;
  projectId: string;
  environmentId: string;
  /** Its current version. */
  version: string;
  nature: Nature;
  /** The version's data key, wrapped; null for a plain value, which the vault never opens, and for a reference. */
  key: WrappedKey | null;
  /** A reference's source, by its key's id: its value and nature are the source's now (R23). */
  source: string | null;
};

export type EnvironmentInput = {
  kind: 'environment';
  id: string;
  projectId: string;
  slug: string;
  /** A personal config's owner (`<env>@me`). */
  owner: string | null;
  /** A fork's or a personal config's parent. */
  parentId: string | null;
  protected: boolean;
  deleted: boolean;
  archived: boolean;
};

/**
 * An Owner's edits of the roles, and the roles they made: only what differs
 * from the release's own tables, which a decision merges them over
 * (`readerOf`), as 0.14's `livePolicy` does. A release that changes a role
 * as it ships changes it wherever nobody edited it, and the log, which
 * never held the shipped tables, replays the same under any release.
 */
export type RolesInput = {
  kind: 'roles';
  roles: Readonly<Record<string, RoleDefinition>>;
  instanceRoles: Readonly<Partial<Record<InstanceRole, RoleDefinition>>>;
};

export type PolicyInput = { kind: 'policy'; bulk: BulkLimit };

export type Input = PrincipalInput | CredentialInput | SecretInput | EnvironmentInput | RolesInput | PolicyInput;
export type Kind = Input['kind'];

/** An object of the log: its kind and its id (the instance's own for the roles and the policy, of which there is one each). */
export type Ref = { kind: Kind; id: string };

export const ROLES_REF: Ref = { kind: 'roles', id: 'instance' };
export const POLICY_REF: Ref = { kind: 'policy', id: 'instance' };

export function refOf(input: Input): Ref {
  switch (input.kind) {
    case 'principal': return { kind: 'principal', id: input.principal };
    case 'roles': return ROLES_REF;
    case 'policy': return POLICY_REF;
    default: return { kind: input.kind, id: input.id };
  }
}

/**
 * An object's key in the log: the first 16 bytes of SHA-256 over its kind
 * and id, as a uuid. Fixed-width, so a probe of the changes by object is
 * about a fifth cheaper than on the text it names (W211, #366), and the same for every kind of id: a principal is text,
 * the others uuids. Anyone computes it: SQL with `sha256()`.
 */
export function objectKey(ref: Ref): string {
  return logObject(ref.kind, ref.id);
}

/** `objectKey` for any kind, the log's own included (`log_object` in SQL): a retention change's is ('log', 'retention'). */
export function logObject(kind: string, id: string): string {
  const hex = createHash('sha256').update(`coffre.object.v1\0${kind}\0${id}`).digest('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/** The keys seals are made under, derived from the vault's signing keys, the first sealing and every one checking. */
export type SealKeys = readonly Buffer[];

export function sealKey(signingKey: Uint8Array): Buffer {
  return Buffer.from(hkdfSync('sha256', signingKey, new Uint8Array(0), 'coffre.vault.seals.v1', 32));
}

/** A seal's length: HMAC-SHA256 cut to 128 bits (R53), as truncation guidance allows. */
export const SEAL_BYTES = 16;

/**
 * An object's seal: HMAC-SHA256 over the object it is filed under, kind
 * and id, and its canonical encoding, cut to 16 bytes. The id is the
 * key's, not the row's, so a row filed under another object's key is not
 * that object's, however valid its seal is over itself.
 */
export function sealOf(key: Buffer, ref: Ref, input: Input): Buffer {
  return createHmac('sha256', key).update(`coffre.seal.v1\0${ref.kind}\0${ref.id}\0`).update(canonical(normalized(input))).digest().subarray(0, SEAL_BYTES);
}

/** Whether `seal` is the vault's over `input`, filed under `ref`, by any of its keys. */
export function sealed(keys: SealKeys, ref: Ref, input: Input, seal: Buffer | null): boolean {
  if (seal === null || seal.length !== SEAL_BYTES) return false;
  return keys.some((key) => timingSafeEqual(sealOf(key, ref, input), seal));
}

/**
 * An object as its seal covers it: a principal's grants as a set, in one
 * order whatever order the rows come back in. Everything else is kept as
 * written: a credential's scope is a list it was issued with.
 */
function normalized(input: Input): Input {
  if (input.kind !== 'principal') return input;
  const grants = input.grants.map((grant) => [grant, canonical(grant)] as const).sort(([, a], [, b]) => (a < b ? -1 : a > b ? 1 : 0));
  return { ...input, grants: grants.map(([grant]) => grant) };
}

/**
 * JSON with every object's keys sorted, and undefined fields left out:
 * one encoding for one value, whichever way its row was read back.
 */
export function canonical(value: unknown): string {
  return JSON.stringify(value, (_, v: unknown) => (
    v !== null && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v).filter(([, x]) => x !== undefined).sort(([a], [b]) => (a < b ? -1 : 1)))
      : v
  ));
}

// --- changes ------------------------------------------------------------------

/** Where a grant is, as a revoke names it. */
export type GrantPlace = Pick<InputGrant, 'projectId' | 'environmentId' | 'environmentSlug'>;

/**
 * What a change does to its object, as logged and as the change path
 * applies it (PR 4's `change_input`). `genesis` writes a whole object as a
 * row has it: the cutover's, once per object, and each adoption of a late
 * 0.14 write (plan, PR 9). Every change to the policy carries the whole
 * policy as its `value`, genesis or `bulk.limit`, so a use's statement reads
 * the cap from the newest one at one path (`value.bulk`, schema 0022's
 * `use_credential`: the spec's `CapSealed`).
 */
export type Op =
  | { op: 'genesis'; value: Input }
  | { op: 'member.add'; role: InstanceRole; scope: Scope }
  | { op: 'member.role'; role: InstanceRole; scope: Scope }
  | { op: 'member.remove' }
  | { op: 'member.restore'; role: InstanceRole; scope: Scope }
  | { op: 'access.grant'; grant: InputGrant }
  | { op: 'access.revoke'; place: GrantPlace }
  | { op: 'credential.issue'; principal: string; caller: CallerKind; scope: CredentialScope | null; expiresAt: number | null }
  | { op: 'credential.revoke' }
  /** A live credential's end moved: a workload's session renewed (never past its hard end, the app's to hold). */
  | { op: 'credential.renew'; expiresAt: number | null }
  /** A live credential's scope written: a token of 0.4's, which carried none, sealed to what its account held (`token.seal`). */
  | { op: 'credential.scope'; scope: CredentialScope | null }
  | { op: 'secret.write'; projectId: string; environmentId: string; version: string; nature: Nature; key: WrappedKey | null; source: string | null }
  | { op: 'secret.delete' }
  | { op: 'environment.create'; projectId: string; slug: string; owner: string | null; parentId: string | null; protected: boolean }
  | { op: 'environment.protect'; protected: boolean }
  | { op: 'environment.rename'; slug: string }
  | { op: 'environment.archive'; archived: boolean }
  | { op: 'environment.delete' }
  | { op: 'role.define'; table: 'roles' | 'instanceRoles'; role: string; definition: RoleDefinition | null }
  | { op: 'bulk.limit'; value: PolicyInput };

/** Every object, by its key: the rows a decision reads, as the log has them. */
export type State = Map<string, Input>;

export function lookup<K extends Kind>(state: ReadonlyMap<string, Input>, kind: K, id: string): Extract<Input, { kind: K }> | null {
  const input = state.get(objectKey({ kind, id }));
  return input?.kind === kind ? (input as Extract<Input, { kind: K }>) : null;
}

/**
 * A change applied to its object: what the object is after it (null: gone),
 * or `undefined` if it does nothing, which the change path never logs: a
 * create of something that exists, a change to something that does not, an
 * op of another kind's, or a limit R52 does not allow.
 */
export function applyOp(before: Input | null, ref: Ref, op: Op): Input | null | undefined {
  // The object, if it is of the kind the change is about: what every change but a create works on.
  const of = <K extends Kind>(kind: K) => (ref.kind === kind && before?.kind === kind ? (before as Extract<Input, { kind: K }>) : null);
  const created = (kind: Kind) => ref.kind === kind && before === null;
  // The roles and the policy are one object each: a change to another of their kind does nothing.
  if ((ref.kind === 'roles' || ref.kind === 'policy') && ref.id !== ROLES_REF.id) return undefined;
  switch (op.op) {
    case 'genesis': {
      // A whole object, held to what the ops that make one hold it to.
      const id = refOf(op.value);
      if (id.kind !== ref.kind || id.id !== ref.id) return undefined;
      if (op.value.kind === 'policy' && !allowedLimit(op.value.bulk)) return undefined;
      if (op.value.kind === 'credential' && !callerFits(op.value)) return undefined;
      return op.value;
    }
    case 'member.add':
      return created('principal') ? { kind: 'principal', principal: ref.id, status: 'active', role: op.role, scope: op.scope, grants: [] } : undefined;
    case 'member.role': {
      const member = of('principal');
      return member?.status === 'active' ? { ...member, role: op.role, scope: op.scope } : undefined;
    }
    case 'member.remove': {
      const member = of('principal');
      return member?.status === 'active' ? { ...member, status: 'removed' } : undefined;
    }
    case 'member.restore': {
      const member = of('principal');
      return member?.status === 'removed' ? { ...member, status: 'active', role: op.role, scope: op.scope } : undefined;
    }
    case 'access.grant': {
      const member = of('principal');
      return member === null ? undefined : { ...member, grants: [...member.grants.filter((grant) => !samePlace(grant, op.grant)), op.grant] };
    }
    case 'access.revoke': {
      const member = of('principal');
      if (member === null || !member.grants.some((grant) => samePlace(grant, op.place))) return undefined;
      return { ...member, grants: member.grants.filter((grant) => !samePlace(grant, op.place)) };
    }
    case 'credential.issue':
      return created('credential') && callerFits(op)
        ? { kind: 'credential', id: ref.id, principal: op.principal, caller: op.caller, scope: op.scope, expiresAt: op.expiresAt, revoked: false }
        : undefined;
    case 'credential.revoke': {
      const credential = of('credential');
      return credential !== null && !credential.revoked ? { ...credential, revoked: true } : undefined;
    }
    case 'credential.renew': {
      const credential = of('credential');
      return credential !== null && !credential.revoked ? { ...credential, expiresAt: op.expiresAt } : undefined;
    }
    case 'credential.scope': {
      const credential = of('credential');
      const scoped = credential === null || credential.revoked ? null : { ...credential, scope: op.scope };
      return scoped !== null && callerFits(scoped) ? scoped : undefined;
    }
    case 'secret.write': {
      const secret = of('secret');
      if (!created('secret') && secret === null) return undefined;
      // A key stays where it was made: a write elsewhere is another key.
      if (secret !== null && (secret.projectId !== op.projectId || secret.environmentId !== op.environmentId)) return undefined;
      const { projectId, environmentId, version, nature, key, source } = op;
      return { kind: 'secret', id: ref.id, projectId, environmentId, version, nature, key, source };
    }
    case 'secret.delete':
      return of('secret') === null ? undefined : null;
    case 'environment.create':
      return created('environment')
        ? { kind: 'environment', id: ref.id, projectId: op.projectId, slug: op.slug, owner: op.owner, parentId: op.parentId, protected: op.protected, deleted: false, archived: false }
        : undefined;
    case 'environment.protect': case 'environment.rename': case 'environment.archive': case 'environment.delete': {
      const environment = of('environment');
      if (environment === null || environment.deleted) return undefined;
      if (op.op === 'environment.protect') return { ...environment, protected: op.protected };
      // A scoped role's filters read the slug: a rename is a change like any other (0.14's `environment.update`).
      if (op.op === 'environment.rename') return { ...environment, slug: op.slug };
      return op.op === 'environment.archive' ? { ...environment, archived: op.archived } : { ...environment, deleted: true };
    }
    case 'role.define': {
      const edits = of('roles') ?? (created('roles') ? noEdits() : null);
      if (edits === null) return undefined;
      // A table with no prototype: a role named `__proto__` is a role like another, never the object's prototype.
      const table: Record<string, RoleDefinition> = Object.assign(Object.create(null) as Record<string, RoleDefinition>, edits[op.table]);
      const shipped: Readonly<Record<string, RoleDefinition>> = op.table === 'roles' ? ROLES : INSTANCE_ROLES;
      const same = op.definition !== null && Object.hasOwn(shipped, op.role) && canonical(normalDefinition(shipped[op.role]!)) === canonical(normalDefinition(op.definition));
      // No definition, or the one it ships with: no edit, so the release's own decides.
      if (op.definition === null || same) delete table[op.role];
      else table[op.role] = op.definition;
      return { ...edits, [op.table]: { ...table } };
    }
    case 'bulk.limit':
      return (created('policy') || of('policy') !== null) && op.value.kind === 'policy' && allowedLimit(op.value.bulk)
        ? { kind: 'policy', bulk: { count: op.value.bulk.count, windowMs: op.value.bulk.windowMs } }
        : undefined;
  }
}

/** No edits: the roles object of a log no Owner edited a role in. */
export function noEdits(): RolesInput {
  return { kind: 'roles', roles: {}, instanceRoles: {} };
}

/** A cap R52 allows: a whole count of at least one, a window above nothing and at most a day (`checkBulkLimit` in config.ts). */
function allowedLimit({ count, windowMs }: BulkLimit): boolean {
  return Number.isSafeInteger(count) && count >= 1 && Number.isSafeInteger(windowMs) && windowMs > 0 && windowMs <= MAX_BULK_WINDOW_MINUTES * 60_000;
}

/**
 * A credential its principal can hold (`through` in vault.ts): a person's
 * for a `user:`, a bearer's or a workload's for a `token:`, and a
 * workload's with the scope that lists what it reads.
 */
function callerFits({ principal, caller, scope }: { principal: string; caller: CallerKind; scope: CredentialScope | null }): boolean {
  if (caller === 'person') return principal.startsWith('user:');
  return principal.startsWith('token:') && (caller === 'bearer' || scope !== null);
}

function samePlace(a: GrantPlace, b: GrantPlace): boolean {
  return a.projectId === b.projectId && a.environmentId === b.environmentId && a.environmentSlug === b.environmentSlug;
}

/**
 * The change a vault starting with `configured` writes before it serves a
 * use, if any: the cap is the deployment's code, while decisions, live and
 * replayed, read the log's, so the two meet here (plan, PR 3). Null when
 * the log already says the same.
 */
export function limitChange(policy: PolicyInput | null, configured: BulkLimit): Op | null {
  // One no change would apply (a window of a fraction of a millisecond) must stop the start, not leave the log policy-less.
  if (!allowedLimit(configured)) throw new Error(`bulkLimit must be a whole count of at least 1 and a whole number of milliseconds up to a day, got ${JSON.stringify(configured)}`);
  if (policy !== null && policy.bulk.count === configured.count && policy.bulk.windowMs === configured.windowMs) return null;
  return limitOp(configured);
}

/** The change that sets the bulk cap: the whole policy, as its `value`. */
export function limitOp(bulk: BulkLimit): Op {
  return { op: 'bulk.limit', value: { kind: 'policy', bulk: { count: bulk.count, windowMs: bulk.windowMs } } };
}
