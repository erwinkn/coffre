import { timingSafeEqual } from 'node:crypto';

import type { Access, CredentialAcceptance, SecretColumns, WriteKeysInput } from '@coffre/core/vault';

import { credentialEnded, keyRefusals, readerOf, sensitiveRefusals, useOnlyRefusals, type Reader } from './decide.ts';
import { noEdits, sealed, type CredentialInput, type EnvironmentInput, type Input, type PolicyInput, type PrincipalInput, type Ref, type RolesInput, type SealKeys, type SecretInput } from './inputs.ts';
import { entryMac, type ChangeRow, type LogMacKey } from './log-entry.ts';
import { configObject, credentialObject, environmentObject, memberStanding, principalObject } from './objects.ts';

/**
 * A key write in five round trips (T179 PR 3; docs/design/two-trips.md, "A key write", "The read and its hold";
 * formal/Writing.tla): the vault's side. Its one statement (`write_request`, migration 0060) reads everything the
 * decision weighs, in one snapshot under the fence shared, and numbers the request; the Worker decides on that read and
 * nothing else (DecideOnRead), and the app's transaction holds the same read again under the fence before it writes
 * (`hold_inputs`, ReadHeld). The read is one text, whose SHA-256 (the digest) the changes the Worker prepares carry.
 *
 * Served only for what this path holds whole: a patch of new values in an environment of its own (no fork, no
 * personal config) over keys that are live values or none, by a credential the vault's seals bear out. Anything else,
 * a refusal included, is `unserved`, and the request goes down today's path, which answers it, logged, as ever.
 *
 *   Ada's PATCH market/dev { API_KEY: "sk-…" }   write_request   the read, the number          one round trip
 *                                                 the Worker      decides, wraps, prepares       none
 */

export { callWrite, type WriteCall, type WriteRead } from './write.postgres.ts';

/** A row of `log_changes` as `to_jsonb` renders it: bytes as `\x`-hex. */
type RawChange = { number: number | string; at: number | string; request_id: string; object: string; actor: string; payload: string; seal: string | null; mac: string };

/** One object as the read has it: its row (null: none), the seal on it, and its newest change, whole. */
type Held<T extends Input> = { row: T | null; seal: Buffer | null; newest: ChangeRow | null };

/** A key as the read has it: by the name asked, its row (archived or not), its object, and its version's number. */
export type ReadKey = {
  name: string;
  /** Its row: none for a key the place does not hold. */
  id: string | null;
  archived: boolean;
  /** Its current version's id and number: none for a key with no value of its own (a reference, or one ended). */
  versionId: string | null;
  version: number;
  object: Held<SecretInput>;
};

/**
 * The read (`write_inputs`), parsed: the only data the decision takes (two-trips.md, "Why the read is complete by
 * construction"), made here and nowhere else.
 */
export type WriteInputs = {
  credential: Held<CredentialInput> & { kind: string | null; createdBy: string | null; identityId: string | null; identity: { provider: string; issuerHash: string; revoked: boolean } | null };
  principal: Held<PrincipalInput> & { access: bigint | null };
  roles: Held<RolesInput>;
  policy: Held<PolicyInput>;
  environment: Held<EnvironmentInput>;
  keys: ReadKey[];
};

const bytes = (hex: string | null | undefined): Buffer | null => (hex == null ? null : Buffer.from(hex.replace(/^\\x/, ''), 'hex'));
const base64Of = (hex: unknown): string => Buffer.from(String(hex), 'hex').toString('base64');

function changeOf(raw: RawChange | null | undefined): ChangeRow | null {
  if (raw == null) return null;
  return {
    number: BigInt(raw.number), at: Number(raw.at), requestId: raw.request_id, object: raw.object, actor: raw.actor, payload: raw.payload,
    seal: bytes(raw.seal), mac: bytes(raw.mac)!,
  };
}

type Raw = {
  credential: { row: Record<string, unknown>; expires: number | string | null; newest: RawChange | null } | null;
  identity: Record<string, unknown> | null;
  principal: { row: Record<string, unknown> | null; grants: Record<string, unknown>[]; access: number | string | null; newest: RawChange | null } | null;
  roles: { value: string | null; seal: string | null; newest: RawChange | null };
  policy: { value: string | null; seal: string | null; newest: RawChange | null };
  project: Record<string, unknown> | null;
  environment: { row: Record<string, unknown>; newest: RawChange | null } | null;
  secrets: { key: string; row: Record<string, unknown> | null; version: Record<string, unknown> | null; newest: RawChange | null }[];
};

/** The read's text as the decision takes it. */
export function parseInputs(text: string): WriteInputs {
  const raw = JSON.parse(text) as Raw;
  const c = raw.credential?.row ?? null;
  const credential: WriteInputs['credential'] = c === null
    ? { row: null, seal: null, newest: null, kind: null, createdBy: null, identityId: null, identity: null }
    : {
      row: credentialObject({
        id: String(c.id), principal: String(c.principal), kind: String(c.kind), scope: c.scope == null ? null : String(c.scope),
        revoked: c.revoked_at != null, expiresAt: raw.credential!.expires == null ? null : Number(raw.credential!.expires), generation: Number(c.generation),
      }),
      seal: bytes(c.seal as string | null),
      newest: changeOf(raw.credential!.newest),
      kind: String(c.kind),
      createdBy: c.created_by == null ? null : String(c.created_by),
      identityId: c.identity_id == null ? null : String(c.identity_id),
      identity: raw.identity === null ? null : { provider: String(raw.identity.provider), issuerHash: String(raw.identity.issuer_hash), revoked: raw.identity.revoked_at != null },
    };
  const m = raw.principal?.row ?? null;
  const principalId = c === null ? null : String(c.principal);
  const principal: WriteInputs['principal'] = {
    row: m === null || principalId === null ? null : principalObject(
      { principal: principalId, status: String(m.status), generation: Number(m.generation), ...memberStanding({ owner: m.owner === true, role: m.role as string | null, scope: m.scope as string | null }) },
      (raw.principal?.grants ?? []).map((g) => ({
        projectId: g.resolved_project == null ? null : String(g.resolved_project), environmentId: g.environment_id == null ? null : String(g.environment_id),
        environmentSlug: g.environment_slug == null ? null : String(g.environment_slug), role: String(g.role), expiresAt: g.expires_at == null ? null : Number(g.expires_at),
      })),
    ),
    seal: m === null ? null : bytes(m.seal as string | null),
    newest: changeOf(raw.principal?.newest),
    access: raw.principal?.access == null ? null : BigInt(raw.principal.access),
  };
  const config = <T extends Input>(part: Raw['roles']): Held<T> => ({ row: part.value === null ? null : (configObject(part.value) as T), seal: bytes(part.seal), newest: changeOf(part.newest) });
  const e = raw.environment?.row ?? null;
  const environment: Held<EnvironmentInput> = {
    row: e === null ? null : environmentObject({
      id: String(e.id), projectId: String(e.project_id), slug: String(e.slug), owner: e.owner == null ? null : String(e.owner), parentId: e.parent_id == null ? null : String(e.parent_id),
      protected: e.protected == null ? null : e.protected === true, archived: e.archived_at != null, projectArchived: raw.project?.archived_at != null,
    }),
    seal: e === null ? null : bytes(e.seal as string | null),
    newest: changeOf(raw.environment?.newest),
  };
  const keys = raw.secrets.map(({ key, row, version, newest }): ReadKey => {
    const id = row === null ? null : String(row.id);
    const archived = row !== null && row.archived_at != null;
    const versionId = row === null || row.current_version_id == null ? null : String(row.current_version_id);
    // Its object as a use reads it: an archived key is none (`secret.delete`), as is one with no value of its own here
    // (a reference, which this path does not serve: `unserved` below, before its object is weighed).
    const object: SecretInput | null = row === null || archived || version === null ? null : {
      kind: 'secret', id: id!, projectId: String(row.project_id), environmentId: String(row.environment_id), version: String(version.id),
      nature: version.sensitive === true ? 'sensitive' : version.digest != null ? 'plain' : 'secret',
      key: version.digest != null ? null : { kekProvider: String(version.kek_provider), kekId: String(version.kek_id), kekVersion: String(version.kek_version), bytes: base64Of(version.wrapped_dek) },
      digest: version.digest == null ? null : base64Of(version.digest), source: null, reference: null,
    };
    return {
      name: key, id, archived, versionId, version: row === null ? 0 : Number(row.current_version),
      object: { row: object, seal: row === null ? null : bytes(row.seal as string | null), newest: changeOf(newest) },
    };
  });
  return { credential, principal, roles: config<RolesInput>(raw.roles), policy: config<PolicyInput>(raw.policy), environment, keys };
}

/** Why the vault does not serve a write so, which goes down today's path: said in the vault's log only by that path's own entries. */
export type Unserved =
  | 'credential' // no credential of the token, one its config does not accept, or one of a kind this path leaves out
  | 'forged' // the caller's own credential, not as its log has it: a row put back, or its newest change's MAC broken (401, never today's path)
  | 'tampered' // a newest change whose MAC does not hold (T190)
  | 'stale' // a row its object's newest change does not seal (StaleFirst), or 0.14's access entry the log does not account for
  | 'place' // no such place, or one this path leaves out (archived, deleted, a fork, a personal config)
  | 'shape' // a key this path leaves out: archived, a reference, a value replaced since it was listed
  | 'refused'; // the decision refuses: today's path refuses it too, and logs the refusal

/** What the write is decided as: the caller, and each key's id, whether the write makes it, and its sensitivity. */
export type WriteDecided = {
  credential: CredentialInput;
  principal: PrincipalInput;
  reader: Reader;
  environment: EnvironmentInput;
  keys: { name: string; id: string; created: boolean; sensitive: boolean; before: ReadKey }[];
};

/** A newest change's MAC, under any of the vault's keys, as `#onLog` checks a member's (T190's `changeHolds`). */
export function changeMacHolds(macs: readonly LogMacKey[], row: ChangeRow): boolean {
  return macs.some((key) => {
    const made = entryMac(key, { tree: 'changes', row });
    return made.length === row.mac.length && timingSafeEqual(made, row.mac);
  });
}

/**
 * The decision, on the read alone (DecideOnRead), in the order the use path takes: every newest change held to its MAC
 * (T190, ChangeMacChecked) and each row to its newest change's seal (StaleFirst), before anything a row says; then what
 * the app would refuse of the credential (AcceptedFirst: its config's `accepts`, its kind, its end at the vault's
 * clock); then the place and the keys this path serves; then 0.14's rules for `secret.write` at the place
 * (`keyRefusals`, on the reader its principal, credential, roles and place make: `readerOf`), and a key's sensitivity,
 * which a write saying nothing keeps (`bareLevel` in the app: sensitive where the value it replaces is, else a secret).
 */
export function decideWrite(
  keys: { seals: SealKeys; macs: readonly LogMacKey[] },
  read: WriteInputs,
  request: { at: number; accepts: CredentialAcceptance; kinds: readonly string[]; asked: readonly { name: string; id: string; replaces?: string | null }[] },
): WriteDecided | Unserved {
  const { credential, principal, roles, policy, environment } = read;
  if (credential.row === null || credential.kind === null || !request.kinds.includes(credential.kind)) return 'credential';
  // An exchanged token's issuing binding is the app's to check, a read this path does not make: today's path.
  if (credential.createdBy?.startsWith('binding:') === true) return 'credential';
  // What the deployment's config accepts (AcceptedFirst, as `use_resolve` holds a named use's token to it).
  if (!request.accepts.signin) return 'credential';
  if (credential.kind === 'browser' && (credential.identity === null || !request.accepts.issuers.includes(`${credential.identity.provider}:${credential.identity.issuerHash}`))) return 'credential';
  if (credential.identity?.revoked === true) return 'credential';
  if (environment.row === null) return 'place';
  const objects: { held: Held<Input>; ref: Ref }[] = [
    { held: credential, ref: { kind: 'credential', id: credential.row.id } },
    { held: principal, ref: { kind: 'principal', id: credential.row.principal } },
    { held: roles, ref: { kind: 'roles', id: 'instance' } },
    { held: policy, ref: { kind: 'policy', id: 'instance' } },
    { held: environment, ref: { kind: 'environment', id: environment.row.id } },
    ...read.keys.flatMap((key) => (key.id === null ? [] : [{ held: key.object as Held<Input>, ref: { kind: 'secret' as const, id: key.id } }])),
  ];
  // Every newest change's MAC first: its seal is only what a writer could not have written once it holds (T190). Then
  // each row's seal: the vault's over the row, and the one its object's newest change left (StaleFirst).
  const holds = ({ held }: { held: Held<Input> }) => held.newest === null || changeMacHolds(keys.macs, held.newest);
  const stands = ({ held, ref }: { held: Held<Input>; ref: Ref }) => {
    const newest = held.newest?.seal ?? null;
    const valid = held.row === null ? held.seal === null : sealed(keys.seals, ref, held.row, held.seal);
    const current = held.row === null ? newest === null : held.seal !== null && newest !== null && held.seal.equals(newest);
    return valid && current;
  };
  // The caller's own credential first, which no other path may then answer for: a session revoked and its row put back
  // live (WritingTamper's dbw), whose MAC the app's check would find whole, is refused here, never written on.
  if (!holds(objects[0]!) || !stands(objects[0]!)) return 'forged';
  if (!objects.every(holds)) return 'tampered';
  if (!objects.every(stands)) return 'stale';
  // 0.14's newest access entry about the principal, which its newest change must account for (UsesSeeOldWrites).
  const old = oldOf(principal.newest);
  if (principal.access !== null && (old === null || principal.access > old)) return 'stale';
  if (principal.row === null || policy.row === null) return 'credential';
  if (credentialEnded(credential.row, principal.row, request.at)) return 'credential';
  const place = environment.row;
  if (place.deleted || place.archived || place.projectArchived || place.owner !== null || place.parentId !== null) return 'place';
  const reader = readerOf(principal.row, credential.row, roles.row ?? noEdits(), [place], request.at);
  const decided: WriteDecided['keys'] = [];
  for (const [i, asked] of request.asked.entries()) {
    const key = read.keys[i];
    if (key === undefined || key.name !== asked.name) throw new Error("write_inputs answers the keys in the order they were asked");
    // Archived, a reference or ended, or not the place's own: today's path refuses it or ends it, logged. A plain value
    // too: its object binds its text, which the read leaves out, by its digest.
    if (key.id !== null && (key.archived || key.versionId === null || key.object.row === null || key.object.row.environmentId !== place.id || key.object.row.nature === 'plain')) return 'shape';
    // A regenerate replaces the version it was listed with, or nothing (409 `stale`, on today's path).
    if (asked.replaces !== undefined && asked.replaces !== key.versionId) return 'shape';
    decided.push({ name: key.name, id: key.id ?? asked.id, created: key.id === null, sensitive: key.object.row?.nature === 'sensitive', before: key });
  }
  const secrets = decided.map(({ id }) => ({ projectId: place.projectId, environmentId: place.id, secretId: id }));
  const environments = new Map([[place.id, { projectId: place.projectId, slug: place.slug, owner: place.owner, parentId: place.parentId, deleted: place.deleted, archived: place.archived || place.projectArchived }]]);
  let codes = keyRefusals(reader, { principal: credential.row.principal, permission: 'secret.write', secrets, at: secrets, environments, needs: secrets.map(() => ['secret.write'] as const) });
  codes = useOnlyRefusals(codes, reader, { action: 'key.wrap', secrets });
  codes = sensitiveRefusals(codes, reader, { action: 'key.wrap', principal: credential.row.principal, secrets: decided.map(({ sensitive }) => ({ projectId: place.projectId, sensitive })) });
  if (codes.some((code) => code !== null)) return 'refused';
  return { credential: credential.row, principal: principal.row, reader, environment: place, keys: decided };
}

/** The 0.14 access entry a principal's newest change accounts for (`old` in its payload), if it names one. */
function oldOf(change: ChangeRow | null): bigint | null {
  if (change === null) return null;
  try {
    const old = (JSON.parse(change.payload) as { old?: unknown }).old;
    return typeof old === 'number' || typeof old === 'string' ? BigInt(old) : null;
  } catch {
    return null;
  }
}

/** The kinds of credential whose writes this path serves: a person's sessions and tokens, and a service's token; never a workload's, nor a handle's. */
export const WRITE_KINDS: readonly string[] = ['browser', 'cli', 'personal', 'service'];

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A write as the app asks it, checked: what no caller of the vault's sends is a bug of the app's, which fails the call. */
export function validateWriteKeys(input: WriteKeysInput): void {
  const text = (value: unknown) => typeof value === 'string' && value.length > 0;
  if (!text(input?.tokenHash) || Buffer.from(input.tokenHash, 'base64').length !== 32) throw new Error('a write names its token by its hash, 32 bytes, base64');
  if (typeof input.accepts?.signin !== 'boolean' || !Array.isArray(input.accepts.issuers) || input.accepts.issuers.some((issuer) => typeof issuer !== 'string')) {
    throw new Error("a write says what credentials the app accepts: whether it signs in, and its providers' issuers");
  }
  if (!text(input.project) || !text(input.environment)) throw new Error('a write names its place by its slugs');
  if (!Array.isArray(input.keys) || input.keys.length === 0 || new Set(input.keys.map((key) => key?.name)).size !== input.keys.length) {
    throw new Error('a write names each of its keys once, and one at least');
  }
  for (const key of input.keys) {
    if (!text(key.name) || !UUID.test(key.id) || !UUID.test(key.versionId) || Buffer.from(key.key ?? '', 'base64').length !== 32) {
      throw new Error("a write's key comes with its name, the ids it takes and a fresh 32-byte data key");
    }
    if (key.replaces !== undefined && key.replaces !== null && !UUID.test(key.replaces)) throw new Error('a regenerate names the version it replaces by its id');
  }
}

/** A key's columns as the read found them, which its change is made from (`prepareChanges`): a live value of its own. */
export function secretColumnsOf(key: ReadKey): SecretColumns {
  const object = key.object.row!;
  return {
    id: object.id, projectId: object.projectId, environmentId: object.environmentId, source: null, reference: null,
    version: {
      id: object.version, sensitive: object.nature === 'sensitive', plaintext: null,
      kekProvider: object.key!.kekProvider, kekId: object.key!.kekId, kekVersion: object.key!.kekVersion, wrappedDek: object.key!.bytes,
    },
  };
}

/**
 * What the write decided the caller holds, as `access` answers it and as a named use's `standingOf` makes it: their
 * standing, role, scope and live grants, and the policy as far as the place it weighed, which is all the app checks of
 * them after (the route's permission there).
 */
export function writeStanding(decided: WriteDecided, at: number): Access {
  const { live, status } = decided.reader;
  return {
    principal: decided.credential.principal,
    status,
    generation: decided.principal.generation,
    role: live.role,
    scope: live.scope,
    grants: decided.principal.grants.filter((grant) => grant.expiresAt === null || grant.expiresAt > at)
      .map(({ projectId, environmentId, role, expiresAt }) => ({ projectId, environmentId, role, expiresAt })),
    since: null,
    by: null,
    ...(live.policy === undefined ? {} : { policy: live.policy }),
  } as Access;
}
