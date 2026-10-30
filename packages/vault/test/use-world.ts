// The 0.15 use path's fixture (use.test.ts, use-cost.test.ts): a world of sealed
// inputs, each made by its `genesis` change, and the change path as the owner
// plays it until PR 4 builds it: under the fence, each row and its change
// entry written together.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { encrypt, freshDek } from '@coffre/core/envelope';
import type { UseInput, UseOutcome } from '@coffre/core/vault';
import { tablesOf, type Database, type Queryable } from '@coffre/db';
import { sql } from 'drizzle-orm';

import type { Sealed } from '../src/checkpointer.ts';
import { resolveVaultConfig } from '../src/config.ts';
import { CUTOVER_OBJECT } from '../src/cutover.ts';
import { objectKey, sealKey, sealOf, type Input, type Op, type Ref } from '../src/inputs.ts';
import { entryMac, logMacKey } from '../src/log-entry.ts';
import { purposeOf, replay, type Logged } from '../src/log-replay.ts';
import { openVault, prepareVault, type VaultOptions } from '../src/vault.ts';
import { newRequestId } from '../src/use.ts';
import { ENGINE, rows, run, type TestDatabase } from './database.ts';

export const SIGNING_KEY = randomBytes(32);
/** The vault's key encryption key, as a configuration names it: a vault elsewhere (a Worker's) opens what this one wrapped. */
export const KEK = { id: 'use-test', key: randomBytes(32).toString('base64') };
export const CONFIG = resolveVaultConfig({
  kek: KEK,
  signingKey: SIGNING_KEY.toString('base64'),
  owners: ['root@acme.example'],
});
export const SEAL = sealKey(SIGNING_KEY);
/** The log's MAC key, as the change path, the use path and the checkpointer derive it. */
export const MAC = logMacKey(SIGNING_KEY);
export const ROOT = 'user:root@acme.example';
export const DAY = 86_400_000;
/** The fence's advisory lock (schema 0022): what a change takes exclusive. */
export const FENCE = sql`SELECT pg_advisory_xact_lock(1668244070, 0)`;

let db: TestDatabase;
let hot: Database;

/** The fixture's databases: the suite's, and the hot path's login on Postgres. */
export async function useDatabases(opened: TestDatabase): Promise<Database> {
  db = opened;
  hot = ENGINE === 'postgres' ? await db.hot() : db.vault;
  return hot;
}

/** The log as a new instance's: no change, no use, the floor a minute back, days of uses made around today. */
export async function emptyLog(): Promise<void> {
  for (const table of ['log_uses', 'log_bulk', 'log_changes', 'log_config']) await run(db.owner, sql.raw(`DELETE FROM ${table}`));
  await run(db.owner, sql`UPDATE log_fence SET at_floor = ${Date.now() - 60_000}`);
  if (ENGINE === 'postgres') {
    // Numbers from the start again: a test may have moved them past 2^53.
    await run(db.owner, sql`SELECT setval('log_number', 1, false)`);
    const today = new Date(Date.now()).toISOString().slice(0, 10);
    await run(db.owner, sql`SELECT make_day(${today}::date - 1), make_day(${today}::date), make_day(${today}::date + 1)`);
  }
}

/**
 * 0.15's log switched on. A use never waits for a seal (R51): the
 * checkpointer's `sealThrough` fails the test if asked, but for the
 * cutover's own change, which an isolate's first call waits for once.
 */
export const LOG_015: VaultOptions = {
  log: '0.15',
  sealThrough: async (number) => {
    if (number === cutoverNumber) return {} as Sealed;
    throw new Error('a use waited for a seal');
  },
  heldOutside: async () => [],
};

/** The cutover's change this fixture stands in for, by its number (`cutOverStandIn`). */
let cutoverNumber: bigint | null = null;

/** A vault of its own, a fresh isolate: its own seal cache, covers and admission count; and the vault, for its decisions. */
export async function isolate(options: VaultOptions = {}) {
  const prepared = await prepareVault(CONFIG, { ...LOG_015, ...options });
  const vault = openVault(db.vault, prepared, hot);
  return { use: (input: UseInput) => vault.use!(input), vault, cache: prepared.uses };
}

// --- the change path, as the owner plays it ---------------------------------------------------------

let number = 0;
export async function nextNumber(tx: Queryable): Promise<number> {
  if (ENGINE === 'postgres') return Number((await rows<{ n: string }>(tx, sql`SELECT nextval('log_number') AS n`))[0]!.n);
  const [row] = await rows<{ n: number }>(tx, sql`SELECT max(coalesce((SELECT max(number) FROM log_changes), 0), coalesce((SELECT max(number) FROM log_uses), 0)) + 1 AS n`);
  return Math.max(row!.n, ++number);
}

/**
 * One change: under the fence, the rows written as `write` does, and the
 * change's entry, sealing `after` (null: gone). `old`, for a principal: the
 * newest 0.14 access entry it accounts for (UsesSeeOldWrites).
 */
export async function change(ref: Ref, op: Op, after: Input | null, write: (tx: Queryable, seal: Buffer | null) => Promise<void>, old?: bigint): Promise<number> {
  const seal = after === null ? null : sealOf(SEAL, ref, after);
  return db.owner.transaction(async (tx) => {
    if (ENGINE === 'postgres') await run(tx, FENCE);
    await write(tx, seal);
    const n = await nextNumber(tx);
    const row = { at: Date.now(), requestId: randomUUID(), object: objectKey(ref), actor: ROOT, payload: JSON.stringify({ ...op, ...(old === undefined ? {} : { old: old.toString() }) }), seal };
    await run(tx, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
      VALUES (${n}, ${row.at}, ${row.requestId}, ${row.object}, ${row.actor}, ${row.payload}, ${row.seal}, ${entryMac(MAC, { tree: 'changes', row })})`);
    return n;
  });
}

export const seal = (table: string, key: string, id: string) => (tx: Queryable, value: Buffer | null) => run(tx, sql`UPDATE ${sql.raw(table)} SET seal = ${value} WHERE ${sql.raw(key)} = ${id}`);

/**
 * A sealed world: a project with `dev`, a member with a grant there, a
 * credential, a key with a value, the policy and the roles, each made by
 * its `genesis` change. What a use reads, and what the replay builds.
 */
export async function world(options: {
  count?: number; windowMs?: number; role?: string; caller?: 'person' | 'bearer';
  /** A person's browser session, signed in through this provider and issuer (its hash): `cli` otherwise. */
  identity?: { provider: string; issuerHash: string };
} = {}) {
  const t = tablesOf(db.owner);
  const project = randomUUID();
  const dev = randomUUID();
  const principal = options.caller === 'person' ? `user:${randomUUID().slice(0, 8)}@acme.example` : `token:${randomUUID().slice(0, 8)}`;
  const credentialId = randomUUID();
  const now = Date.now();
  await db.owner.insert(t.projects).values({ id: project, slug: `p-${project.slice(0, 8)}`, name: 'Project' });
  await db.owner.insert(t.environments).values({ id: dev, projectId: project, slug: 'dev', name: 'Development', protected: false });
  await db.owner.insert(t.vaultMembers).values({
    principal, status: 'active', role: null, scope: null, generation: 0, createdAt: now, createdBy: ROOT, statusChangedAt: now, statusChangedBy: ROOT,
    accessSeq: 0n, mac: Buffer.alloc(32),
  });
  await db.owner.insert(t.vaultGrants).values({ principal, projectId: null, environmentId: dev, environmentSlug: null, role: options.role ?? 'viewer', grantedAt: now, grantedBy: ROOT });
  const expiresAt = now + DAY;
  const identityId = options.identity === undefined ? null : randomUUID();
  if (options.identity !== undefined) {
    await db.owner.insert(t.identities).values({
      id: identityId!, provider: options.identity.provider, issuerHash: options.identity.issuerHash, authMac: Buffer.alloc(32), subject: randomUUID(), generation: 0,
      principal, createdBy: ROOT,
    });
  }
  await db.owner.insert(t.credentials).values({
    id: credentialId, kind: identityId !== null ? 'browser' : principal.startsWith('user:') ? 'cli' : 'service', authMac: Buffer.alloc(32), tokenHash: randomBytes(32),
    tokenHint: 'hint', generation: 0, principal, createdBy: ROOT, expiresAt: new Date(expiresAt), scope: null, identityId,
  });
  const caller = principal.startsWith('user:') ? 'person' as const : 'bearer' as const;
  const grant = { projectId: project, environmentId: dev, environmentSlug: null, role: options.role ?? 'viewer', expiresAt: null };
  const objects = {
    principal: { kind: 'principal', principal, status: 'active', generation: 0, role: 'member', scope: { projects: 'all', environments: 'all' }, grants: [grant] } as Input,
    credential: { kind: 'credential', id: credentialId, principal, caller, scope: null, expiresAt, revoked: false, generation: 0 } as Input,
    environment: { kind: 'environment', id: dev, projectId: project, slug: 'dev', owner: null, parentId: null, protected: false, deleted: false, archived: false, projectArchived: false } as Input,
  };
  // The instance's one policy and one roles object: the first world's, and the cutover's marker beside them.
  if ((await rows(db.owner, sql`SELECT 1 FROM log_config`)).length === 0) {
    await genesis({ kind: 'policy', id: 'instance' }, { kind: 'policy', bulk: { count: options.count ?? 1000, windowMs: options.windowMs ?? 15 * 60_000 } });
    await genesis({ kind: 'roles', id: 'instance' }, { kind: 'roles', roles: {}, instanceRoles: {} });
    await cutOverStandIn();
  }
  await genesis({ kind: 'principal', id: principal }, objects.principal);
  await genesis({ kind: 'credential', id: credentialId }, objects.credential);
  await genesis({ kind: 'environment', id: dev }, objects.environment);
  const keys: { id: string; value: string; object: Input }[] = [];
  /** A key in `dev`, or another environment of the project, with a value of its own, sealed. */
  const key = async (value = `value-${keys.length}`, sensitive = false, environment = dev) => {
    const id = randomUUID();
    const version = randomUUID();
    const dek = freshDek();
    const sealed = encrypt(Buffer.from(value), { projectId: project, environmentId: environment, secretId: id }, dek);
    const context = { projectId: project, environmentId: environment, secretId: id, ...(sensitive ? { sensitive: true as const } : {}) };
    const wrapped = await CONFIG.keks.wrap(dek, context, { deadline: Date.now() + 5000, signal: new AbortController().signal });
    await db.owner.insert(t.secrets).values({ id, projectId: project, environmentId: environment, key: `KEY_${keys.length}_${id.slice(0, 4)}` });
    await db.owner.insert(t.secretVersions).values({
      id: version, secretId: id, version: 1, envelopeVersion: sealed.envelopeVersion, ciphertext: sealed.ciphertext, iv: sealed.iv, authTag: sealed.authTag,
      wrappedDek: wrapped.bytes, kekProvider: wrapped.kekProvider, kekId: wrapped.kekId, kekVersion: wrapped.kekVersion, createdBy: ROOT, sensitive,
    });
    await run(db.owner, sql`UPDATE secrets SET current_version_id = ${version}, current_version = 1 WHERE id = ${id}`);
    const object: Input = {
      kind: 'secret', id, projectId: project, environmentId: environment, version, nature: sensitive ? 'sensitive' : 'secret',
      key: { kekProvider: wrapped.kekProvider, kekId: wrapped.kekId, kekVersion: wrapped.kekVersion, bytes: Buffer.from(wrapped.bytes).toString('base64') }, digest: null, source: null, reference: null,
    };
    await genesis({ kind: 'secret', id }, object);
    keys.push({ id, value, object });
    return id;
  };
  return { project, dev, principal, credentialId, objects, keys, key, grant };
}

/**
 * The cutover's change (plan PR 9), as this fixture stands in for it with its
 * own genesis changes: the marker a 0.15 vault waits for before it serves,
 * naming 0.14's head as it is.
 */
export async function cutOverStandIn(): Promise<void> {
  await db.owner.transaction(async (tx) => {
    if (ENGINE === 'postgres') await run(tx, FENCE);
    const [head] = await rows<{ next_seq: string | number; head_hash: Buffer | Uint8Array }>(tx, sql`SELECT next_seq, head_hash FROM audit_chain_head`);
    const anchor = { seq: (BigInt(head!.next_seq) - 1n).toString(), hash: Buffer.from(head!.head_hash).toString('hex') };
    const n = await nextNumber(tx);
    cutoverNumber = BigInt(n);
    const row = { at: Date.now(), requestId: randomUUID(), object: CUTOVER_OBJECT, actor: 'system:vault', payload: JSON.stringify({ op: 'cutover', anchor, from: anchor }), seal: null };
    await run(tx, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
      VALUES (${n}, ${row.at}, ${row.requestId}, ${row.object}, ${row.actor}, ${row.payload}, ${null}, ${entryMac(MAC, { tree: 'changes', row })})`);
  });
}

/** An object's first change, `genesis`, sealing its row as it is (or, for the roles and the policy, making it from its value). */
export async function genesis(ref: Ref, object: Input): Promise<void> {
  const op: Op = { op: 'genesis', value: object };
  const where: Record<string, [string, string]> = {
    principal: ['vault_members', 'principal'], credential: ['credentials', 'id'], environment: ['environments', 'id'], secret: ['secrets', 'id'],
    connection: ['mcp_connections', 'id'], binding: ['service_bindings', 'id'],
  };
  await change(ref, op, object, async (tx, value) => {
    if (ref.kind === 'roles' || ref.kind === 'policy') {
      await run(tx, sql`INSERT INTO log_config (name, value, seal) VALUES (${ref.kind}, ${JSON.stringify(object)}, ${value})`);
      return;
    }
    const [table, key] = where[ref.kind]!;
    await seal(table, key, ref.id)(tx, value);
  });
}

/** A use's input, its time now and its deadline 3 s on. */
export function ask(w: { credentialId: string }, secretId: string, extra: Partial<UseInput> = {}): UseInput {
  const at = Date.now();
  return { credential: w.credentialId, secretId, place: null, purpose: 'run', requestId: newRequestId(), at, deadline: at + 3000, ...extra };
}

/**
 * The log replayed (log-replay.ts) and each use's decision held to its live answer, read in number order: `refOf`
 * knows an object from its genesis, and the heap need not hold the rows so (a VACUUM frees the slots of the rows a
 * test deleted, and the next insert takes the first, ahead of rows written before it).
 */
export async function replayed(answered: ReadonlyMap<string, UseOutcome>): Promise<number> {
  const changes = await rows<{ number: string | number; at: string | number; object: string; payload: string; seal: Buffer | null }>(db.owner,
    sql`SELECT number, at, object, payload, seal FROM log_changes ORDER BY number`);
  const uses = await rows<{ number: string | number; at: string | number; credential: string; secret: string; purpose: number; place: string | null }>(db.owner,
    sql`SELECT number, at, credential, secret, purpose, place FROM log_uses ORDER BY number`);
  const refs = new Map<string, Ref>();
  const entries: Logged[] = [
    ...changes.map((row) => {
      const op = JSON.parse(row.payload) as Op & { old?: string };
      const ref = refOf(op, row.object, refs);
      return { kind: 'change' as const, number: BigInt(row.number), at: Number(row.at), ref, op: stripped(op), seal: row.seal === null ? null : Buffer.from(row.seal) };
    }),
    ...uses.map((row) => ({
      kind: 'use' as const, number: BigInt(row.number),
      request: { credential: row.credential, secretId: row.secret, place: row.place, at: Number(row.at), ...purposeOf(Number(row.purpose))! },
    })),
  ].sort((a, b) => (a.number < b.number ? -1 : 1));
  let checked = 0;
  const result = replay([SEAL], entries, (entry, code) => {
    const live = answered.get(entry.number.toString());
    if (live === undefined) return;
    // Live may refuse `stale` or `tampered` where the log allows (a row put back or edited, a late 0.14 write), never otherwise.
    if (!live.ok && 'code' in live && (live.code === 'stale' || live.code === 'tampered')) return;
    assert.equal(live.ok ? null : (live as { code: string }).code, code, `entry ${entry.number}: live and replay disagree`);
    checked += 1;
  });
  assert.deepEqual(result.faults, []);
  return checked;
}

function stripped(op: Op & { old?: string }): Op {
  const { old: _, ...rest } = op;
  return rest as Op;
}

/** The object a change is about: the kind and id its key is of, from a genesis's value or a ref seen before. */
function refOf(op: Op, key: string, seen: Map<string, Ref>): Ref {
  if (op.op === 'genesis') {
    const value = op.value;
    const ref: Ref = value.kind === 'principal' ? { kind: 'principal', id: value.principal } : value.kind === 'roles' || value.kind === 'policy' ? { kind: value.kind, id: 'instance' } : { kind: value.kind, id: value.id };
    assert.equal(objectKey(ref), key);
    seen.set(key, ref);
  }
  return seen.get(key)!;
}
