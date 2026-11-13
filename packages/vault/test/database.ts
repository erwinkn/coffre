import { randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';

import type { PairNotes } from '@coffre/core/merkle';
import type { ObjectChange, SecretRef, Through, WrappedKey } from '@coffre/core/vault';
import { createDatabase, type Database, type Queryable } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { appChanges, forgetLogHeads } from '@coffre/db/log';
import { and, eq, sql, type SQL } from 'drizzle-orm';

import { prepareChanges, type ChangeKeys } from '../src/changes.ts';
import type { Sealed, SealThrough } from '../src/checkpointer.ts';
import { sealKey } from '../src/inputs.ts';
import { openLocalVault as openRawVault, spoken, type SpokenVault as RawLocalVault } from '../src/local.ts';
import { logMacKey } from '../src/log-entry.ts';
import { auditChainHead, auditLog, credentials, dismissedKeys, environments, grants, logChanges, logConfig, passkeys, policy, principals, projects, proxyDefinitions, proxyReserved, roles, secretReferences, secrets, secretVersions, serviceBindings, spentIdTokens, vaultReleases } from '@coffre/db/schema';

/**
 * The suite's database, as the vault's tests use it: the one the server's
 * tests use, which scripts/test-suite.sh prepares. Opened twice: as its
 * owner, to set up places and play someone who edits rows, and as the
 * vault, which is the vault's own login.
 */
const name = process.env.COFFRE_TEST_DATABASE ?? 'coffre_test';
const url = (login: string) => `postgresql://${login}@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${name}`;
export const OWNER_URL = url('coffre_owner:local-dev-only');
export const VAULT_URL = url('coffre_vault_runtime:local-vault-only');
/** 0.15's hot path's login (schema 0022): the vault's, with its lock and statement timeouts and generic plans. */
export const HOT_URL = url('coffre_vault_hot:local-hot-only');
/** The app's runtime login: what it may call, it may call with any arguments. */
export const APP_URL = url('coffre_runtime:local-runtime-only');

/** A vault's input as a test writes it: its `caller` may be left out, for `speaking` to say. */
type Spoken<I> = I extends Through ? Omit<I, 'caller'> & Partial<Through> : I;

/** A vault whose calls may leave `caller` out (`speaking`). */
export type SpeakingVault<V> = { [K in keyof V]: V[K] extends (input: infer I) => infer R ? (I extends Through ? (input: Spoken<I>) => R : V[K]) : V[K] };

/**
 * `vault`, spoken to as the app does by a test about something other than
 * who asks: a call that leaves its `caller` out says the kind its acting
 * principal is, a person for `user:`, a bearer for `token:`. One about a
 * workload says so itself.
 */
export function speaking<V extends object>(vault: V): SpeakingVault<V> {
  return new Proxy(vault, {
    get(target, name) {
      const value: unknown = Reflect.get(target, name);
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => value.apply(target, [said(args[0]), ...args.slice(1)]);
    },
  }) as unknown as SpeakingVault<V>;
}

function said(input: unknown): unknown {
  if (typeof input !== 'object' || input === null || 'caller' in input) return input;
  const { actor, principal } = input as { actor?: unknown; principal?: unknown };
  const asking = typeof actor === 'string' ? actor : principal;
  return typeof asking === 'string' ? { ...input, caller: asking.startsWith('user:') ? 'person' : 'bearer' } : input;
}

/** The vault in this process, as the tests speak to it (`speaking`). */
export type LocalVault = SpeakingVault<RawLocalVault>;

/**
 * A checkpointer that seals everything at once: what a change waits on,
 * under 0.15's log, in a test with no tree. The vault answers nothing of
 * what it is given back.
 */
export const sealed: SealThrough = async () => ({}) as Sealed;

/** No pair held outside, as a signer that never signed: what a vault with no checkpointer is verified against. */
export const nothingHeld = async (): Promise<PairNotes[]> => [];

/**
 * `openLocalVault`, spoken to as the app does (`speaking`), its changes
 * sealed at once (`sealed`). The first since the database was emptied seals
 * the places a test wrote before it (`sealPlaces`), as the app would have
 * made them under its keys.
 */
export async function openLocalVault(...[db, config, options, close]: Parameters<typeof openRawVault>): Promise<LocalVault> {
  const vault = spoken(await openRawVault(db, config, { sealThrough: sealed, heldOutside: nothingHeld, ...options }, close));
  const first = placeKeys === null;
  placeKeys = { seals: config.signingKeys.map((key) => sealKey(key)), mac: logMacKey(config.signingKeys[0]!) };
  if (first && suiteOwner !== null) await sealPlaces(suiteOwner, await unsealedPlaces(suiteOwner));
  return speaking(vault);
}

/**
 * The keys the vault this process opened last seals with (`openLocalVault`):
 * what the fixtures seal the places they write with (`sealPlaces`); null
 * until the first since the database was emptied. The vault checks every
 * environment row it decides on against the log (T159).
 */
let placeKeys: ChangeKeys | null = null;

/** The suite's database as its owner (`openTestDatabase`), which seals places as the app's login would. */
let suiteOwner: Database | null = null;

/** The plain environments a test wrote with no seal and no change of 0.15's log: written before any vault opened. */
async function unsealedPlaces(owner: Database): Promise<{ id: string; projectId: string; slug: string; parentId: string | null }[]> {
  const found = await rows<{ id: string; project_id: string; slug: string; parent_id: string | null }>(owner, sql`SELECT e.id, e.project_id, e.slug, e.parent_id
    FROM environments e WHERE e.seal IS NULL AND e.owner IS NULL AND e.archived_at IS NULL AND e.protected IS NULL
      AND NOT EXISTS (SELECT 1 FROM log_changes l WHERE l.object = log_object('environment', e.id::text))`);
  return found.map((row) => ({ id: row.id, projectId: row.project_id, slug: row.slug, parentId: row.parent_id }));
}

/**
 * New environments' rows, written by a test, sealed as the app's creation
 * of each seals it (`Vault.prepare`, then `app_change` in a transaction of
 * its own), once a vault has opened.
 */
export async function sealPlaces(owner: Database, made: readonly { id: string; projectId: string; slug: string; parentId?: string | null }[]): Promise<void> {
  if (placeKeys === null || made.length === 0) return;
  const changes: ObjectChange[] = made.map(({ id, projectId, slug, parentId = null }) => ({
    kind: 'environment', id, before: null, after: { id, projectId, slug, owner: null, parentId, protected: null, archived: false, projectArchived: false },
  }));
  const calls = prepareChanges(placeKeys, Date.now(), 'user:root@acme.example', changes, new Map());
  const numbers = await owner.transaction((tx) => appChanges(tx, calls));
  assert.ok(numbers.every((number) => number !== null && number > 0n), 'a new environment is sealed as the app makes one');
}

export type TestDatabase = {
  owner: Database;
  vault: Database;
  connect(connections?: number): Promise<Database>;
  hot(connections?: number): Promise<Database>;
  release(): Promise<void>;
  close(): Promise<void>;
};

/**
 * The database as its owner and as the vault; `connect` opens one more as the vault, as a second instance would, with
 * up to `connections` at once (10 unless set). `connections`, each pool's own: a matrix that runs beside the others,
 * a process of its own each, keeps its share of Postgres's connections (forks.matrix.ts). `release` closes the pools
 * `connect` and `hot` opened so far, for a file whose tests each open their own (`afterEach`): a vault's start asks
 * its reads together, a pooled connection each on Node (T206), so a file that kept every test's pools open until it
 * ends would hold more than the 100 connections Postgres has for the four files that run at once.
 */
export async function openTestDatabase({ connections: pools }: { connections?: number } = {}): Promise<TestDatabase> {
  const opened: (() => Promise<void>)[] = [];
  let extra: (() => Promise<void>)[] = [];
  const open = async (login: string, connections?: number, into = extra): Promise<Database> => {
    const client = postgresClient(login, { max: connections ?? pools ?? 10 });
    into.push(() => client.end());
    return createDatabase(client);
  };
  const release = async () => {
    const closing = extra;
    extra = [];
    await Promise.all(closing.map((close) => close()));
  };
  const owner = await open(OWNER_URL, undefined, opened);
  suiteOwner = owner;
  return {
    owner,
    vault: await open(VAULT_URL, undefined, opened),
    connect: (connections) => open(VAULT_URL, connections),
    hot: (connections) => open(HOT_URL, connections),
    release,
    close: async () => {
      // A connection whose transaction a test left open is one no client's end lets go of (`endLeftOpen`).
      try {
        await endLeftOpen(owner);
      } finally {
        await Promise.all([release(), ...opened.map((close) => close())]);
      }
    },
  };
}

/**
 * `work`, as the owner, with the audit log's append-only triggers lifted,
 * as someone who rewrites it would: disabled for one transaction.
 */
export async function withLogUnlocked<T>(owner: Database, work: (db: Queryable) => Promise<T>): Promise<T> {
  return withTriggersLifted(owner, 'audit_log', work);
}

/** `work`, as the owner, with `table`'s triggers lifted (`withLogUnlocked`): a secret version's erase-only, say. */
export async function withTriggersLifted<T>(owner: Database, table: 'audit_log' | 'secret_versions' | 'log_changes', work: (db: Queryable) => Promise<T>): Promise<T> {
  return owner.transaction(async (tx) => {
    await tx.execute(sql.raw(`ALTER TABLE ${table} DISABLE TRIGGER USER`));
    const result = await work(tx);
    await tx.execute(sql.raw(`ALTER TABLE ${table} ENABLE TRIGGER USER`));
    return result;
  });
}

/** Rows of a raw query. */
export async function rows<Row>(db: Queryable, query: SQL): Promise<Row[]> {
  return [...await db.execute(query)] as Row[];
}

/** A raw statement. */
export async function run(db: Queryable, query: SQL): Promise<void> {
  await db.execute(query);
}

/**
 * How many of `pg_locks`'s rows match `where` (its `locktype`, `classid`,
 * `objid`, `mode`, `granted`), of this test's database's sessions alone.
 * The view is the cluster's: the files running beside this one take the
 * same advisory keys, and wait for locks, in clones of their own, and
 * counted here they would say this file's sessions hold or wait for what
 * they do not (T153).
 */
export async function locksHere(owner: Database, where: SQL): Promise<number> {
  const [row] = await rows<{ n: number }>(owner, sql`SELECT count(*)::int AS n FROM pg_locks JOIN pg_stat_activity USING (pid)
    WHERE datname = current_database() AND ${where}`);
  return row!.n;
}

/** How long a reset, or the file's `close`, waits for the transactions open in the test's database to end. */
const LEFT_OPEN_MS = 10_000;

/**
 * Every other transaction in the test's database ended, before
 * a reset and before the file closes its connections. One a test left open,
 * as a holder of the log's head it never let go of, having failed first,
 * would keep its locks and its connection for good: the reset would wait on
 * them, and the file's `close` on its connection, until CI's limit (T153).
 * Those still open after `LEFT_OPEN_MS` are ended, and the call fails,
 * naming what each ran last; the next test starts clean.
 */
async function endLeftOpen(owner: Database): Promise<void> {
  for (const until = Date.now() + LEFT_OPEN_MS; ; await sleep(50)) {
    const open = await rows<{ pid: number; usename: string; query: string }>(owner, sql`SELECT pid, usename, query FROM pg_stat_activity
      WHERE datname = current_database() AND backend_type = 'client backend' AND pid <> pg_backend_pid() AND xact_start IS NOT NULL`);
    if (open.length === 0) return;
    if (Date.now() < until) continue;
    await run(owner, sql`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid IN (${sql.join(open.map(({ pid }) => sql`${pid}`), sql`, `)})`);
    throw new Error(`a test left ${open.length} transaction(s) open for over ${LEFT_OPEN_MS} ms, now ended: ${open.map(({ usename, query }) => `${usename}: ${query.trim()}`).join('; ')}`);
  }
}

/** The reads' projection of 0.15's log (T166), gone with the log, its cursor back at the start: another log's, under another key, otherwise. */
export async function emptyReads(owner: Database): Promise<void> {
  await run(owner, sql`DELETE FROM log_reads`);
  await run(owner, sql`DELETE FROM log_read_days`);
  await run(owner, sql`DELETE FROM log_read_place_days`);
  await run(owner, sql`INSERT INTO log_reads_cursor (only_row, through, pair, at, mac) VALUES (true, 0, 0, 0, NULL) ON CONFLICT (only_row) DO UPDATE SET through = 0, pair = 0, at = 0, mac = NULL`);
  // The audit projection at its start: nothing listed of any log.
  await run(owner, sql`TRUNCATE audit_events, audit_event_places, audit_member_keys`);
  await run(owner, sql`INSERT INTO audit_cursor (only_row, through, pair, at, old_floor, old_from, old_top, old_hash, mac, reads_from)
    VALUES (true, 0, 0, 0, 0, 0, 0, ${Buffer.alloc(32)}, NULL, 0) ON CONFLICT (only_row) DO UPDATE SET through = 0, pair = 0, at = 0, old_floor = 0,
    old_from = 0, old_top = 0, old_hash = excluded.old_hash, mac = NULL, reads_from = 0`);
}

/** Everything a vault test leaves behind, gone, and the heads this process remembers forgotten. */
export async function emptyDatabase(owner: Database): Promise<void> {
  await endLeftOpen(owner);
  // A new instance: the next vault opened decides the keys its places are sealed with.
  placeKeys = null;
  await owner.delete(secretReferences);
  await withLogUnlocked(owner, async (db) => {
    await db.update(auditLog).set({ relatedSeq: null });
    await db.delete(auditLog);
  });
  await owner.update(auditChainHead).set({ nextSeq: 0n, headHash: Buffer.alloc(32) });
  // Kept from the log, and gone with it.
  await owner.delete(vaultReleases);
  // 0.15's log, which only the change path writes.
  await owner.delete(logChanges);
  await owner.delete(logConfig);
  await owner.delete(policy);
  await owner.delete(roles);
  await owner.delete(proxyDefinitions);
  await owner.delete(proxyReserved);
  await emptyReads(owner);
  await owner.delete(grants);
  // A session a test made, for a use to name; a binding a sign-in came through, and the tokens it spent (credentials.test.ts).
  await owner.delete(credentials);
  // A passkey a session names (issue.test.ts), gone after the sessions and before its person.
  await owner.delete(passkeys);
  await owner.delete(serviceBindings);
  await owner.delete(spentIdTokens);
  await owner.delete(principals);
  await owner.delete(dismissedKeys);
  await owner.update(secrets).set({ currentVersionId: null });
  await run(owner, sql`DELETE FROM secret_versions`);
  await owner.delete(secrets);
  await owner.delete(environments);
  await owner.delete(projects);
  forgetLogHeads();
}

/**
 * An environment renamed or archived as the app does it: its change sealed
 * (`Vault.prepare`) and written beside the row in one transaction
 * (`app_change`); before a vault has opened, the row alone.
 */
export async function changePlace(owner: Database, id: string, set: { slug?: string; archived?: boolean }): Promise<void> {
  const write = (db: Queryable) => run(db, sql`UPDATE environments SET slug = coalesce(${set.slug ?? null}, slug),
    archived_at = ${set.archived === undefined ? sql`archived_at` : set.archived ? sql`${new Date()}` : sql`NULL`} WHERE id = ${id}`);
  if (placeKeys === null) return write(owner);
  const [row] = await rows<{ project_id: string; slug: string; owner: string | null; parent_id: string | null; protected: boolean | null; archived: boolean; project_archived: boolean; seal: Buffer | Uint8Array | null }>(owner,
    sql`SELECT e.project_id, e.slug, e.owner, e.parent_id, e.protected, e.archived_at IS NOT NULL AS archived, p.archived_at IS NOT NULL AS project_archived, e.seal
      FROM environments e JOIN projects p ON p.id = e.project_id WHERE e.id = ${id}`);
  assert.ok(row !== undefined, `no environment ${id}`);
  const columns = {
    id, projectId: row.project_id, slug: row.slug, owner: row.owner, parentId: row.parent_id, protected: row.protected === null ? null : Boolean(row.protected),
    archived: Boolean(row.archived), projectArchived: Boolean(row.project_archived),
  };
  const before = { columns, seal: row.seal === null ? null : Buffer.from(row.seal).toString('base64') };
  const after = { ...columns, slug: set.slug ?? columns.slug, archived: set.archived ?? columns.archived };
  const calls = prepareChanges(placeKeys, Date.now(), 'user:root@acme.example', [{ kind: 'environment', id, before, after }], new Map());
  const numbers = await owner.transaction(async (tx) => {
    await write(tx);
    return appChanges(tx, calls);
  });
  assert.ok(numbers.every((number) => number !== null && number > 0n), 'an environment is changed as the app changes one');
}

/**
 * A project with two environments, and secrets in them on demand, as the app would have made them; `sealed: false`, its
 * rows as 0.14's log alone holds them, for a test that stands in for the cutover itself.
 */
export async function places(owner: Database, { sealed: seal = true }: { sealed?: boolean } = {}) {
  const project = await newProject(owner);
  const [dev, prod] = [randomUUID(), randomUUID()];
  await owner.insert(environments).values([
    { id: dev, projectId: project, slug: 'dev', name: 'Development' },
    { id: prod, projectId: project, slug: 'prod', name: 'Production' },
  ]);
  if (seal) await sealPlaces(owner, [{ id: dev, projectId: project, slug: 'dev' }, { id: prod, projectId: project, slug: 'prod' }]);
  let n = 0;
  /** A new secret's ref, its row committed. */
  const secret = async (environmentId: string, key = 'DATABASE_URL'): Promise<SecretRef> => {
    const id = randomUUID();
    await owner.insert(secrets).values({ id, projectId: project, environmentId, key: `${key}_${++n}` });
    return { projectId: project, environmentId, secretId: id, version: 1, path: `${projectSlug(project)}/${environmentId === dev ? 'dev' : 'prod'}/${key}_${n}` };
  };
  return { project, dev, prod, secret };
}

/**
 * A project's slug from its id: `p-` and 30 hex digits (about 116 random bits), so no two collide across the thousands
 * of worlds one database holds (the first 8 digits did, now and then: T223), and 32 characters, the longest a route's
 * name may be, for a test that names a route for its project.
 */
export const projectSlug = (id: string) => `p-${id.replaceAll('-', '').slice(0, 30)}`;

/** A project of its own, with one environment, for a grant somewhere else. */
export async function newProject(owner: Database): Promise<string> {
  const id = randomUUID();
  await owner.insert(projects).values({ id, slug: projectSlug(id), name: 'Project' });
  return id;
}

export async function newEnvironment(owner: Database, projectId: string): Promise<string> {
  const id = randomUUID();
  await owner.insert(environments).values({ id, projectId, slug: `e-${id.slice(0, 8)}`, name: 'Environment' });
  await sealPlaces(owner, [{ id, projectId, slug: `e-${id.slice(0, 8)}` }]);
  return id;
}

/** Commit fixture versions, as the app would, before asking the vault to open them. */
export async function storedVersions(owner: Database, items: { secret: SecretRef; wrapped: WrappedKey }[]): Promise<{ secretVersionId: string }[]> {
  return Promise.all(items.map(async ({ secret, wrapped }) => {
    await owner.insert(secretVersions).values({
      id: randomUUID(), secretId: secret.secretId, version: secret.version, envelopeVersion: 1,
      ciphertext: Buffer.from('fixture'), iv: Buffer.alloc(12), authTag: Buffer.alloc(16),
      wrappedDek: Buffer.from(wrapped.bytes, 'base64'), kekProvider: wrapped.kekProvider,
      kekId: wrapped.kekId, kekVersion: wrapped.kekVersion, createdBy: 'user:root@acme.example', sensitive: secret.sensitive === true,
    }).onConflictDoNothing({ target: [secretVersions.secretId, secretVersions.version] });
    const [row] = await owner.select().from(secretVersions).where(and(eq(secretVersions.secretId, secret.secretId), eq(secretVersions.version, secret.version)));
    assert.equal(row.wrappedDek.toString('base64'), wrapped.bytes, 'fixture version already has another wrapped key');
    return { secretVersionId: row.id };
  }));
}
