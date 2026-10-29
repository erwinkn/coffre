import { randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';

import type { SecretRef, Through, Vault, WrappedKey } from '@coffre/core/vault';
import { createDatabase, tablesOf, type Database, type Queryable } from '@coffre/db';
import { openDatabase, postgresClient } from '@coffre/db/connect';
import { forgetLogHeads } from '@coffre/db/log';
import { and, eq, sql, type SQL } from 'drizzle-orm';

import type { Sealed, SealThrough } from '../src/checkpointer.ts';
import { openLocalVault as openRawVault, type LocalVault as RawLocalVault } from '../src/local.ts';

/**
 * The suite's database, as the vault's tests use it: the one the server's
 * tests use, on the engine `COFFRE_TEST_ENGINE` names, which
 * scripts/test-suite.sh prepares. Opened twice: as its owner, to set up
 * places and play someone who edits rows, and as the vault, which on
 * Postgres is the vault's own login.
 */
export const ENGINE = process.env.COFFRE_TEST_ENGINE === 'sqlite' ? 'sqlite' : 'postgres';

const name = process.env.COFFRE_TEST_DATABASE ?? 'coffre_test';
const url = (login: string) => `postgresql://${login}@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${name}`;
export const OWNER_URL = url('coffre_owner:local-dev-only');
export const VAULT_URL = url('coffre_vault_runtime:local-vault-only');
/** 0.15's hot path's login (schema 0022): the vault's, with its lock and statement timeouts and generic plans. */
export const HOT_URL = url('coffre_vault_hot:local-hot-only');

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
 * Which log the suite's vaults keep (`VaultOptions.log`): 0.14's unless
 * `COFFRE_TEST_LOG` says 0.15, which runs every vault test with 0.15's log
 * on too (0.15's plan: each PR runs the suite on both settings). Its changes
 * answer once committed here: no checkpointer runs (`sealed`).
 */
export const LOG = process.env.COFFRE_TEST_LOG === '0.15' ? '0.15' : '0.14';

/**
 * A checkpointer that seals everything at once: what a change waits on,
 * under 0.15's log, in a test with no tree. The vault answers nothing of
 * what it is given back.
 */
export const sealed: SealThrough = async () => ({}) as Sealed;

/**
 * `openLocalVault`, spoken to as the app does (`speaking`), keeping the
 * suite's log (`LOG`): under 0.15's, cut over from 0.14 as it opens
 * (`cutOver`), as the app has it before anything else.
 */
export async function openLocalVault(...[db, config, options, close]: Parameters<typeof openRawVault>): Promise<LocalVault> {
  const vault = await openRawVault(db, config, { ...(LOG === '0.15' ? { log: LOG, sealThrough: sealed } : {}), ...options }, close);
  if (vault.cutover !== undefined && (options?.log ?? LOG) === '0.15') await cutOver(vault, db);
  return speaking(vault);
}

/**
 * The cutover (plan PR 9), as the app asks for it, vouching for nothing of
 * its own: the vault's tests have no app key, so no credential or binding
 * the app made, and no place it deleted. The chain checked to its head.
 */
export async function cutOver(vault: Pick<Vault, 'cutover'>, db: Queryable): Promise<void> {
  const asked = await vault.cutover!();
  if (asked.ok && asked.done) return;
  assert.ok(asked.ok, `the cutover is refused: ${asked.ok ? '' : asked.why}`);
  const [head] = await rows<{ next_seq: string | number; head_hash: Buffer | Uint8Array }>(db, sql`SELECT next_seq, head_hash FROM audit_chain_head`);
  const to = { seq: (BigInt(head!.next_seq) - 1n).toString(), hash: Buffer.from(head!.head_hash).toString('hex') };
  const outcome = await vault.cutover!({ checked: { from: asked.from, to }, credentials: [], bindings: [], deleted: [] });
  assert.ok(outcome.ok && outcome.done, `the cutover is refused: ${outcome.ok ? '' : outcome.why}`);
}

export type TestDatabase = { owner: Database; vault: Database; connect(connections?: number): Promise<Database>; hot(connections?: number): Promise<Database>; close(): Promise<void> };

/**
 * The database as its owner and as the vault; `connect` opens one more as the vault, as a second instance would, with
 * up to `connections` at once (10 unless set).
 */
export async function openTestDatabase(): Promise<TestDatabase> {
  const opened: (() => Promise<void>)[] = [];
  const open = async (login: string, connections?: number): Promise<Database> => {
    if (ENGINE === 'postgres') {
      const client = postgresClient(login, { max: connections ?? 10 });
      opened.push(() => client.end());
      return createDatabase(client);
    }
    const file = process.env.COFFRE_TEST_DATABASE_URL;
    if (!file) throw new Error('COFFRE_TEST_DATABASE_URL is required on sqlite; see scripts/test-suite.sh');
    const { db, close } = await openDatabase(file);
    opened.push(close);
    return db;
  };
  const owner = await open(OWNER_URL);
  return {
    owner,
    vault: await open(VAULT_URL),
    connect: (connections) => open(VAULT_URL, connections),
    hot: (connections) => open(HOT_URL, connections),
    close: async () => {
      // A connection whose transaction a test left open is one no client's end lets go of (`endLeftOpen`).
      try {
        if (ENGINE === 'postgres') await endLeftOpen(owner);
      } finally {
        await Promise.all(opened.map((close) => close()));
      }
    },
  };
}

/**
 * Options that run a test under 0.14's log alone (`LOG`), saying why 0.15's
 * answers otherwise, beside whatever else skips it.
 */
export function log014Only(reason: string, options: { skip?: string | false } = {}): { skip: string | false } {
  return { skip: options.skip || (LOG === '0.15' ? `0.14's log only: ${reason}` : false) };
}

/** A grant on every project of 0.4, converted by the vault of 0.5: rows from long before 0.15's cutover, which 0.15's log never holds. */
export const CONVERSION = "a grant on every project of 0.4 is converted on rows 0.14's log holds, before 0.15's cutover";

/** A tampered member started over: 0.15's log refuses a change on top of a row it does not hold, and a reseal makes it the log's again (plan PR 9). */
export const START_OVER = "0.15's log changes no tampered member until a reseal makes its row the log's again (plan PR 9), never 0.14's start over";

/** Options that run a test on Postgres only, saying why. */
export function postgresOnly(reason: string): { skip: string | false } {
  return { skip: ENGINE === 'postgres' ? false : `Postgres only: ${reason}` };
}

/**
 * `work`, as the owner, with the audit log's append-only triggers lifted,
 * as someone who rewrites it would. Postgres disables them for one
 * transaction; SQLite has no such switch, so they are dropped and made again.
 */
export async function withLogUnlocked<T>(owner: Database, work: (db: Queryable) => Promise<T>): Promise<T> {
  return withTriggersLifted(owner, 'audit_log', work);
}

/** `work`, as the owner, with `table`'s triggers lifted (`withLogUnlocked`): a secret version's erase-only, say. */
export async function withTriggersLifted<T>(owner: Database, table: 'audit_log' | 'secret_versions', work: (db: Queryable) => Promise<T>): Promise<T> {
  if (ENGINE === 'postgres') {
    return owner.transaction(async (tx) => {
      await tx.execute(sql.raw(`ALTER TABLE ${table} DISABLE TRIGGER USER`));
      const result = await work(tx);
      await tx.execute(sql.raw(`ALTER TABLE ${table} ENABLE TRIGGER USER`));
      return result;
    });
  }
  const triggers = await rows<{ name: string; sql: string }>(
    owner,
    sql`SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ${table}`,
  );
  for (const trigger of triggers) await run(owner, sql.raw(`DROP TRIGGER ${trigger.name}`));
  try {
    return await work(owner);
  } finally {
    for (const trigger of triggers) await run(owner, sql.raw(trigger.sql));
  }
}

/** Rows of a raw query, on either engine. */
export async function rows<Row>(db: Queryable, query: SQL): Promise<Row[]> {
  if (ENGINE === 'postgres') return [...await db.execute(query)] as Row[];
  return (db as unknown as { all<R>(query: SQL): Promise<R[]> }).all<Row>(query);
}

/**
 * SQLite's plan for `query`, one line per step, read on a connection of its own that is closed after.
 *
 * libsql never resets an `EXPLAIN`'s statement (`all`, `run`): it stays active on its connection, so every read
 * that connection makes after it keeps its snapshot open. The next write from another connection then ends that
 * connection's `BEGIN IMMEDIATE` in SQLITE_BUSY_SNAPSHOT, and every one after, until the statement is collected.
 * Run on a pooled connection, an EXPLAIN made a later test fail now and then (T146).
 */
export async function sqlitePlan(query: SQL): Promise<string[]> {
  const { db, close } = await openDatabase(process.env.COFFRE_TEST_DATABASE_URL!);
  try {
    return (await rows<{ detail: string }>(db, sql`EXPLAIN QUERY PLAN ${query}`)).map(({ detail }) => detail);
  } finally {
    await close();
  }
}

/** A raw statement, on either engine. */
export async function run(db: Queryable, query: SQL): Promise<void> {
  if (ENGINE === 'postgres') await db.execute(query);
  else await (db as unknown as { run(query: SQL): Promise<unknown> }).run(query);
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
 * On Postgres, every other transaction in the test's database ended, before
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

/** Everything a vault test leaves behind, gone, and the heads this process remembers forgotten. */
export async function emptyDatabase(owner: Database): Promise<void> {
  if (ENGINE === 'postgres') await endLeftOpen(owner);
  const { auditLog, auditChainHead, vaultGrants, vaultMembers, vaultReleases, secrets, environments, projects, secretReferences, dismissedKeys, logChanges, logConfig, credentials, serviceBindings, consumedTokens } = tablesOf(owner);
  await owner.delete(secretReferences);
  // SQLite checks a RESTRICT foreign key row by row, so entries that point
  // at others let go of them first.
  await withLogUnlocked(owner, async (db) => {
    await db.update(auditLog).set({ relatedSeq: null });
    await db.delete(auditLog);
  });
  await owner.update(auditChainHead).set({ nextSeq: 0n, headHash: Buffer.alloc(32) });
  // Kept from the log, and gone with it.
  await owner.delete(vaultReleases);
  // 0.15's log, which only the cutover and the change path write.
  await owner.delete(logChanges);
  await owner.delete(logConfig);
  await owner.delete(vaultGrants);
  // A session a test made, for a use to name; a binding a sign-in came through, and the tokens it spent (credentials.test.ts).
  await owner.delete(credentials);
  await owner.delete(serviceBindings);
  await owner.delete(consumedTokens);
  await owner.delete(vaultMembers);
  await owner.delete(dismissedKeys);
  await owner.update(secrets).set({ currentVersionId: null });
  await run(owner, sql`DELETE FROM secret_versions`);
  await owner.delete(secrets);
  await owner.delete(environments);
  await owner.delete(projects);
  forgetLogHeads();
}

/** A project with two environments, and secrets in them on demand, as the app would have made them. */
export async function places(owner: Database) {
  const { environments, secrets } = tablesOf(owner);
  const project = await newProject(owner);
  const [dev, prod] = [randomUUID(), randomUUID()];
  await owner.insert(environments).values([
    { id: dev, projectId: project, slug: 'dev', name: 'Development' },
    { id: prod, projectId: project, slug: 'prod', name: 'Production' },
  ]);
  let n = 0;
  /** A new secret's ref, its row committed. */
  const secret = async (environmentId: string, key = 'DATABASE_URL'): Promise<SecretRef> => {
    const id = randomUUID();
    await owner.insert(secrets).values({ id, projectId: project, environmentId, key: `${key}_${++n}` });
    return { projectId: project, environmentId, secretId: id, version: 1, path: `p-${project.slice(0, 8)}/${environmentId === dev ? 'dev' : 'prod'}/${key}_${n}` };
  };
  return { project, dev, prod, secret };
}

/** A project of its own, with one environment, for a grant somewhere else. */
export async function newProject(owner: Database): Promise<string> {
  const { projects } = tablesOf(owner);
  const id = randomUUID();
  await owner.insert(projects).values({ id, slug: `p-${id.slice(0, 8)}`, name: 'Project' });
  return id;
}

export async function newEnvironment(owner: Database, projectId: string): Promise<string> {
  const { environments } = tablesOf(owner);
  const id = randomUUID();
  await owner.insert(environments).values({ id, projectId, slug: `e-${id.slice(0, 8)}`, name: 'Environment' });
  return id;
}

/** Commit fixture versions, as the app would, before asking the vault to open them. */
export async function storedVersions(owner: Database, items: { secret: SecretRef; wrapped: WrappedKey }[]): Promise<{ secretVersionId: string }[]> {
  const { secretVersions } = tablesOf(owner);
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
