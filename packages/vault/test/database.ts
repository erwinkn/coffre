import { randomUUID } from 'node:crypto';

import type { SecretRef } from '@coffre/core/vault';
import { createDatabase, tablesOf, type Database, type Queryable } from '@coffre/db';
import { openDatabase } from '@coffre/db/connect';
import { forgetLogHeads } from '@coffre/db/log';
import { sql, type SQL } from 'drizzle-orm';
import pg from 'pg';

/**
 * The suite's database, as the vault's tests use it: the one the server's
 * tests use, on the engine `COFFRE_TEST_ENGINE` names, which
 * scripts/test-suite.sh prepares. Opened twice: as its owner, to set up
 * places and play someone who edits rows, and as the vault, which on
 * Postgres is the vault's own login.
 */
export const ENGINE = process.env.COFFRE_TEST_ENGINE === 'sqlite' ? 'sqlite' : 'postgres';

const name = process.env.COFFRE_TEST_DATABASE ?? 'coffre_test';
const url = (login: string) => `postgresql://${login}@127.0.0.1:55432/${name}`;
export const OWNER_URL = url('coffre_owner:local-dev-only');
export const VAULT_URL = url('coffre_vault_runtime:local-vault-only');

export type TestDatabase = { owner: Database; vault: Database; connect(): Promise<Database>; close(): Promise<void> };

/** The database as its owner and as the vault; `connect` opens one more as the vault, as a second instance would. */
export async function openTestDatabase(): Promise<TestDatabase> {
  const opened: (() => Promise<void>)[] = [];
  const open = async (login: string): Promise<Database> => {
    if (ENGINE === 'postgres') {
      const pool = new pg.Pool({ connectionString: login });
      opened.push(() => pool.end());
      return createDatabase(pool);
    }
    const file = process.env.COFFRE_TEST_DATABASE_URL;
    if (!file) throw new Error('COFFRE_TEST_DATABASE_URL is required on sqlite; see scripts/test-suite.sh');
    const { db, close } = await openDatabase(file);
    opened.push(close);
    return db;
  };
  return {
    owner: await open(OWNER_URL),
    vault: await open(VAULT_URL),
    connect: () => open(VAULT_URL),
    close: async () => {
      await Promise.all(opened.map((close) => close()));
    },
  };
}

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
  if (ENGINE === 'postgres') {
    return owner.transaction(async (tx) => {
      await tx.execute(sql`ALTER TABLE audit_log DISABLE TRIGGER USER`);
      const result = await work(tx);
      await tx.execute(sql`ALTER TABLE audit_log ENABLE TRIGGER USER`);
      return result;
    });
  }
  const triggers = await rows<{ name: string; sql: string }>(
    owner,
    sql`SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_log'`,
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
  if (ENGINE === 'postgres') return (await db.execute(query)).rows as Row[];
  return (db as unknown as { all<R>(query: SQL): Promise<R[]> }).all<Row>(query);
}

/** A raw statement, on either engine. */
export async function run(db: Queryable, query: SQL): Promise<void> {
  if (ENGINE === 'postgres') await db.execute(query);
  else await (db as unknown as { run(query: SQL): Promise<unknown> }).run(query);
}

/** Everything a vault test leaves behind, gone, and the heads this process remembers forgotten. */
export async function emptyDatabase(owner: Database): Promise<void> {
  const { auditLog, auditChainHead, vaultGrants, vaultMembers, secrets, environments, projects } = tablesOf(owner);
  // SQLite checks a RESTRICT foreign key row by row, so entries that point
  // at others let go of them first.
  await withLogUnlocked(owner, async (db) => {
    await db.update(auditLog).set({ relatedSeq: null });
    await db.delete(auditLog);
  });
  await owner.update(auditChainHead).set({ nextSeq: 0n, headHash: Buffer.alloc(32) });
  await owner.delete(vaultGrants);
  await owner.delete(vaultMembers);
  await owner.update(secrets).set({ currentVersionId: null });
  await run(owner, sql`DELETE FROM secret_versions`);
  await owner.delete(secrets);
  await run(owner, sql`DELETE FROM syncs`);
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
    return { projectId: project, environmentId, secretId: id, version: 1, path: `market/${environmentId === dev ? 'dev' : 'prod'}/${key}` };
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
