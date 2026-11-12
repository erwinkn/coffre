// The collapse of the numbered migrations (T285; 0.16's clean break, D197): one baseline for a new database and
// one upgrade from 0.15.0, each SQL function written once, in its final form, in a file of its own that both name.
// A tool for that one collapse, rerun on the day it lands: the pull request that deletes the numbered migrations
// deletes it too, and keeps the parity test (test/collapse.test.ts).
//
// It parses no SQL. It replays the migrations a statement at a time on a scratch database and reads, after each,
// which functions it made, replaced, altered, granted or dropped (`pg_proc`). Every statement about functions alone
// is then left out, and each function that lives to the end is written where the path first made or changed it,
// as the catalog holds it at the end (`pg_get_functiondef`, with its grants); one that does not is dropped where
// the path last touched it. Every other statement stays, in its order. So does every row a migration writes.
//
// Also left out: the DO blocks that grant a function's owner what it calls or reads (0057 to 0081's), for an owner
// that was not the login migrating. Since T193 the migrator hands each of coffre's objects to the ledger's owner in
// the migrations' own transaction (`HANDED_OVER`, migrate.ts), so they are moot, and they name each function by a
// signature of the time, which the collapsed upgrade no longer makes.
//
//   pnpm collapse:migrations <dir>   writes <dir>/baseline.sql, <dir>/upgrade.sql and <dir>/functions/<name>.sql
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { migrationsFolder } from '../src/migrate.ts';
import { onlineIndex } from '../src/online-indexes.ts';
import { postgresClient, quoteIdentifier, type PostgresClient } from '../src/postgres.ts';

export const BREAK = '--> statement-breakpoint';
/** The release the upgrade starts from, as its tag holds its migrations (0022 was rewritten since: migrate.ts, `REWRITTEN`). */
export const RELEASE = 'v0.15.0';
/** Where a function's file goes in a migration: the line `-- @function <name>`, a statement of its own. */
const MARKER = /^-- @function (\S+)$/gm;

export type Migration = { tag: string; sql: string };
export type Collapsed = { baseline: string; upgrade: string; functions: Map<string, string> };

const root = fileURLToPath(new URL('../../..', import.meta.url));
const folder = 'packages/db/src/migrations/postgres';

/** This checkout's numbered migrations, in the journal's order. */
export async function numbered(): Promise<Migration[]> {
  const { entries } = JSON.parse(await readFile(`${migrationsFolder()}/meta/_journal.json`, 'utf8')) as { entries: { tag: string }[] };
  return Promise.all(entries.map(async ({ tag }) => ({ tag, sql: await readFile(`${migrationsFolder()}/${tag}.sql`, 'utf8') })));
}

/** 0.15.0's migrations, from its tag: what every database the upgrade meets has applied. */
export function released(): Migration[] {
  const show = (path: string) => {
    try {
      return execFileSync('git', ['show', `${RELEASE}:${folder}/${path}`], { cwd: root, encoding: 'utf8', maxBuffer: 1 << 26, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (error) {
      throw new Error(`cannot read ${path} at ${RELEASE}: fetch the tag (git fetch --depth=1 origin tag ${RELEASE})`, { cause: error });
    }
  };
  const { entries } = JSON.parse(show('meta/_journal.json')) as { entries: { tag: string }[] };
  return entries.map(({ tag }) => ({ tag, sql: show(`${tag}.sql`) }));
}

/** A migration's statements, as the migrator splits them. */
export function statements(sql: string): string[] {
  return sql.split(BREAK).map((statement) => statement.trim()).filter((statement) => statement !== '');
}

/** A migration with each `-- @function` line replaced by that function's file. */
export function assemble(sql: string, functions: ReadonlyMap<string, string>): string {
  return sql.replace(MARKER, (_, name: string) => {
    const file = functions.get(name);
    if (file === undefined) throw new Error(`no function file for ${name}`);
    return file;
  });
}

/** The statement without the comment lines before it. */
const bare = (statement: string) => statement.replace(/^(?:\s*--[^\n]*\n)*\s*/, '');
const aboutFunctions = (statement: string) =>
  /^(?:CREATE (?:OR REPLACE )?FUNCTION|DROP FUNCTION|ALTER FUNCTION|(?:GRANT|REVOKE)\s[^;]*?\sON (?:FUNCTION|ALL (?:FUNCTIONS|ROUTINES) IN SCHEMA))\s/i.test(bare(statement));
const ownerGrant = (statement: string) => /^DO\s/.test(bare(statement)) && statement.includes('pg_get_userbyid(proowner)');

/**
 * Each function of the public schema, by its signature (`regprocedure`, as the default search path writes it): a
 * digest of its whole definition, what CREATE OR REPLACE cannot change (its arguments' names and defaults, its
 * result), and the roles other than its owner that may execute it (null: everyone, Postgres's default).
 */
type Fn = { name: string; digest: string; head: string; grantees: string[] | null };
type Snapshot = Map<string, Fn>;

const FUNCTIONS = `
  SELECT p.oid::regprocedure::text AS id, p.proname::text AS name, md5(pg_get_functiondef(p.oid)) AS digest,
         pg_get_function_arguments(p.oid) || ' -> ' || pg_get_function_result(p.oid) AS head,
         CASE WHEN p.proacl IS NOT NULL THEN ARRAY(
           SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(a.grantee)) END
                  || CASE WHEN a.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END
             FROM aclexplode(p.proacl) a WHERE a.grantee <> p.proowner ORDER BY 1) END AS grantees
    FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace`;

async function snapshot(client: PostgresClient): Promise<Snapshot> {
  const rows = await client.unsafe<({ id: string } & Fn)[]>(FUNCTIONS);
  return new Map(rows.map(({ id, ...fn }) => [id, fn]));
}

/** The functions whose definition, grants or existence differ between two snapshots. */
function changed(before: Snapshot, after: Snapshot): string[] {
  return [...new Set([...before.keys(), ...after.keys()])].filter((id) => JSON.stringify(before.get(id)) !== JSON.stringify(after.get(id))).sort();
}

/** `statements` run one at a time, autocommitted, a CONCURRENTLY index built plainly: what each changed of the functions. */
async function replay(client: PostgresClient, list: readonly string[]): Promise<{ touched: string[][]; start: Snapshot; end: Snapshot }> {
  const start = await snapshot(client);
  let before = start;
  const touched: string[][] = [];
  for (const statement of list) {
    const online = onlineIndex(statement);
    await client.unsafe(online === null ? statement : `CREATE ${online.unique ? 'UNIQUE ' : ''}INDEX ${quoteIdentifier(online.name)} ON ${quoteIdentifier(online.table)} ${online.body}`);
    const after = await snapshot(client);
    touched.push(changed(before, after));
    before = after;
  }
  return { touched, start, end: before };
}

const everyone = (grantees: string[] | null) => grantees ?? ['PUBLIC'];
const qualified = (id: string) => (id.startsWith('public.') ? id : `public.${id}`);

/**
 * `list`, from the database `start` describes to the one `end` does: each statement about functions alone left
 * out, each function of `end` placed where `list` first changed it, under its marker, and each function of `start`
 * that `end` lacks dropped where `list` last touched it. A function `end` keeps whose head changed is dropped
 * before its file makes it again; one only replaced keeps its grants, and loses those `end` does not give.
 */
function collapse(where: string[], list: readonly string[], { touched, start, end }: Awaited<ReturnType<typeof replay>>): string {
  const out: string[] = [];
  const placed = new Set<string>();
  const last = new Map<string, number>();
  touched.forEach((ids, index) => ids.forEach((id) => last.set(id, index)));
  list.forEach((statement, index) => {
    if (!aboutFunctions(statement) && !ownerGrant(statement)) {
      if (touched[index]!.length > 0) throw new Error(`${where[index]} changes ${touched[index]!.join(', ')} but is no statement about functions`);
      out.push(statement);
      return;
    }
    for (const id of touched[index]!) {
      const final = end.get(id);
      if (final === undefined) {
        if (start.has(id) && last.get(id) === index) out.push(`DROP FUNCTION ${qualified(id)};`);
        continue;
      }
      if (placed.has(final.name)) continue;
      placed.add(final.name);
      const overloads = [...end].filter(([, fn]) => fn.name === final.name);
      const remade = overloads.filter(([other, fn]) => start.has(other) && start.get(other)!.head !== fn.head);
      for (const [other] of remade) out.push(`DROP FUNCTION ${qualified(other)};`);
      out.push(`-- @function ${final.name}`);
      for (const [other, fn] of overloads) {
        const was = start.get(other);
        if (was === undefined || remade.some(([dropped]) => dropped === other)) continue;
        const now = everyone(fn.grantees);
        const lost = everyone(was.grantees).filter((grantee) => grantee !== 'PUBLIC' && !now.includes(grantee));
        if (lost.length > 0) out.push(`REVOKE ALL ON FUNCTION ${qualified(other)} FROM ${lost.map((grantee) => grantee.split(' ')[0]).join(', ')};`);
        if (now.includes('PUBLIC') && !everyone(was.grantees).includes('PUBLIC')) out.push(`GRANT EXECUTE ON FUNCTION ${qualified(other)} TO PUBLIC;`);
      }
    }
  });
  // A function is written where the path first made it, in the form it last had, which may name what is made later
  // (a table 0076 renamed, an overload made after it): Postgres checks a body as it is made, so the check waits
  // until the transaction ends, as a restore of pg_dump's does. Each body was checked where the path made it.
  return [UNCHECKED, ...out, CHECKED].join(`\n${BREAK}\n`) + '\n';
}

const UNCHECKED = 'SET LOCAL check_function_bodies = off;';
const CHECKED = 'RESET check_function_bodies;';

/**
 * Each function's file: every overload of its name, in its final form, with its grants, after the comment the
 * statement that last wrote it had (`comments`, by signature).
 */
async function files(client: PostgresClient, end: Snapshot, comments: ReadonlyMap<string, string>): Promise<Map<string, string>> {
  const rows = await client.unsafe<{ id: string; def: string }[]>(
    `SELECT p.oid::regprocedure::text AS id, pg_get_functiondef(p.oid) AS def FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace`,
  );
  const defs = new Map(rows.map(({ id, def }) => [id, def.trimEnd()]));
  const out = new Map<string, string[]>();
  for (const [id, fn] of [...end].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const parts = out.get(fn.name) ?? [];
    const grantees = fn.grantees;
    parts.push(`${comments.get(id) ?? ''}${defs.get(id)!};`);
    if (grantees !== null && !grantees.includes('PUBLIC')) parts.push(`REVOKE ALL ON FUNCTION ${qualified(id)} FROM PUBLIC;`);
    for (const grantee of grantees?.filter((grantee) => !grantee.startsWith('PUBLIC')) ?? []) parts.push(`GRANT EXECUTE ON FUNCTION ${qualified(id)} TO ${grantee};`);
    out.set(fn.name, parts);
  }
  return new Map([...out].map(([name, parts]) => [name, parts.join(`\n${BREAK}\n`)]));
}

/** The comment lines before the last statement that made each function what it is at the end. */
function lastComments(list: readonly string[], touched: readonly string[][]): Map<string, string> {
  const comments = new Map<string, string>();
  list.forEach((statement, index) => {
    if (!/^CREATE\s/i.test(bare(statement))) return;
    const comment = statement.slice(0, statement.length - bare(statement).length);
    for (const id of touched[index]!) comments.set(id, comment);
  });
  return comments;
}

/** The migrator's ledger, which it makes before the first migration, and which 0000 and 0019 grant. */
export const LEDGER = 'CREATE SCHEMA IF NOT EXISTS drizzle; CREATE TABLE IF NOT EXISTS drizzle.__drizzle_migrations (id SERIAL PRIMARY KEY, hash text NOT NULL, created_at bigint)';

/** A database of its own on the cluster `cluster` (a URL to its `postgres` database) for `work`, dropped after. */
async function scratch<T>(cluster: string, work: (client: PostgresClient) => Promise<T>): Promise<T> {
  const name = `coffre_collapse_${randomBytes(6).toString('hex')}`;
  const admin = postgresClient(cluster, { max: 1 });
  try {
    await admin.unsafe(`CREATE DATABASE ${quoteIdentifier(name)}`);
    const client = postgresClient(Object.assign(new URL(cluster), { pathname: `/${name}` }).toString(), { max: 1, onnotice: () => {} });
    try {
      await client.unsafe(LEDGER);
      return await work(client);
    } finally {
      await client.end();
    }
  } finally {
    await admin.unsafe(`DROP DATABASE IF EXISTS ${quoteIdentifier(name)} WITH (FORCE)`);
    await admin.end();
  }
}

const located = (migrations: readonly Migration[]) =>
  migrations.flatMap(({ tag, sql }) => statements(sql).map((statement, index) => ({ where: `${tag} statement ${index + 1}`, statement })));

/**
 * The collapse of this checkout's numbered migrations, made on the cluster `cluster` (a URL to its `postgres`
 * database, as the owner: the runtime logins must be there, as `scripts/setup-test-database.sh` makes them).
 */
export async function collapseMigrations(cluster: string): Promise<Collapsed> {
  const all = await numbered();
  const release = released();
  release.forEach(({ tag }, index) => {
    if (all[index]?.tag !== tag) throw new Error(`the journal does not start with ${RELEASE}'s: ${all[index]?.tag ?? 'nothing'} where it has ${tag}`);
  });
  const whole = located(all);
  const after = located(all.slice(release.length));

  const fromEmpty = await scratch(cluster, async (client) => {
    const replayed = await replay(client, whole.map(({ statement }) => statement));
    return { replayed, functions: await files(client, replayed.end, lastComments(whole.map(({ statement }) => statement), replayed.touched)) };
  });
  const fromRelease = await scratch(cluster, async (client) => {
    for (const { statement } of located(release)) {
      const online = onlineIndex(statement);
      await client.unsafe(online === null ? statement : `CREATE ${online.unique ? 'UNIQUE ' : ''}INDEX ${quoteIdentifier(online.name)} ON ${quoteIdentifier(online.table)} ${online.body}`);
    }
    return replay(client, after.map(({ statement }) => statement));
  });
  // Both paths end in the same functions, or the numbered migrations disagree with themselves.
  const differ = changed(fromEmpty.replayed.end, fromRelease.end);
  if (differ.length > 0) throw new Error(`0.15.0 then its successors and the whole path end in different functions: ${differ.join(', ')}`);

  return {
    baseline: collapse(whole.map(({ where }) => where), whole.map(({ statement }) => statement), fromEmpty.replayed),
    upgrade: collapse(after.map(({ where }) => where), after.map(({ statement }) => statement), fromRelease),
    functions: fromEmpty.functions,
  };
}

/** The local cluster the tests use, as its owner. */
export const LOCAL_CLUSTER = `postgresql://coffre_owner:local-dev-only@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/postgres`;

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dir = process.argv[2];
  if (dir === undefined) throw new Error('usage: pnpm collapse:migrations <dir>');
  const { baseline, upgrade, functions } = await collapseMigrations(LOCAL_CLUSTER);
  await rm(join(dir, 'functions'), { recursive: true, force: true });
  await mkdir(join(dir, 'functions'), { recursive: true });
  await writeFile(join(dir, 'baseline.sql'), baseline);
  await writeFile(join(dir, 'upgrade.sql'), upgrade);
  for (const [name, text] of functions) await writeFile(join(dir, 'functions', `${name}.sql`), `${text}\n`);
  const lines = (text: string) => text.split('\n').length - 1;
  const ofFunctions = [...functions.values()].reduce((sum, text) => sum + lines(`${text}\n`), 0);
  console.log(`baseline.sql ${lines(baseline)} lines, upgrade.sql ${lines(upgrade)}, ${functions.size} function files ${ofFunctions}`);
}
