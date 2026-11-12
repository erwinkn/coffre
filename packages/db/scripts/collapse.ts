// The collapse of the numbered migrations (T285; 0.16's clean break, D197): one baseline for a new database and
// one upgrade from 0.15.0, each SQL function written once, in its final form, in a file of its own that both name.
// A tool for that one collapse, rerun on the day it lands: the pull request that deletes the numbered migrations
// deletes it too, and keeps the parity test (test/collapse.test.ts).
//
// It parses no SQL. It replays the migrations a statement at a time on a scratch database and reads, after each,
// which functions it made, replaced, altered, granted or dropped (`pg_proc`). Every statement about functions alone
// is then left out, and each function that lives to the end is written where the path first made or changed it,
// as the catalog holds it at the end (`pg_get_functiondef`, with its grants); one that does not is dropped where
// the path last touched it. Every other statement stays, in its order. So does every row a migration writes, and so
// does a function of the session's own (`pg_temp`, 0084's), which lives only for the statements of its migration that
// call it, and which the migration's one session runs as the collapsed one does.
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
/** A statement about a function of the session's own (`pg_temp`), which a migration makes to run its own statements. */
const temporary = (statement: string) => /^(?:CREATE (?:OR REPLACE )?FUNCTION|DROP FUNCTION(?: IF EXISTS)?|ALTER FUNCTION)\s+pg_temp\./i.test(bare(statement));
const aboutFunctions = (statement: string) =>
  !temporary(statement) &&
  /^(?:CREATE (?:OR REPLACE )?FUNCTION|DROP FUNCTION|ALTER FUNCTION|(?:GRANT|REVOKE)\s[^;]*?\sON (?:FUNCTION|ALL (?:FUNCTIONS|ROUTINES) IN SCHEMA))\s/i.test(bare(statement));
const ownerGrant = (statement: string) => /^DO\s/.test(bare(statement)) && statement.includes('pg_get_userbyid(proowner)');

/**
 * Each function, by its signature (`regprocedure`, as the default search path writes it): its schema and owner, a
 * digest of its whole definition, what CREATE OR REPLACE refuses to change (its kind, its arguments' names, modes
 * and types, its result) and how many of its arguments have defaults (a replace may add one, not remove one), and
 * the roles other than its owner that may execute it (null: everyone, Postgres's default).
 */
type Fn = { name: string; schema: string; owner: string; digest: string; head: string; defaults: number; grantees: string[] | null };
type Snapshot = Map<string, Fn>;

const FUNCTIONS = `
  SELECT p.oid::regprocedure::text AS id, p.oid::text AS oid, p.proname::text AS name, p.pronamespace::regnamespace::text AS schema,
         pg_get_userbyid(p.proowner)::text AS owner, md5(pg_get_functiondef(p.oid)) AS digest,
         concat_ws(' ', p.prokind, p.proargnames::text, p.proargmodes::text, coalesce(p.proallargtypes, p.proargtypes::oid[])::regtype[]::text,
                   p.prorettype::regtype::text, p.proretset) AS head,
         p.pronargdefaults::int AS defaults,
         CASE WHEN p.proacl IS NOT NULL THEN ARRAY(
           SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(a.grantee)) END
                  || CASE WHEN a.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END
             FROM aclexplode(p.proacl) a WHERE a.grantee <> p.proowner ORDER BY 1) END AS grantees
    FROM pg_proc p WHERE p.pronamespace NOT IN ('pg_catalog'::regnamespace, 'information_schema'::regnamespace)
     AND p.pronamespace <> pg_my_temp_schema() AND NOT pg_is_other_temp_schema(p.pronamespace)`;

/** The functions, and each one's object ID, which a rename or a move keeps. */
async function snapshot(client: PostgresClient): Promise<{ fns: Snapshot; oids: Map<string, string> }> {
  const rows = await client.unsafe<({ id: string; oid: string } & Fn)[]>(FUNCTIONS);
  return { fns: new Map(rows.map(({ id, oid: _, ...fn }) => [id, fn])), oids: new Map(rows.map(({ id, oid }) => [id, oid])) };
}

/** The functions whose definition, owner, grants or existence differ between two snapshots. */
function changed(before: Snapshot, after: Snapshot): string[] {
  return [...new Set([...before.keys(), ...after.keys()])].filter((id) => JSON.stringify(before.get(id)) !== JSON.stringify(after.get(id))).sort();
}

/**
 * What may run what, by name, and when: a relation runs its triggers' and defaults' functions when written (`write`),
 * its policies' and its view's (functions and relations) when read (`read`), its checks', indexes', generated columns'
 * and its columns' domains' when written or rebuilt (`structure`), its partitions however it is touched (`all`), the
 * tables its foreign keys cascade to when written; a domain its checks' functions; a function every name its body holds
 * (a function, a table, a view; words in its strings too, for what it runs by EXECUTE), however it is called. Collected
 * at every step, so it holds every edge the path ever had, and every function name (`functions`).
 */
type Kind = 'write' | 'read' | 'structure' | 'all';
type Runs = { edges: Map<string, Set<`${Kind} ${string}`>>; functions: Set<string> };

const RELATION_EDGES = `
  WITH used AS (
    SELECT coalesce(t.tgrelid, ad.adrelid, nullif(co.conrelid, 0), rw.ev_class, po.polrelid, ix.indrelid) AS rel,
           CASE WHEN t.oid IS NOT NULL OR (ad.oid IS NOT NULL AND ga.attgenerated = '') THEN 'write' WHEN po.oid IS NOT NULL OR rw.oid IS NOT NULL THEN 'read' ELSE 'structure' END AS kind,
           p.proname::text AS runs
      FROM pg_depend d
      JOIN pg_proc p ON d.refclassid = 'pg_proc'::regclass AND p.oid = d.refobjid AND p.pronamespace = 'public'::regnamespace
      LEFT JOIN pg_trigger t ON d.classid = 'pg_trigger'::regclass AND t.oid = d.objid
      LEFT JOIN pg_attrdef ad ON d.classid = 'pg_attrdef'::regclass AND ad.oid = d.objid
      LEFT JOIN pg_attribute ga ON ga.attrelid = ad.adrelid AND ga.attnum = ad.adnum
      LEFT JOIN pg_constraint co ON d.classid = 'pg_constraint'::regclass AND co.oid = d.objid
      LEFT JOIN pg_rewrite rw ON d.classid = 'pg_rewrite'::regclass AND rw.oid = d.objid
      LEFT JOIN pg_policy po ON d.classid = 'pg_policy'::regclass AND po.oid = d.objid
      LEFT JOIN pg_index ix ON d.classid = 'pg_class'::regclass AND ix.indexrelid = d.objid
  )
  SELECT rel::regclass::text AS runner, kind, runs FROM used WHERE rel IS NOT NULL
  UNION
  SELECT rw.ev_class::regclass::text, 'read', d.refobjid::regclass::text FROM pg_depend d JOIN pg_rewrite rw ON d.classid = 'pg_rewrite'::regclass AND rw.oid = d.objid
   WHERE d.refclassid = 'pg_class'::regclass AND d.refobjid <> rw.ev_class
  UNION
  SELECT co.contypid::regtype::text, 'all', p.proname::text FROM pg_depend d JOIN pg_proc p ON d.refclassid = 'pg_proc'::regclass AND p.oid = d.refobjid
    JOIN pg_constraint co ON d.classid = 'pg_constraint'::regclass AND co.oid = d.objid WHERE co.contypid <> 0
  UNION
  SELECT a.attrelid::regclass::text, 'structure', ty.oid::regtype::text FROM pg_attribute a JOIN pg_type ty ON ty.oid = a.atttypid
   WHERE ty.typtype = 'd' AND ty.typnamespace = 'public'::regnamespace AND a.attnum > 0 AND NOT a.attisdropped
  UNION
  SELECT i.inhparent::regclass::text, 'all', i.inhrelid::regclass::text FROM pg_inherits i
  UNION
  SELECT k.confrelid::regclass::text, 'write', k.conrelid::regclass::text FROM pg_constraint k WHERE k.contype = 'f'`;

/** A statement without its comment lines. */
const uncommented = (sql: string) => sql.replace(/^\s*--[^\n]*$/gm, '');
/** The words of a statement or a body, as names: lowercased, unquoted. */
const words = (sql: string) => new Set(uncommented(sql).toLowerCase().match(/[a-z_][a-z0-9_$]*/g) ?? []);
const named = (name: string) => name.replaceAll('"', '').replace(/^public\./, '');
/** A relation's name as a statement spells it: quoted or not, with or without its schema. */
const NAME = String.raw`((?:"[^"]+"|\w+)(?:\s*\.\s*(?:"[^"]+"|\w+))?)`;

async function collectRuns(client: PostgresClient, runs: Runs, fns: Snapshot, ids: readonly string[]): Promise<void> {
  const add = (runner: string, kind: Kind, what: Iterable<string>) => {
    const set = runs.edges.get(runner) ?? new Set();
    for (const name of what) set.add(`${kind} ${name}`);
    runs.edges.set(runner, set);
  };
  for (const fn of fns.values()) runs.functions.add(fn.name);
  if (ids.length > 0) {
    const bodies = await client.unsafe<{ name: string; src: string }[]>(
      `SELECT p.proname::text AS name, p.prosrc AS src FROM pg_proc p WHERE p.oid::regprocedure::text = ANY($1)`,
      [ids as string[]],
    );
    for (const { name, src } of bodies) add(name, 'all', words(src));
  }
  for (const { runner, kind, runs: name } of await client.unsafe<{ runner: string; kind: Kind; runs: string }[]>(RELATION_EDGES)) add(named(runner), kind, [named(name)]);
}

/** The edges each way of touching a relation follows; a function, once reached, is run whole. */
const FOLLOWS: Record<'full' | 'read' | 'structure', readonly Kind[]> = { full: ['write', 'read', 'structure', 'all'], read: ['read', 'all'], structure: ['structure', 'all'] };

/**
 * The functions a statement may run, through `runs`: a DML statement writes the relations it names after INSERT INTO,
 * UPDATE, DELETE FROM or MERGE INTO, and reads every other; an index runs the functions it names, over the rows; an
 * ALTER TABLE those it names, and its table's checks and indexes, which a rewrite runs again; anything else is taken
 * to write every name it holds.
 */
function mayRun(statement: string, runs: Runs): Set<string> {
  const text = bare(uncommented(statement));
  const all = [...words(text)];
  const fns = all.filter((word) => runs.functions.has(word)).map((word) => [word, 'full'] as const);
  const seeds: (readonly [string, keyof typeof FOLLOWS])[] = /^CREATE (?:UNIQUE )?INDEX\s/i.test(text)
    ? fns
    : /^ALTER TABLE\s/i.test(text)
      ? [...fns, [named(new RegExp(String.raw`^ALTER TABLE (?:IF EXISTS )?(?:ONLY )?${NAME}`, 'i').exec(text)?.[1]?.replace(/\s+/g, '').toLowerCase() ?? ''), 'structure']]
      : /^(?:INSERT|UPDATE|DELETE|MERGE|WITH|SELECT)\s/i.test(text)
        ? [
            ...all.map((word) => [word, 'read'] as const),
            ...[...text.matchAll(new RegExp(String.raw`\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|MERGE\s+INTO)\s+(?:ONLY\s+)?${NAME}`, 'gi'))].map(([, target]) => [named(target!.replace(/\s+/g, '').toLowerCase()), 'full'] as const),
          ]
        : all.map((word) => [word, 'full'] as const);
  const ran = new Set<string>();
  const seen = new Set<string>();
  const queue = [...seeds];
  for (let next = queue.pop(); next !== undefined; next = queue.pop()) {
    const [name, how] = next;
    const mode = runs.functions.has(name) ? 'full' : how;
    if (seen.has(`${mode} ${name}`)) continue;
    seen.add(`${mode} ${name}`);
    if (runs.functions.has(name)) ran.add(name);
    for (const edge of runs.edges.get(name) ?? []) {
      const [kind, target] = edge.split(' ') as [Kind, string];
      if (FOLLOWS[mode].includes(kind)) queue.push([target, mode]);
    }
  }
  return ran;
}

type Replayed = { start: Snapshot; steps: Snapshot[]; touched: string[][]; end: Snapshot; runs: Runs };

/**
 * `list` run one at a time, autocommitted, a CONCURRENTLY index built plainly: the functions after each statement,
 * which each changed, and, when asked (`collect`), what may run what (`Runs`). Refused: a function outside the public schema, which the
 * collapse does not write, and a function renamed or moved, which the collapse would drop and make anew, breaking
 * what holds it by its object ID (a trigger, a view).
 */
async function replay(client: PostgresClient, where: readonly string[], list: readonly string[], { collect = false } = {}): Promise<Replayed> {
  const outside = (fns: Snapshot, at: string) => {
    for (const [id, fn] of fns) if (fn.schema !== 'public') throw new Error(`${at} makes ${id} outside the public schema, which the collapse does not write`);
  };
  const first = await snapshot(client);
  outside(first.fns, 'the database the replay starts from');
  const runs: Runs = { edges: new Map(), functions: new Set() };
  if (collect) await collectRuns(client, runs, first.fns, [...first.fns.keys()]);
  let before = first;
  const steps: Snapshot[] = [];
  const touched: string[][] = [];
  for (const [index, statement] of list.entries()) {
    const online = onlineIndex(statement);
    await client.unsafe(online === null ? statement : `CREATE ${online.unique ? 'UNIQUE ' : ''}INDEX ${quoteIdentifier(online.name)} ON ${quoteIdentifier(online.table)} ${online.body}`);
    const after = await snapshot(client);
    outside(after.fns, where[index]!);
    for (const [id, oid] of before.oids) {
      const now = after.oids.has(id) ? undefined : [...after.oids].find(([, other]) => other === oid);
      if (now !== undefined) throw new Error(`${where[index]} renames or moves ${id} to ${now[0]}, which the collapse would drop and make anew`);
    }
    const ids = changed(before.fns, after.fns);
    touched.push(ids);
    if (collect) await collectRuns(client, runs, after.fns, ids.filter((id) => after.fns.has(id)));
    steps.push(after.fns);
    before = after;
  }
  return { start: first.fns, steps, touched, end: before.fns, runs };
}

const everyone = (grantees: string[] | null) => grantees ?? ['PUBLIC'];
const qualified = (id: string) => (id.startsWith('public.') ? id : `public.${id}`);

/**
 * Where the collapse writes each function of `end` (by name: every overload, its file) and drops each of `start` that
 * `end` lacks. A name goes where the path first changed it, but one with an overload CREATE OR REPLACE cannot turn
 * into its final form (its head changed, or a default went) is dropped and made where the path itself dropped that
 * overload, not before, when what the path dropped with it may still hold it. A function `end` lacks is dropped where
 * the path last touched it.
 */
function placement({ start, steps, touched, end }: Replayed) {
  const placeAt = new Map<string, number>();
  const last = new Map<string, number>();
  touched.forEach((ids, index) =>
    ids.forEach((id) => {
      last.set(id, index);
      const name = end.get(id)?.name;
      if (name !== undefined && !placeAt.has(name)) placeAt.set(name, index);
    }),
  );
  const remade = (id: string) => {
    const was = start.get(id);
    const now = end.get(id);
    return was !== undefined && now !== undefined && (was.head !== now.head || now.defaults < was.defaults);
  };
  for (const [id, fn] of end) {
    if (!remade(id)) continue;
    const dropped = steps.findIndex((step) => !step.has(id));
    if (dropped === -1) throw new Error(`${id} changes in a way CREATE OR REPLACE refuses, yet the numbered path never drops it`);
    placeAt.set(fn.name, Math.max(placeAt.get(fn.name)!, dropped));
  }
  return { placeAt, last, remade };
}

/**
 * `list`, from the database `start` describes to the one `end` does: each statement about functions alone left
 * out, each function of `end` written under its marker and each of `start` that `end` lacks dropped, as `placement`
 * says. A function remade is dropped before its file makes it again; one only replaced keeps its grants, and loses
 * those `end` does not give.
 */
function collapse(where: readonly string[], list: readonly string[], replayed: Replayed): string {
  const { start, touched, end } = replayed;
  const { placeAt, last, remade } = placement(replayed);
  const out: string[] = [];
  const placed = new Set<string>();
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
      if (placed.has(final.name) || placeAt.get(final.name) !== index) continue;
      placed.add(final.name);
      const overloads = [...end].filter(([, fn]) => fn.name === final.name);
      for (const [other] of overloads) if (remade(other)) out.push(`DROP FUNCTION ${qualified(other)};`);
      out.push(`-- @function ${final.name}`);
      for (const [other, fn] of overloads) {
        const was = start.get(other);
        if (was === undefined || remade(other)) continue;
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

/** Statements that run no function, whatever rows the database holds. */
const INERT = /^(?:CREATE (?:OR REPLACE )?(?:TRIGGER|POLICY|VIEW|SCHEMA|SEQUENCE|TYPE|STATISTICS)\s|COMMENT ON\s|GRANT\s|REVOKE\s|DROP\s|ALTER (?:POLICY|TYPE|SEQUENCE)\s|ALTER (?:TABLE|INDEX|VIEW) \S+ RENAME\s)/i;
const inert = (statement: string) => INERT.test(bare(statement)) || (/^CREATE TABLE\s/i.test(bare(statement)) && !/\bAS\s+(?:SELECT|WITH|VALUES|TABLE)\b/i.test(statement));

/**
 * The collapse moves functions, not the statements that run them: a function is written in its final form where the
 * path first changed it, so a statement kept between there and the path's last change of it would run a form the
 * numbered path never ran there (a backfill calling it, an insert firing a trigger it is, an index or a check on it
 * over the rows). On a new database that runs over no rows, and the parity test compares what it writes; on an
 * upgrade it runs over rows no test holds, so the collapse refuses each statement kept in the upgrade that may run
 * (`mayRun`) a function whose form there differs between the two paths. Refused, the upgrade is no longer
 * mechanical: a person writes it.
 */
function refuseDiverged(where: readonly string[], list: readonly string[], replayed: Replayed): void {
  const { start, steps, end, runs } = replayed;
  const { placeAt, last } = placement(replayed);
  const form = (fn: Fn | undefined) => (fn === undefined ? 'none' : `${fn.digest} ${fn.owner}`);
  const collapsedAt = (index: number, id: string) => {
    const final = end.get(id);
    if (final !== undefined) return (placeAt.get(final.name) ?? Infinity) < index ? final : start.get(id);
    return start.has(id) && last.get(id)! < index ? undefined : start.get(id);
  };
  const refused: string[] = [];
  list.forEach((statement, index) => {
    // An online index is built after the transaction, by both paths, so with every function in its final form.
    if (aboutFunctions(statement) || ownerGrant(statement) || inert(statement) || onlineIndex(statement) !== null) return;
    const numberedAt = index === 0 ? start : steps[index - 1]!;
    const diverged = new Set<string>();
    for (const id of new Set([...numberedAt.keys(), ...start.keys(), ...end.keys()])) {
      const fn = numberedAt.get(id) ?? start.get(id) ?? end.get(id)!;
      if (form(numberedAt.get(id)) !== form(collapsedAt(index, id))) diverged.add(fn.name);
    }
    if (diverged.size === 0) return;
    const hit = [...mayRun(statement, runs)].filter((name) => diverged.has(name)).sort();
    if (hit.length > 0) refused.push(`${where[index]} may run ${hit.join(', ')}, in another form than the numbered path ran there`);
  });
  if (refused.length > 0) throw new Error(`the upgrade cannot keep these statements as they are:\n${refused.join('\n')}`);
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

  const owned = async (client: PostgresClient, fns: Snapshot) => {
    // A function's file sets no owner: the login migrating owns what it makes, so the path must leave it that.
    const [{ login }] = await client.unsafe<{ login: string }[]>('SELECT current_user::text AS login');
    for (const [id, fn] of fns) if (fn.owner !== login) throw new Error(`${id} ends owned by ${fn.owner}, not by ${login}, which migrates; its file sets no owner`);
  };
  const fromEmpty = await scratch(cluster, async (client) => {
    const replayed = await replay(client, whole.map(({ where }) => where), whole.map(({ statement }) => statement));
    await owned(client, replayed.end);
    return { replayed, functions: await files(client, replayed.end, lastComments(whole.map(({ statement }) => statement), replayed.touched)) };
  });
  const fromRelease = await scratch(cluster, async (client) => {
    for (const { statement } of located(release)) {
      const online = onlineIndex(statement);
      await client.unsafe(online === null ? statement : `CREATE ${online.unique ? 'UNIQUE ' : ''}INDEX ${quoteIdentifier(online.name)} ON ${quoteIdentifier(online.table)} ${online.body}`);
    }
    return replay(client, after.map(({ where }) => where), after.map(({ statement }) => statement), { collect: true });
  });
  // Both paths end in the same functions, or the numbered migrations disagree with themselves.
  const differ = changed(fromEmpty.replayed.end, fromRelease.end);
  if (differ.length > 0) throw new Error(`0.15.0 then its successors and the whole path end in different functions: ${differ.join(', ')}`);
  // Only the upgrade meets rows no test holds; the baseline starts empty, and its parity test compares every row.
  refuseDiverged(after.map(({ where }) => where), after.map(({ statement }) => statement), fromRelease);

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
