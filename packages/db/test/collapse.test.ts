// The parity of 0.16's collapsed migrations (T285): a database migrated to 0.15.0 and then upgraded is the database
// the baseline makes, and both are what the numbered migrations make, until those are deleted. Compared: the catalog
// (tables, columns, types, defaults, checks, keys, indexes, triggers, sequences, views, policies, statistics, each
// function's definition, and every grant: of the logins, the backup group and everyone), and every row, a
// materialized view's included. An index's contents are compared by its definition, so no index may compute over a
// function of ours (one would keep what an earlier body computed); an upgrade's columns, by what an older row reads.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';

import { assemble, collapseMigrations, LEDGER, numbered, RELEASE, released, several, statements, type Collapsed } from '../scripts/collapse.ts';
import { migrateDatabase, restrictDatabase } from '../src/migrate.ts';
import { buildOnline, onlineIndex, onlineIndexes } from '../src/online-indexes.ts';
import { postgresClient, postgresSession, quoteIdentifier } from '../src/postgres.ts';

const BASE = `postgresql://coffre_owner:local-dev-only@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${process.env.COFFRE_TEST_DATABASE ?? 'coffre_test'}`;
// Short, not the suite's database name with a suffix: Postgres cuts a name at 63 bytes, which made two of these one.
const PREFIX = `coffre_collapse_${randomBytes(4).toString('hex')}`;
const made: string[] = [];
const urlOf = (name: string) => Object.assign(new URL(BASE), { pathname: `/${name}` }).toString();

async function admin<T>(work: (client: ReturnType<typeof postgresClient>) => Promise<T>): Promise<T> {
  const client = postgresClient(BASE, { max: 1 });
  try {
    return await work(client);
  } finally {
    await client.end();
  }
}

/** A new database, empty or a copy of `template`. */
async function database(name: string, template?: string): Promise<string> {
  assert.ok(`${PREFIX}_${name}`.length <= 63, `${PREFIX}_${name} is longer than Postgres keeps`);
  made.push(`${PREFIX}_${name}`);
  await admin((client) => client.unsafe(`CREATE DATABASE ${quoteIdentifier(`${PREFIX}_${name}`)}${template === undefined ? '' : ` TEMPLATE ${quoteIdentifier(template)}`}`));
  return urlOf(`${PREFIX}_${name}`);
}

/**
 * A statement applied: its command, as Postgres names it (CREATE TABLE … AS is a SELECT), the rows it inserted,
 * updated or deleted, and the tables it rewrote (by object ID, which a rename keeps) and their rows then.
 */
type Applied = { statement: string; command: string; written: number; rewritten: { oid: string; table: string; held: number }[] };

/**
 * `migrations` applied as the migrator applies them, but for its ledger's rows: in one transaction, then the indexes
 * built online, then the database restricted.
 */
async function apply(url: string, migrations: readonly string[]): Promise<Applied[]> {
  const client = postgresSession(url);
  const WRITTEN = `SELECT coalesce(sum(n_tup_ins + n_tup_upd + n_tup_del), 0)::int8::text AS n FROM pg_stat_xact_user_tables`;
  // A table rewritten (a column converted, a volatile default added) gets a new file: Postgres says which, not the SQL.
  const FILES = `SELECT oid::text, oid::regclass::text AS name, relfilenode::text AS file FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r'`;
  const applied: Applied[] = [];
  try {
    await client.begin(async (tx) => {
      await tx.unsafe(LEDGER);
      const files = async () => new Map((await tx.unsafe<{ oid: string; name: string; file: string }[]>(FILES)).map((row) => [row.oid, row]));
      let was = await files();
      for (const sql of migrations) {
        for (const statement of statements(sql)) {
          if (onlineIndex(statement) !== null) continue;
          const [before] = await tx.unsafe<{ n: string }[]>(WRITTEN);
          const { command } = await tx.unsafe(statement);
          const [after] = await tx.unsafe<{ n: string }[]>(WRITTEN);
          const now = await files();
          const rewritten: Applied['rewritten'] = [];
          for (const [oid, { name, file }] of now) {
            if (!was.has(oid) || was.get(oid)!.file === file) continue;
            const [held] = await tx.unsafe<{ n: string }[]>(`SELECT count(*)::text AS n FROM ${name}`);
            rewritten.push({ oid, table: name, held: Number(held!.n) });
          }
          was = now;
          applied.push({ statement, command: command ?? '', written: Number(after!.n) - Number(before!.n), rewritten });
        }
      }
    });
    const session = { client, briefly: <T>(run: () => Promise<T>) => run(), waitShort: async () => {}, waitLong: async () => {} };
    for (const index of onlineIndexes(migrations)) await buildOnline(session, index);
    await restrictDatabase(client);
    return applied;
  } finally {
    await client.end();
  }
}

/** A statement without its comment lines. */
const code = (statement: string) => statement.replace(/^\s*--[^\n]*(?:\n|$)/gm, '').trim();
/** A command that writes no rows of its own, by the name Postgres gives it; any other is held to the seed. */
const DDL = /^(?:CREATE|ALTER|DROP|GRANT|REVOKE|COMMENT|SET|RESET)\b/;

/** One line per object, sorted; a table partitioned by day has days named by the date the database was made. */
const CATALOG = `
  WITH fn AS (
    SELECT p.oid FROM pg_proc p WHERE p.pronamespace NOT IN ('pg_catalog'::regnamespace, 'information_schema'::regnamespace)
  ), rel AS (
    -- A day's index is named by its parent and its day: the online build names those of the days it finds its own way,
    -- a plain CREATE INDEX Postgres's way (as it names a day made later on either path), and nothing names one.
    SELECT c.oid, coalesce((SELECT 'index ' || h.inhparent::regclass::text || ' on ' || x.indrelid::regclass::text FROM pg_inherits h JOIN pg_index x ON x.indexrelid = c.oid WHERE h.inhrelid = c.oid AND c.relkind = 'i'),
                           CASE WHEN c.relnamespace = 'public'::regnamespace THEN '' ELSE c.relnamespace::regnamespace::text || '.' END || c.relname) AS name
      FROM pg_class c WHERE c.relnamespace IN ('public'::regnamespace, 'drizzle'::regnamespace)
  ), acl AS (
    SELECT 'grant on ' || r.name AS object, coalesce(c.relacl, acldefault(CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END::"char", c.relowner)) AS acl
      FROM rel r JOIN pg_class c ON c.oid = r.oid
    UNION ALL
    SELECT 'grant on ' || r.name || '.' || a.attname, a.attacl FROM rel r JOIN pg_attribute a ON a.attrelid = r.oid WHERE a.attacl IS NOT NULL
    UNION ALL
    SELECT 'grant on ' || p.oid::regprocedure::text, coalesce(p.proacl, acldefault('f'::"char", p.proowner)) FROM fn JOIN pg_proc p ON p.oid = fn.oid
    UNION ALL
    SELECT 'grant on schema ' || n.nspname, coalesce(n.nspacl, acldefault('n'::"char", n.nspowner)) FROM pg_namespace n WHERE n.nspname IN ('public', 'drizzle')
    UNION ALL
    SELECT 'grant on database', d.datacl FROM pg_database d WHERE d.datname = current_database() AND d.datacl IS NOT NULL
  )
  SELECT 'relation ' || r.name AS line, concat_ws(' | ', pg_get_userbyid(c.relowner), c.relkind, c.relpersistence, c.relrowsecurity, c.relforcerowsecurity, c.reloptions::text,
         pg_get_partkeydef(c.oid), pg_get_expr(c.relpartbound, c.oid), (SELECT i.inhparent::regclass::text FROM pg_inherits i WHERE i.inhrelid = c.oid),
         CASE WHEN c.relkind IN ('v', 'm') THEN pg_get_viewdef(c.oid) END,
         CASE WHEN c.relkind IN ('i', 'I') THEN replace(pg_get_indexdef(c.oid), ' INDEX ' || quote_ident(c.relname) || ' ON ', ' INDEX ON ') || (SELECT ' valid ' || i.indisvalid FROM pg_index i WHERE i.indexrelid = c.oid) END,
         (SELECT concat_ws(' ', format_type(s.seqtypid, NULL), s.seqstart, s.seqincrement, s.seqmax, s.seqmin, s.seqcache, s.seqcycle) FROM pg_sequence s WHERE s.seqrelid = c.oid)) AS def
    FROM rel r JOIN pg_class c ON c.oid = r.oid
  UNION ALL
  SELECT 'column ' || r.name || '.' || a.attname, concat_ws(' | ', rank() OVER (PARTITION BY r.oid ORDER BY a.attnum), format_type(a.atttypid, a.atttypmod),
         a.attnotnull, pg_get_expr(d.adbin, d.adrelid), a.attidentity, a.attgenerated, CASE WHEN a.attcollation <> 0 THEN a.attcollation::regcollation::text END,
         -- What a row older than its column reads (a default added without a rewrite), which only a path that added it holds.
         CASE WHEN a.atthasmissing AND $1::boolean THEN 'missing ' || a.attmissingval::text END)
    FROM rel r JOIN pg_attribute a ON a.attrelid = r.oid AND a.attnum > 0 AND NOT a.attisdropped
    LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
  UNION ALL
  SELECT 'constraint ' || coalesce(k.conrelid::regclass::text, k.contypid::regtype::text) || '.' || k.conname, pg_get_constraintdef(k.oid)
    FROM pg_constraint k WHERE k.connamespace = 'public'::regnamespace
  UNION ALL
  SELECT 'trigger ' || r.name || '.' || t.tgname, pg_get_triggerdef(t.oid) || ' ' || t.tgenabled::text FROM rel r JOIN pg_trigger t ON t.tgrelid = r.oid WHERE NOT t.tgisinternal
  UNION ALL
  SELECT 'function ' || p.oid::regprocedure::text, 'owner ' || pg_get_userbyid(p.proowner) || ' ' || pg_get_functiondef(p.oid) FROM fn JOIN pg_proc p ON p.oid = fn.oid
  UNION ALL
  SELECT 'type ' || t.typname, concat_ws(' | ', pg_get_userbyid(t.typowner), t.typtype, format_type(t.typbasetype, t.typtypmod), t.typnotnull, t.typdefault,
         (SELECT string_agg(e.enumlabel, ',' ORDER BY e.enumsortorder) FROM pg_enum e WHERE e.enumtypid = t.oid))
    FROM pg_type t WHERE t.typnamespace = 'public'::regnamespace AND t.typtype IN ('c', 'd', 'e', 'r')
     AND (t.typrelid = 0 OR (SELECT c.relkind FROM pg_class c WHERE c.oid = t.typrelid) = 'c')
  UNION ALL
  SELECT 'policy ' || r.name || '.' || p.polname, concat_ws(' | ', p.polcmd, p.polpermissive, p.polroles::regrole[]::text, pg_get_expr(p.polqual, p.polrelid), pg_get_expr(p.polwithcheck, p.polrelid))
    FROM rel r JOIN pg_policy p ON p.polrelid = r.oid
  UNION ALL
  SELECT 'rule ' || g.tablename || '.' || g.rulename, g.definition FROM pg_rules g WHERE g.schemaname = 'public'
  UNION ALL
  SELECT 'statistics ' || s.stxname, pg_get_statisticsobjdef(s.oid) FROM pg_statistic_ext s WHERE s.stxnamespace = 'public'::regnamespace
  UNION ALL
  SELECT acl.object || ' to ' || CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
         string_agg(a.privilege_type || CASE WHEN a.is_grantable THEN ' with grant option' ELSE '' END, ', ' ORDER BY a.privilege_type)
    FROM acl CROSS JOIN LATERAL aclexplode(acl.acl) a GROUP BY acl.object, a.grantee
  UNION ALL
  SELECT 'default privileges of ' || d.defaclrole::regrole::text || ' in ' || coalesce(d.defaclnamespace::regnamespace::text, 'the database') || ' on ' || d.defaclobjtype::text, d.defaclacl::text
    FROM pg_default_acl d
  UNION ALL
  SELECT 'setting of ' || s.setrole::regrole::text, s.setconfig::text FROM pg_db_role_setting s, pg_database d WHERE d.datname = current_database() AND s.setdatabase = d.oid
  UNION ALL
  SELECT 'comment on ' || pg_describe_object(d.classoid, d.objoid, d.objsubid), d.description FROM pg_description d WHERE d.objoid >= 16384
  UNION ALL
  SELECT 'extension ' || x.extname, x.extversion FROM pg_extension x
  UNION ALL
  SELECT 'schema ' || n.nspname, pg_get_userbyid(n.nspowner) FROM pg_namespace n WHERE n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema'`;

/** Rows a migration wrote at the time it ran: equal only where both databases ran it at once. */
const WHEN_MIGRATED: Record<string, string[]> = { checkpoint_fence: ['at_floor'] };

/**
 * The catalog and every row, or, for a table's rows when asked (`digest`), their count and one digest of each row's.
 * Two databases upgraded from one 0.15.0 database (`history`) hold what only their path made too: the rows written as
 * a migration ran, and what a row older than a column added since reads in it.
 */
async function state(url: string, { history = false, digest = false } = {}): Promise<string[]> {
  // A row is compared as Postgres writes it, each value by its type's own output function: no JSON (which reads a
  // float's -0 as 0 and keeps one of a json value's duplicate keys, r5) and no parsing in the driver. The settings
  // that output reads are the same for every database compared.
  const client = postgresClient(url, { max: 1, connection: { extra_float_digits: '1', DateStyle: 'ISO, YMD', IntervalStyle: 'postgres', TimeZone: 'UTC', bytea_output: 'hex' } });
  try {
    const lines = (await client.unsafe<{ line: string; def: string | null }[]>(CATALOG, [history])).map(({ line, def }) =>
      `${line}: ${line.startsWith('relation ') ? (def ?? '').replace(/'\d{13}'/g, "'<at>'") : def}`.replace(/_20\d{6}\b/g, '_<day>'));
    // A table's columns in their order, which the catalog's lines hold alike.
    const tables = await client.unsafe<{ name: string; kind: string; columns: string[] }[]>(`
      SELECT c.relname::text AS name, c.relkind::text AS kind, array_agg(a.attname::text ORDER BY a.attnum) AS columns
        FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
       WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'm', 'S') AND NOT c.relispartition GROUP BY c.oid`);
    for (const { name, kind, columns } of tables) {
      const compared = kind === 'S' ? ['last_value', 'is_called'] : columns.filter((column) => history || !(WHEN_MIGRATED[name] ?? []).includes(column));
      const row = `ROW(${compared.map((column) => `t.${quoteIdentifier(column)}`).join(', ')})::text`;
      if (digest && kind !== 'S') {
        const [{ n, sum }] = await client.unsafe<{ n: string; sum: string }[]>(
          `SELECT count(*)::text AS n, md5(coalesce(string_agg(h, '' ORDER BY h), '')) AS sum FROM (SELECT md5(${row}) AS h FROM ${quoteIdentifier(name)} t) r`,
        );
        lines.push(`rows of ${name}: ${n}, digest ${sum}`);
        continue;
      }
      for (const { line } of await client.unsafe<{ line: string }[]>(`SELECT ${row} AS line FROM ${quoteIdentifier(name)} t`)) lines.push(`row of ${name}: ${line}`);
    }
    return lines.sort();
  } finally {
    await client.end();
  }
}

/** What one database has that the other has not, line by line, each cut to what a reader can take in. */
function differences(left: readonly string[], right: readonly string[]): { only: { left: string[]; right: string[] } } {
  const count = new Map<string, number>();
  for (const line of left) count.set(line, (count.get(line) ?? 0) + 1);
  const onlyRight: string[] = [];
  for (const line of right) {
    const n = count.get(line) ?? 0;
    if (n === 0) onlyRight.push(line);
    else count.set(line, n - 1);
  }
  const onlyLeft = [...count].flatMap(([line, n]) => Array.from({ length: n }, () => line));
  const cut = (lines: string[]) => lines.map((line) => (line.length > 400 ? `${line.slice(0, 400)}…` : line));
  return { only: { left: cut(onlyLeft), right: cut(onlyRight) } };
}

const same = (left: readonly string[], right: readonly string[]) => assert.deepEqual(differences(left, right), { only: { left: [], right: [] } });

/**
 * Rows a 0.15.0 database holds that the upgrade's statements read: the reads it placed, its bulk policy, and its
 * clients' redirects (a list, and one only a forger writes, which 0084 converts to none). Each statement of the
 * upgrade but DDL must write rows from them (or `WRITES_NOTHING` say why it writes none), and each that rewrites a
 * table 0.15.0 has must meet rows there, so a backfill or a conversion added later fails this test until the seed
 * gives it rows.
 */
const SEED = `
  INSERT INTO log_config (name, value, seal) VALUES ('policy', '{"kind":"policy","bulk":{"count":50,"windowMs":60000}}', '\\x000102030405060708090a0b0c0d0e0f');
  INSERT INTO log_reads (number, at, credential, purpose, principal, secret, environment, project, place, source, source_environment, source_project, mac)
  SELECT n, (extract(epoch FROM now()) * 1000)::bigint - n, '00000000-0000-4000-8000-000000000001', 1, 'user:reader@acme.example',
         '00000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000004',
         CASE WHEN n = 1 THEN '00000000-0000-4000-8000-000000000005'::uuid END, CASE WHEN n = 1 THEN '00000000-0000-4000-8000-000000000006'::uuid END,
         CASE WHEN n = 1 THEN '00000000-0000-4000-8000-000000000007'::uuid END, CASE WHEN n = 1 THEN '00000000-0000-4000-8000-000000000008'::uuid END,
         '\\x000102030405060708090a0b0c0d0e0f'
    FROM generate_series(1, 2) AS n;
  INSERT INTO oauth_clients (id, auth_mac, name, redirect_uris, created_at) VALUES
    ('00000000-0000-4000-8000-000000000009', '\\x000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f', 'cli',
     '["https://b.example/cb","https://a.example/cb"]', '2026-01-01T00:00:00Z'),
    ('00000000-0000-4000-8000-00000000000a', '\\x000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f', 'forged',
     '[1,"https://c.example/cb",null]', '2026-01-01T00:00:00Z');`;

/** The upgrade's statements that look like they write rows but write none, by design. */
const WRITES_NOTHING: { reason: string; matches: RegExp }[] = [
  { reason: '0076 makes the old names as views, and grants on them', matches: /EXECUTE format\('CREATE VIEW public\.%I WITH \(security_invoker = true\)/ },
];

let collapsed: Collapsed;
let release: string[];

before(async () => {
  collapsed = await collapseMigrations(BASE);
  release = released().map(({ sql }) => sql);
});

after(async () => {
  await admin(async (client) => {
    for (const name of made) await client.unsafe(`DROP DATABASE IF EXISTS ${quoteIdentifier(name)} WITH (FORCE)`);
  });
});

test('each function is made once, by its own file, which the baseline names once and the upgrade at most once', () => {
  const named = (sql: string) => [...sql.matchAll(/^-- @function (\S+)$/gm)].map(([, name]) => name!);
  for (const sql of [collapsed.baseline, collapsed.upgrade]) {
    assert.equal(new Set(named(sql)).size, named(sql).length);
    // Inline, only a function the path made and dropped again (an overload, or 0085's), which the same statements drop.
    const inline = [...sql.matchAll(/^CREATE (?:OR REPLACE )?FUNCTION (?!pg_temp\.)(?:public\.)?(\w+)\(/gim)].map(([, name]) => name!);
    const dropped = [...sql.matchAll(/^DROP FUNCTION public\.(\w+)\(/gm)].map(([, name]) => name!);
    for (const name of inline) assert.ok(dropped.includes(name), `${name} is made inline, yet never dropped`);
    // 0.16.0's upgrade is offline (D197): it builds every index in its transaction, none after it.
    assert.deepEqual(statements(assemble(sql, collapsed.functions)).filter((statement) => onlineIndex(statement) !== null), []);
  }
  assert.deepEqual(named(collapsed.baseline).sort(), [...collapsed.functions.keys()].sort());
});

test('the baseline makes what the numbered migrations make', async () => {
  const numberedPath = await database('numbered');
  assert.deepEqual(await migrateDatabase(numberedPath), { unbuilt: [] });
  const baseline = await database('baseline');
  await apply(baseline, [assemble(collapsed.baseline, collapsed.functions)]);
  same(await state(numberedPath), await state(baseline));
  // An index stores what its expressions compute when a row is written, and parity compares an index by its
  // definition alone: one over a function of ours would keep what an earlier body of it computed on one path.
  const client = postgresClient(numberedPath, { max: 1 });
  try {
    const over = await client.unsafe<{ index: string; on: string }[]>(`
      SELECT d.objid::regclass::text AS index, pg_describe_object(d.refclassid, d.refobjid, 0) AS on FROM pg_depend d JOIN pg_class c ON c.oid = d.objid
       WHERE d.classid = 'pg_class'::regclass AND c.relkind IN ('i', 'I') AND d.refclassid IN ('pg_proc'::regclass, 'pg_operator'::regclass, 'pg_opclass'::regclass)
         AND d.refobjid >= 16384`);
    assert.deepEqual([...over], [], 'an index over a function of ours: decide at the collapse whether its contents may differ, then rebuild it');
  } finally {
    await client.end();
  }
});

test('0.15.0 upgraded makes what the baseline makes', async () => {
  const baseline = await database('baseline_again');
  await apply(baseline, [assemble(collapsed.baseline, collapsed.functions)]);
  const upgraded = await database('upgraded');
  await apply(upgraded, release);
  await apply(upgraded, [assemble(collapsed.upgrade, collapsed.functions)]);
  same(await state(baseline), await state(upgraded));
});

test('on a 0.15.0 database with rows, the upgrade writes what the numbered migrations after 0.15.0 write', async () => {
  const seeded = await database('seeded');
  await apply(seeded, release);
  const client = postgresClient(seeded, { max: 1 });
  const atRelease = new Set<string>();
  try {
    await client.unsafe(SEED);
    for (const { oid } of await client.unsafe<{ oid: string }[]>(`SELECT oid::text FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r'`)) atRelease.add(oid);
  } finally {
    await client.end();
  }
  const stepped = await database('stepped', `${PREFIX}_seeded`);
  await apply(stepped, (await numbered()).slice(release.length).map(({ sql }) => sql));
  const upgraded = await database('seeded_upgraded', `${PREFIX}_seeded`);
  const applied = await apply(upgraded, [assemble(collapsed.upgrade, collapsed.functions)]);
  // Every statement but DDL may write rows: an unknown kind is held to the seed too.
  const writers = applied.filter(({ statement, command }) => code(statement) !== '' && !DDL.test(command));
  assert.ok(writers.length > 0);
  for (const { statement, written } of writers) {
    if (WRITES_NOTHING.some(({ matches }) => matches.test(statement))) continue;
    assert.ok(written > 0, `the seed gives this statement no rows to write; seed what it reads:\n${code(statement).slice(0, 300)}`);
  }
  for (const { statement, rewritten } of applied) {
    for (const { oid, table, held } of rewritten) {
      if (atRelease.has(oid)) assert.ok(held > 0, `the seed gives ${table} no rows for this statement to rewrite:\n${code(statement).slice(0, 300)}`);
    }
  }
  same(await state(stepped, { history: true }), await state(upgraded, { history: true }));
});

test('parity tells apart rows that are equal only as JSON (r5)', async () => {
  for (const [left, right] of [[`'-0'::float8`, `'0'::float8`], [`'{"a": 1}'::json`, `'{"a":1}'::json`]]) {
    const urls: string[] = [];
    for (const value of [left!, right!]) {
      const url = await database(`as_text_${made.length}`);
      const client = postgresClient(url, { max: 1 });
      // The catalog's query names the ledger's schema.
      await client.unsafe('CREATE SCHEMA drizzle').then(() => client.unsafe(`CREATE TABLE probe AS SELECT ${value} AS v`)).finally(() => client.end());
      urls.push(url);
    }
    for (const digest of [false, true]) assert.notDeepEqual(await state(urls[0]!, { digest }), await state(urls[1]!, { digest }));
  }
});

/** A database restored from a 0.15.0 deployment's backup on the test cluster (T265's rehearsal), which both paths upgrade. */
const RESTORED = process.env.COFFRE_TEST_RESTORED_DATABASE;

test('on the restored database COFFRE_TEST_RESTORED_DATABASE names, the upgrade leaves what the numbered migrations leave', { skip: RESTORED === undefined }, async () => {
  const client = postgresClient(urlOf(RESTORED!), { max: 1 });
  try {
    const ledger = await client.unsafe<{ hash: string }[]>('SELECT hash FROM drizzle.__drizzle_migrations ORDER BY created_at, id');
    const hashes = release.map((sql) => createHash('sha256').update(sql).digest('hex'));
    assert.deepEqual(ledger.map(({ hash }) => hash), hashes, `${RESTORED} is not a database ${RELEASE} migrated, and no later release`);
  } finally {
    await client.end();
  }
  const stepped = await database('restored_stepped', RESTORED);
  await apply(stepped, (await numbered()).slice(release.length).map(({ sql }) => sql));
  const upgraded = await database('restored_upgraded', RESTORED);
  await apply(upgraded, [assemble(collapsed.upgrade, collapsed.functions)]);
  same(await state(stepped, { history: true, digest: true }), await state(upgraded, { history: true, digest: true }));
});

const probe = async (sql: string) => collapseMigrations(BASE, [...(await numbered()), { tag: '9999_probe', sql: statements(sql).join(`\n--> statement-breakpoint\n`) }]);

test('a statement of the migrations after 0.15.0 holds one command', async () => {
  // Two commands in one statement (r3's probe): the seed check would sort the INSERT by the DROP before it.
  await assert.rejects(probe('DROP TABLE IF EXISTS "probe_no_such"; INSERT INTO "log_changes" SELECT * FROM "log_changes";'), /9999_probe statement 1 holds more than one command/);
  assert.equal(several('DO $$ BEGIN PERFORM 1; PERFORM 2; END $$;  -- one block\n'), false);
  assert.equal(several('-- one; two\nINSERT INTO t VALUES (1);'), false);
  assert.equal(several("INSERT INTO t VALUES (';x');"), true);
  // r4's: a `$$` in a string opens no body that would hide the second command.
  assert.equal(several("CREATE TABLE t (c text DEFAULT '$$'); INSERT INTO log_changes SELECT * FROM log_changes WHERE 'x' = '$$';"), true);
});

test('an index built online is built plainly, unless the path drops it', async () => {
  const collapsedProbe = await probe(`
    CREATE TABLE "probe_a" ("n" integer);
    --> statement-breakpoint
    CREATE INDEX CONCURRENTLY "probe_a_n" ON "probe_a" USING btree ("n");
    --> statement-breakpoint
    DROP INDEX "probe_a_n";
    --> statement-breakpoint
    CREATE INDEX CONCURRENTLY "probe_a_kept" ON "probe_a" USING btree ("n");
    --> statement-breakpoint
    CREATE INDEX CONCURRENTLY "probe_a_gone" ON "probe_a" USING btree ("n");
    --> statement-breakpoint
    DROP INDEX IF EXISTS "probe_a_gone";
    --> statement-breakpoint
    CREATE TABLE "probe_b" ("n" integer);
    --> statement-breakpoint
    CREATE INDEX CONCURRENTLY "probe_b_n" ON "probe_b" USING btree ("n");
    --> statement-breakpoint
    DROP TABLE "probe_b";`);
  for (const sql of [collapsedProbe.baseline, collapsedProbe.upgrade]) {
    const kept = statements(sql).filter((statement) => statement.includes('probe_'));
    assert.deepEqual(kept, [
      'CREATE TABLE "probe_a" ("n" integer);',
      'CREATE INDEX "probe_a_kept" ON "probe_a" USING btree ("n");',
      'DROP INDEX IF EXISTS "probe_a_gone";',
      'CREATE TABLE "probe_b" ("n" integer);',
      'DROP TABLE "probe_b";',
    ]);
  }
  await apply(await database('probe'), [assemble(collapsedProbe.baseline, collapsedProbe.functions)]);
});
