// `coffre backup`: a deployment's database, dumped with PostgreSQL's own
// pg_dump as a backup login, a member of coffre_backup, and a manifest
// beside the dump that says what it holds: each table's rows, counted and
// hashed, the newest migration and the audit log's head, all read in the
// one snapshot pg_dump reads, and the dump's own size and SHA-256. `coffre
// restore` and `coffre verify backup` hold a restored copy to it
// (restore.ts).
//
// It asks for the backup login's connection string, at a hidden prompt or
// on stdin, never the command line, and hands pg_dump its password in
// PGPASSWORD, never an argument. Postgres only: a SQLite database is a file,
// which its own `.backup` copies.
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { chmodSync, closeSync, createReadStream, openSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';
import { parseArgs } from 'node:util';

import { postgresConnection } from '@coffre/db/connect';
import { KNOWN_MIGRATIONS } from '@coffre/db/schema-version';
import pg from 'pg';

import { readDatabaseUrl } from './database-url.ts';
import { Cancelled, listed, type Output, style } from './tty.ts';
import { cliVersion } from './version.ts';

export const MANIFEST_FORMAT = 'coffre.backup.v1';

/** What a database holds, as one transaction reads it: what a dump must bring back. */
export type Facts = {
  /** Every table in `public` and `drizzle`, by its quoted name: its rows, and a hash of them in any order. */
  tables: Record<string, { rows: number; digest: string }>;
  /** The migration ledger: how many ran, and the hash of the newest, null with none. */
  migrations: { applied: number; last: string | null };
  /** The audit log's head: the next entry's number, and the newest entry's hash, hex. Null with no head row. */
  log: { nextSeq: string; head: string } | null;
};

/** What `coffre backup` writes beside a dump, as `<name>.manifest.json`. */
export type Manifest = Facts & {
  format: typeof MANIFEST_FORMAT;
  /** The CLI that took it. */
  coffre: string;
  takenAt: string;
  /** Where it was taken from, `host/database`, and as whom: no password. */
  database: string;
  login: string;
  dump: { file: string; bytes: number; sha256: string };
};

/** The manifest's path for a dump's: `coffre.dump` → `coffre.manifest.json`. */
export function manifestPath(dump: string): string {
  return `${dump.replace(/\.dump$/, '')}.manifest.json`;
}

/**
 * Text that is the same in any session: a row's text form depends on these,
 * and its digest on its text. Set in each transaction that reads the facts.
 */
const STABLE_TEXT = [
  "SET LOCAL TimeZone = 'UTC'",
  "SET LOCAL DateStyle = 'ISO, YMD'",
  "SET LOCAL IntervalStyle = 'postgres'",
  'SET LOCAL extra_float_digits = 1',
  "SET LOCAL bytea_output = 'hex'",
];

/**
 * Each table's rows, counted, and the sum of the first 64 bits of each row's
 * MD5: a hash of the table that no order of its rows changes, so a restored
 * copy makes the same one only with the same rows. Integrity, not a seal:
 * whoever writes rows can make it agree. One statement for every table.
 */
const TABLES = `
  SELECT name, (xpath('/row/n/text()', counted))[1]::text AS rows, (xpath('/row/d/text()', counted))[1]::text AS digest
  FROM (
    SELECT name, query_to_xml(
      format('SELECT count(*) AS n, coalesce(sum((''x'' || left(md5(t::text), 16))::bit(64)::bigint::numeric), 0) AS d FROM %s t', name),
      false, true, '') AS counted
    FROM (
      SELECT format('%I.%I', n.nspname, c.relname) AS name
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE c.relkind = 'r' AND n.nspname IN ('public', 'drizzle')
    ) tables
  ) each
  ORDER BY name`;

/** What `client` reads of its database, in the transaction it has open. */
export async function readFacts(client: pg.ClientBase): Promise<Facts> {
  for (const statement of STABLE_TEXT) await client.query(statement);
  const tables = await client.query<{ name: string; rows: string; digest: string }>(TABLES);
  const ledger = await client.query<{ applied: number; last: string | null }>(
    "SELECT count(*)::int AS applied, (array_agg(hash ORDER BY id DESC))[1] AS last FROM drizzle.__drizzle_migrations",
  );
  const head = await client.query<{ next_seq: string; head: string }>("SELECT next_seq::text, encode(head_hash, 'hex') AS head FROM audit_chain_head");
  return {
    tables: Object.fromEntries(tables.rows.map((row) => [row.name, { rows: Number(row.rows), digest: row.digest }])),
    migrations: ledger.rows[0]!,
    log: head.rows[0] === undefined ? null : { nextSeq: head.rows[0].next_seq, head: head.rows[0].head },
  };
}

/** The migrations a ledger of `applied` ran, as this CLI names them: the newest's name. */
export function migrationName(applied: number): string {
  return applied === 0 ? 'no migration' : (KNOWN_MIGRATIONS.postgres[applied - 1] ?? `${applied} migrations, more than this CLI knows`);
}

/**
 * The tables whose rows row-level security hides from this login, if any:
 * the audit log, today, but any table the manifest counts. A login it
 * applies to sees only the rows its policies show it, and pg_dump, with
 * --enable-row-security, dumps only those, silently; the manifest, read as
 * the same login, would agree. It sees them all when a permissive policy
 * for one of its roles shows every row, as migration 0019's shows
 * coffre_backup the log's, and no restrictive one for them hides any: those
 * are ANDed on top (docs/restore.md).
 */
const HIDDEN = `
  SELECT format('%I.%I', n.nspname, c.relname) AS name
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind = 'r' AND n.nspname IN ('public', 'drizzle') AND row_security_active(c.oid) AND NOT (
    EXISTS (SELECT 1 FROM applies a WHERE a.oid = c.oid AND a.permissive AND a.whole)
    AND NOT EXISTS (SELECT 1 FROM applies a WHERE a.oid = c.oid AND NOT a.permissive AND NOT a.whole)
  )
  ORDER BY 1`;

const APPLIES = `
  WITH applies AS (
    SELECT p.polrelid AS oid, p.polpermissive AS permissive, coalesce(pg_get_expr(p.polqual, p.polrelid) = 'true', false) AS whole
    FROM pg_policy p
    WHERE p.polcmd IN ('r', '*')
      AND (0 = ANY (p.polroles) OR EXISTS (SELECT 1 FROM unnest(p.polroles) AS r (oid) WHERE r.oid <> 0 AND pg_has_role(r.oid, 'USAGE')))
  )`;

export class BackupError extends Error {}

/**
 * A PostgreSQL client tool, connected as `url` says, if it connects: the
 * password in PGPASSWORD, never an argument, where `ps` would show it. Its
 * stderr is kept, for the error; nothing it prints holds the password.
 */
export async function pgTool(tool: 'pg_dump' | 'pg_restore', args: readonly string[], url: URL | null): Promise<void> {
  let connection: string[] = [];
  const env = { ...process.env };
  if (url !== null) {
    // libpq takes passwords in the query too, `?password=…` and a client key's `?sslpassword=…`: moved out as well, or `ps` would show them.
    const bare = new URL(url.href);
    const password = bare.searchParams.get('password') ?? decodeURIComponent(url.password);
    const sslpassword = bare.searchParams.get('sslpassword');
    bare.password = '';
    bare.searchParams.delete('password');
    bare.searchParams.delete('sslpassword');
    connection = ['--no-password', `--dbname=${bare.href}`];
    env.PGPASSWORD = password;
    if (sslpassword !== null) env.PGSSLPASSWORD = sslpassword;
  }
  const child = spawn(tool, [...args, ...connection], { env, stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
  const code = await new Promise<number | null>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', resolve);
  }).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== 'ENOENT') throw error;
    throw new BackupError(`${tool} is not on PATH: coffre runs PostgreSQL's own, of the server's major version or newer. Install PostgreSQL's client tools`);
  });
  if (code !== 0) throw new BackupError(`${tool} failed: ${stderr.trim() || `exit ${code}`}`);
}

/** A file's SHA-256, hex, read as a stream: a dump may be larger than memory. */
export async function sha256(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

/** `12,345`: a count as people read it. */
export function counted(n: number | bigint | string): string {
  return BigInt(n).toLocaleString('en-US');
}

/** `11.5 MB`. */
export function size(bytes: number): string {
  return bytes < 1e6 ? `${(bytes / 1e3).toFixed(1)} kB` : `${(bytes / 1e6).toFixed(1)} MB`;
}

export async function backup(args: string[]): Promise<void> {
  const out = process.stderr;
  const s = style(out);
  const secrets: string[] = [];
  const made: string[] = [];
  try {
    const { positionals } = parseArgs({ args, allowPositionals: true, options: {} });
    if (positionals.length > 1) throw new BackupError('usage: coffre backup [<file>]');
    const file = positionals[0] ?? `coffre-${new Date().toISOString().replace(/[-:]/g, '').slice(0, 13)}Z.dump`;
    const manifestFile = manifestPath(file);
    // Made first, for this user alone and only if new: a dump holds plain values in the clear, and an older one is never overwritten.
    for (const path of [file, manifestFile]) {
      try {
        closeSync(openSync(path, 'wx', 0o600));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
        throw new BackupError(`${path} already exists: coffre backup writes only a new file`);
      }
      made.push(path);
    }

    const { url, secrets: typed } = await readDatabaseUrl(out, s, {
      question: "The backup login's connection string",
      hint: 'Hidden as you type. A login in coffre_backup, direct: it reads every row and writes none.',
      command: 'coffre backup',
    });
    secrets.push(...typed);
    const database = `${url.hostname}${decodeURIComponent(url.pathname)}`;
    const login = decodeURIComponent(url.username);

    const client = new pg.Client({ ...postgresConnection(url.href), application_name: 'coffre backup' });
    await client.connect();
    let facts: Facts;
    let takenAt: string;
    try {
      // The snapshot stays open while pg_dump reads in it. A migration queued for an exclusive lock between the
      // two would wait on this session while pg_dump waited on it, and the app's writes behind both: so this
      // session waits 30 seconds at most for a lock, and pg_dump as long, and the server ends this one if it
      // sits idle past 10 minutes, as it does once this process is gone.
      await client.query("SET lock_timeout = '30s'");
      await client.query("SET idle_in_transaction_session_timeout = '10min'");
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY');
      // The transaction's start is the snapshot's moment: what the backup holds is the database as it was then.
      const { id: snapshot, at } = (await client.query<{ id: string; at: Date }>('SELECT pg_export_snapshot() AS id, now() AS at')).rows[0]!;
      takenAt = at.toISOString();
      facts = await readFacts(client).catch((error: unknown) => {
        // The one table this login may not read is one coffre's migrations did not make; pg_dump would stop at it too.
        if ((error as { code?: string }).code !== '42501') throw error;
        throw new BackupError(
          `${(error as Error).message}, as ${login}: coffre_backup reads coffre's own tables, and pg_dump would stop at this one too. ` +
            'Grant it SELECT to coffre_backup, or move it out of this database',
        );
      });
      const hidden = (await client.query<{ name: string }>(`${APPLIES} ${HIDDEN}`)).rows.map((row) => row.name);
      if (hidden.length > 0) {
        const log = hidden.includes('public.audit_log') ? `, ${counted(facts.tables['public.audit_log']?.rows ?? 0)} of the log's ${counted(facts.log?.nextSeq ?? 0)} entries among them` : '';
        throw new BackupError(
          `row-level security hides rows of ${listed(hidden, 'and')} from ${login}, and no policy shows it all of them: pg_dump would dump only those it sees${log}, ` +
            "and say nothing. Back up as a login in coffre_backup, whose policies show it every row: `coffre migrate --backup-login <login>` grants it the group (docs/restore.md)",
        );
      }
      // A statement a minute while pg_dump reads: the session is never idle that long, however long the dump takes.
      const awake = setInterval(() => client.query('SELECT 1').catch(() => {}), 60_000);
      try {
        await pgTool('pg_dump', [`--snapshot=${snapshot}`, '--enable-row-security', '--lock-wait-timeout=30s', '--format=custom', `--file=${file}`], url);
      } finally {
        clearInterval(awake);
      }
      await client.query('COMMIT');
    } finally {
      await client.end().catch(() => {});
    }
    // pg_dump wrote into the file made above, keeping its mode; chmod again in case it made its own.
    chmodSync(file, 0o600);
    const bytes = statSync(file).size;
    const manifest: Manifest = {
      format: MANIFEST_FORMAT,
      coffre: cliVersion(),
      takenAt,
      database,
      login,
      dump: { file: basename(file), bytes, sha256: await sha256(file) },
      ...facts,
    };
    writeFileSync(manifestFile, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
    made.length = 0;
    const rows = Object.values(facts.tables).reduce((sum, table) => sum + table.rows, 0);
    const log = facts.log === null ? 'no audit log head' : facts.log.nextSeq === '0' ? 'an empty audit log' : `the audit log through entry ${counted(BigInt(facts.log.nextSeq) - 1n)}`;
    out.write(
      `${s.green('✓')} Backed up ${database} to ${file}, ${size(bytes)}: ${counted(rows)} rows in ${Object.keys(facts.tables).length} tables, ` +
        `${log}, at ${migrationName(facts.migrations.applied)}\n`,
    );
    out.write(`  ${s.dim(`What it holds is in ${manifestFile}; \`coffre verify backup ${file}\` restores a copy and checks it.`)}\n`);
  } catch (error) {
    for (const path of made) rmSync(path, { force: true });
    if (error instanceof Cancelled) return fail(out, 'cancelled; nothing was written', 130);
    const message = error instanceof Error ? error.message : String(error);
    return fail(out, secrets.filter((secret) => secret.length > 0).reduce((shown, secret) => shown.split(secret).join('…'), message));
  }
}

function fail(out: Output, message: string, code = 1): never {
  out.write(`${style(out).red('✗')} ${message}\n`);
  process.exit(code);
}
