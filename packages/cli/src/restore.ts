// `coffre restore` and `coffre verify backup`: a dump `coffre backup` made,
// restored into an empty database with PostgreSQL's own pg_restore, then
// held to its manifest. Restore brings the database back for a deployment
// to run on, its grants and row policies with it, and says what is left to
// do; verify restores a copy only to check it, without owners, grants or
// policies, so it needs none of coffre's roles on the server it uses.
//
// Without a key, the checks are what a backup holds and anyone may check:
// the dump is the one described, every table has its rows (counted and
// hashed), the migrations and the log's head are the same, and the log's
// chain runs whole from its first entry to the head. With `--keys`, the
// vault key and the app key, from hidden prompts or stdin, never the command
// line, also open every version of every value and authenticate the log's
// entries: who wrote them, not only where they sit.
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { parseArgs } from 'node:util';

import { deriveLogKey, GENESIS_HASH, verifyEntries, type Author, type LogKey, type StoredEntry } from '@coffre/core/audit';
import { decrypt, ownerKey, type SecretContext } from '@coffre/core/envelope';
import { derivedSigningKey, KekBadClaimError, LocalKekProvider } from '@coffre/core/kek';
import { MOVES_FROM } from '@coffre/db/log';
import { postgresClient, postgresSession, type PostgresClient } from '@coffre/db/connect';

import { BackupError, counted, type Facts, type Manifest, MANIFEST_FORMAT, manifestPath, migrationName, pgTool, readFacts, sha256, size } from './backup.ts';
import { databaseUrl, DatabaseUrlError, readDatabaseUrl, urlSecrets } from './database-url.ts';
import { Cancelled, hiddenLine, listed, type Output, style } from './tty.ts';
import { Checks, Failure, Skip } from './verify/checks.ts';
import { decoded } from './verify/keys.ts';

/**
 * The keys `--keys` asks for, as typed: each author's, the current one and
 * any it replaced, separated by spaces; either may be empty, skipped.
 */
type Keys = { vault: string; app: string };

/** The roles coffre's migrations make, which a dump's grants and policies name. */
const COFFRE_ROLES = ['coffre_app', 'coffre_vault', 'coffre_backup'];

/** How a dump comes back: for a deployment, or as a copy to check. */
type Mode = 'restore' | 'verify';

export async function restore(args: string[]): Promise<void> {
  return run('restore', args);
}

export async function verifyBackup(args: string[]): Promise<void> {
  return run('verify', args);
}

async function run(mode: Mode, args: string[]): Promise<void> {
  const out = process.stderr;
  const s = style(out);
  const secrets: string[] = [];
  try {
    const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { keys: { type: 'boolean', default: false } } });
    if (positionals.length !== 1) throw new BackupError(`usage: coffre ${mode === 'restore' ? 'restore' : 'verify backup'} <dump> [--keys]`);
    const dump = positionals[0]!;
    const manifest = readManifest(dump);

    const inputs = await readInputs(out, values.keys, mode === 'restore' ? 'coffre restore' : 'coffre verify backup');
    secrets.push(...inputs.secrets);
    const { url } = inputs;
    const database = `${url.hostname}${decodeURIComponent(url.pathname)}`;
    out.write(`${s.bold(`${mode === 'restore' ? 'Restoring' : 'Checking'} ${dump}`)}, ${s.dim(`taken ${manifest.takenAt} from ${manifest.database}, into ${database}`)}\n`);

    const report = new Checks(out);
    const whole = await report.check('dump', {}, async () => {
      await checkDump(dump, manifest);
      return { detail: `the one its manifest describes, ${size(manifest.dump.bytes)}, sha256 ${manifest.dump.sha256.slice(0, 12)}…`, value: true };
    });
    if (whole === undefined) process.exit(1);
    await restoreInto(dump, url, mode);
    out.write(`  ${s.green('✓')} ${'restored'.padEnd(19)} into ${database}, ${mode === 'restore' ? 'as its owner, with its grants and row policies' : 'without owners, grants or row policies'}\n`);
    await checkRestored(report, url, manifest, inputs.keys);

    if (report.failed.length > 0) {
      // The facts all matching, a broken chain is the backup's own: the database it was taken from had it too.
      const said = report.failed.length === 1 && report.failed[0] === 'audit log'
        ? `The backup's audit log is broken, as the database it was taken from had it: \`coffre verify log\` there says where.`
        : `${database} does not hold what the backup does: ${listed(report.failed, 'and')} failed.`;
      const stays = mode === 'restore' ? ` What was restored stays in ${database}: drop it, and create it again, to restore once more.` : '';
      out.write(`\n${s.red('✗')} ${s.bold(said)}${stays}\n`);
      process.exitCode = 1;
      return;
    }
    if (mode === 'verify') {
      out.write(`\n${s.green('✓')} ${s.bold(`The backup restores whole.`)} ${s.dim(`The copy stays in ${database}: drop it when done.`)}\n`);
      return;
    }
    out.write(`\n${s.green('✓')} ${s.bold(`${database} holds what the backup does.`)} Left to do before traffic, in the deployment's folder:\n`);
    for (const [i, step] of LEFT_TO_DO.entries()) out.write(`  ${i + 1}. ${step}\n`);
  } catch (error) {
    if (error instanceof Cancelled) {
      out.write(`${s.red('✗')} cancelled\n`);
      process.exit(130);
    }
    const message = error instanceof Error ? error.message : String(error);
    const shown = secrets.filter((secret) => secret.length > 0).reduce((text, secret) => text.split(secret).join('…'), message);
    out.write(`${s.red('✗')} ${shown}\n`);
    process.exit(1);
  }
}

/** What a restore leaves to do, which neither a dump nor this command can (docs/restore.md). */
const LEFT_TO_DO = [
  '`pnpm exec coffre setup --reset-passwords` where the runtime logins\' passwords changed (a new server; PlanetScale resets them), ' +
    "or else `pnpm exec coffre migrate`: either migrates, and reasserts the database's own privileges, which a dump of one database leaves out; " +
    'add --backup-login <login> to grant the backup login its group on this server',
  'Point both components at it, each with its own login: on Workers the three Hyperdrive configs, coffre, coffre-vault and coffre-vault-hot, as setup shows; ' +
    'on Node, DATABASE_URL in .env and vault.env, and HOT_DATABASE_URL in vault.env',
  'Redeploy or restart both, with the same keys and settings',
  '`coffre verify log`, then `coffre verify keys`, before reopening traffic',
];

/** The manifest beside `dump`, as `coffre backup` wrote it. */
export function readManifest(dump: string): Manifest {
  const path = manifestPath(dump);
  let manifest: Manifest;
  try {
    manifest = JSON.parse(readFileSync(path, 'utf8')) as Manifest;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new BackupError(`no ${path} beside the dump: coffre restores and checks only what \`coffre backup\` made, with its manifest. pg_restore restores any other (docs/restore.md)`);
    }
    throw new BackupError(`${path} is not a manifest: ${(error as Error).message}`);
  }
  if (manifest?.format !== MANIFEST_FORMAT) throw new BackupError(`${path} is not a manifest this CLI reads: its format is ${String(manifest?.format)}, not ${MANIFEST_FORMAT}`);
  const { dump: file, tables, migrations, log } = manifest;
  const missing = [
    typeof file?.bytes === 'number' && typeof file.sha256 === 'string' ? null : 'dump',
    typeof tables === 'object' && tables !== null && Object.values(tables).every((table) => typeof table?.rows === 'number' && typeof table.digest === 'string') ? null : 'tables',
    typeof migrations?.applied === 'number' && (migrations.last === null || typeof migrations.last === 'string') ? null : 'migrations',
    log === null || (typeof log?.nextSeq === 'string' && typeof log.head === 'string') ? null : 'log',
  ].filter((field) => field !== null);
  if (missing.length > 0) throw new BackupError(`${path} is not a whole manifest: it lacks ${listed(missing, 'and')}`);
  return manifest;
}

/** The dump is the one its manifest describes, byte for byte. */
async function checkDump(dump: string, manifest: Manifest): Promise<void> {
  const bytes = statSync(dump).size;
  if (bytes !== manifest.dump.bytes) throw new Failure(`${dump} is ${counted(bytes)} bytes, and the backup made ${counted(manifest.dump.bytes)}: not the dump its manifest describes`);
  if ((await sha256(dump)) !== manifest.dump.sha256) throw new Failure(`${dump} is not the dump its manifest describes: its SHA-256 differs`);
}

const NO_KEYS = '--keys, and no key given: give the vault keys, the app keys or both, or leave --keys out to check without them';

/**
 * The connection string, and with `--keys` the two keys: hidden prompts on
 * a terminal, or stdin's lines in order. Every form of each, for the caller
 * to keep out of what it shows.
 */
async function readInputs(out: Output, withKeys: boolean, command: string): Promise<{ url: URL; secrets: string[]; keys: Keys | null }> {
  const s = style(out);
  const asking = {
    question: "The empty database's owner connection string",
    hint: 'Hidden as you type. The login that will own its tables, direct: not a runtime login, not Hyperdrive.',
    command,
  };
  if (!withKeys) return { ...(await readDatabaseUrl(out, s, asking)), keys: null };
  if (process.stdin.isTTY) {
    const { url, secrets } = await readDatabaseUrl(out, s, asking);
    const hint = (earlier: string) => `The one it signs with now, then ${earlier}, separated by spaces. Hidden, kept on this machine. Enter alone skips.`;
    const vault = await hiddenLine(process.stdin, out, s, 'Vault keys?', hint('any it replaced: its own signing key first, if its config gives one'));
    const app = await hiddenLine(process.stdin, out, s, 'App keys?', hint('any it replaced'));
    if (words(vault).length === 0 && words(app).length === 0) throw new BackupError(NO_KEYS);
    return { url, secrets: [...secrets, ...words(vault), ...words(app)], keys: { vault, app } };
  }
  const lines = readFileSync(0, 'utf8').split(/\r?\n/).map((line) => line.trim());
  if (!lines[0]) throw new DatabaseUrlError(`no connection string: pipe it in on the first line, the vault key and the app key on the next two, or run ${command} on a terminal`);
  const url = databaseUrl(lines[0], command);
  const keys = { vault: lines[1] ?? '', app: lines[2] ?? '' };
  if (words(keys.vault).length === 0 && words(keys.app).length === 0) throw new BackupError(NO_KEYS);
  return { url, secrets: [...urlSecrets(lines[0], url), ...words(keys.vault), ...words(keys.app)], keys };
}

/**
 * Restore `dump` into the empty database `url` names, in one transaction:
 * one that fails leaves it empty. A deployment's restore keeps the grants
 * and row policies, which name coffre's roles; a check's leaves them out,
 * and every owner, so that it needs no role at all. Every object belongs to
 * whoever restores, either way: the owner the deployment migrates as.
 */
async function restoreInto(dump: string, url: URL, mode: Mode): Promise<void> {
  const client = postgresClient(url.href, { max: 1, application_name: 'coffre restore' });
  try {
    const found = await client.unsafe<{ name: string }[]>(`
      SELECT format('%I.%I', n.nspname, c.relname) AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname IN ('public', 'drizzle') AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
      UNION ALL SELECT 'the schema drizzle' FROM pg_namespace WHERE nspname = 'drizzle'
      ORDER BY 1`);
    if (found.length > 0) {
      const names = found.slice(0, 3).map((row) => row.name);
      throw new BackupError(
        `${decodeURIComponent(url.pathname.slice(1))} is not empty: it holds ${listed(found.length > 3 ? [...names, `${found.length - 3} more`] : names, 'and')}. ` +
          'Restore into a new database: createdb, as the owner',
      );
    }
  } finally {
    await client.end().catch(() => {});
  }
  const options = ['--no-owner', '--exit-on-error', '--single-transaction'];
  let list: string | null = null;
  try {
    if (mode === 'verify') {
      // The table of contents without its row policies, which name roles; --no-acl leaves out the grants.
      list = join(mkdtempSync(join(tmpdir(), 'coffre-restore-')), 'toc.list');
      await pgTool('pg_restore', ['--list', `--file=${list}`, dump], null);
      // An entry's line is `<id>; <oid> <oid> <type> …`: only the type says it is a policy, not a name that holds the word.
      writeFileSync(list, readFileSync(list, 'utf8').split('\n').filter((line) => !/^\d+; \d+ \d+ POLICY /.test(line)).join('\n'));
      options.push('--no-acl', `--use-list=${list}`);
    }
    await pgTool('pg_restore', [...options, dump], url);
  } catch (error) {
    const said = error instanceof Error ? error.message : '';
    if (/unrecognized configuration parameter/.test(said)) {
      throw new BackupError(`${said}\nThis pg_restore is newer than the server, and sends a setting it lacks, so nothing was restored: restore with the pg_restore of the server's major version`);
    }
    const role = /role "([^"]+)" does not exist/.exec(said)?.[1];
    if (role === undefined) throw error;
    if (!COFFRE_ROLES.includes(role)) {
      throw new BackupError(
        `this server has no role ${role}, so nothing was restored. It owned the database backed up, and its default privileges name it ` +
          `(ALTER DEFAULT PRIVILEGES FOR ROLE ${role}), which no restore by another owner leaves out: restore as ${role}, or create that role first, ` +
          'and make it a member of the login restoring',
      );
    }
    throw new BackupError(
      `this server has no role ${role}, which the backup's grants name, so nothing was restored. Make coffre's roles first: ` +
        '`coffre migrate` once against another, empty database on this server makes the group roles, and the logins are made as in docs/restore.md. ' +
        '`coffre verify backup` checks a dump with no role at all',
    );
  } finally {
    if (list !== null) rmSync(dirname(list), { recursive: true, force: true });
  }
}

/**
 * Hold the restored database to the manifest, each check a line of
 * `report`, in one snapshot. With keys, the values and the log's authors
 * too.
 */
async function checkRestored(report: Checks, url: URL, manifest: Manifest, keys: Keys | null): Promise<void> {
  // One session, its snapshot read throughout: lost, every statement after fails rather than reading outside it.
  const client = postgresSession(url.href, { application_name: 'coffre restore' });
  try {
    await client.unsafe('BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY');
    const facts = await readFacts(client);
    await report.check('rows', {}, async () => rowsVerdict(manifest, facts));
    await report.check('migrations', {}, async () => {
      const { applied, last } = facts.migrations;
      if (applied !== manifest.migrations.applied || last !== manifest.migrations.last) {
        throw new Failure(`${applied} applied, the last ${last ?? 'none'}; the backup had ${manifest.migrations.applied}, the last ${manifest.migrations.last ?? 'none'}`);
      }
      return `${applied}, the last ${migrationName(applied)}, as backed up`;
    });
    await report.check('audit log', {}, async () => walkLog(client, manifest, facts, keys === null ? null : keysOf(keys)));
    if (keys !== null) await report.check('values', {}, async () => openValues(client, keys.vault));
    await client.unsafe('COMMIT');
  } finally {
    await client.end().catch(() => {});
  }
}

/** Every table's rows, as the backup counted and hashed them; what differs, by table. */
export function rowsVerdict(manifest: Pick<Manifest, 'tables'>, facts: Pick<Facts, 'tables'>): string {
  const names = [...new Set([...Object.keys(manifest.tables), ...Object.keys(facts.tables)])].sort();
  const differ = names.flatMap((name) => {
    const was = manifest.tables[name];
    const now = facts.tables[name];
    if (was === undefined) return [`${name}, which the backup does not hold`];
    if (now === undefined) return [`${name} is missing`];
    if (now.rows !== was.rows) return [`${name} has ${counted(now.rows)} ${now.rows === 1 ? 'row' : 'rows'}, and the backup ${counted(was.rows)}`];
    if (now.digest !== was.digest) return [`${name}'s ${counted(now.rows)} rows are not those backed up`];
    return [];
  });
  if (differ.length > 0) throw new Failure(`${differ.length === 1 ? 'one table differs' : `${differ.length} tables differ`}: ${differ.join('; ')}`);
  const rows = Object.values(facts.tables).reduce((sum, table) => sum + table.rows, 0);
  return `every table's, as backed up: ${counted(rows)} rows in ${names.length} tables`;
}

/** The keys on a line, separated by spaces. */
function words(line: string): string[] {
  return line.split(/\s+/).filter((word) => word !== '');
}

/** Each key on a line, decoded: 32 bytes in base64, or the line refused, saying which. */
function decodedKeys(line: string, what: string): Buffer[] {
  return words(line).map((text, i) => {
    const key = decoded(text);
    if (key === null) throw new Failure(`the ${ordinal(i)} ${what} is not one: one is 32 bytes in base64, 44 characters, and these ${text.length} characters are not`);
    return key;
  });
}

function ordinal(i: number): string {
  return ['first', 'second', 'third'][i] ?? `${i + 1}th`;
}

/**
 * The log keys the keys given stand for, by author, none for one skipped,
 * and the ids of those the first key typed makes: the one the author signs
 * with now. A vault key stands for two: the one its own signing key makes,
 * and, for a vault given a signing key of its own, that key's, typed as a
 * vault key.
 */
type LogKeys = Record<Author, LogKey[]> & { current: Record<Author, ReadonlySet<string>> };

function keysOf(keys: Keys): LogKeys {
  const app = decodedKeys(keys.app, 'app key').map((key) => [deriveLogKey('app', key)]);
  const vault = decodedKeys(keys.vault, 'vault key').map((key) => [deriveLogKey('vault', derivedSigningKey(key)), deriveLogKey('vault', key)]);
  const ids = (made: LogKey[][]) => new Set((made[0] ?? []).map((key) => key.keyId));
  return { app: app.flat(), vault: vault.flat(), current: { app: ids(app), vault: ids(vault) } };
}

const BATCH = 5000;

/** An author's entries as the walk saw them: by the keys given, and by others. */
/** `signs`: the one key id of the current key's that has written, once one has. */
type Tally = { authenticated: number; others: Map<string, number>; newest: string | null; moved: Set<string>; left: string[]; signs: string | null };

/**
 * The log, from its first entry to the head the manifest names: no gap,
 * every link and every hash, and each author's keys used as the online
 * verifiers allow them, which needs no key. The app's key writes nothing
 * from the first entry that moves on from it (`key.reseal`, `key.rotate`);
 * the vault's keys only move forward, so one it left never writes again.
 * With keys, each entry under one of them is authenticated by its MAC, the
 * others are linked only, and counted; each author's newest key must be one
 * given, or the keys given are not its current ones.
 */
async function walkLog(client: PostgresClient, manifest: Manifest, facts: Facts, keys: LogKeys | null): Promise<string> {
  if (manifest.log === null || facts.log === null) {
    if (manifest.log !== facts.log) throw new Failure(`the log's head is ${facts.log === null ? 'missing' : 'there'}, and the backup ${manifest.log === null ? 'had none' : 'had one'}`);
    throw new Skip('no log head, in the backup or here');
  }
  if (facts.log.nextSeq !== manifest.log.nextSeq || facts.log.head !== manifest.log.head) {
    throw new Failure(`the head is at entry ${facts.log.nextSeq}, ${facts.log.head.slice(0, 12)}…; the backup's was ${manifest.log.nextSeq}, ${manifest.log.head.slice(0, 12)}…`);
  }
  const given = keys === null ? [] : [...keys.app, ...keys.vault];
  const ids = new Set(given.map((key) => key.keyId));
  const tally: Record<Author, Tally> = {
    app: { authenticated: 0, others: new Map(), newest: null, moved: new Set(), left: [], signs: null },
    vault: { authenticated: 0, others: new Map(), newest: null, moved: new Set(), left: [], signs: null },
  };
  let at = { nextSeq: 0n, head: GENESIS_HASH };
  for (;;) {
    const batch = await entriesFrom(client, at.nextSeq);
    if (batch.length === 0) break;
    // Runs of entries alike, under a key given or not, each verified as one.
    for (let from = 0; from < batch.length; ) {
      const signed = ids.has(batch[from]!.keyId);
      let to = from + 1;
      while (to < batch.length && ids.has(batch[to]!.keyId) === signed) to += 1;
      const run = batch.slice(from, to);
      const result = verifyEntries(run, { startSeq: at.nextSeq, startPrevHash: at.head, keys: signed ? given : [], chainOnly: signed ? [] : ['app', 'vault'] });
      if (!result.ok) throw new Failure(`broken at entry ${result.failedAtSeq}: ${result.reason}`);
      for (const entry of run) {
        const author = tally[entry.author];
        keyOrder(entry, author, keys?.current[entry.author] ?? null);
        if (signed) author.authenticated += 1;
        else author.others.set(entry.keyId, (author.others.get(entry.keyId) ?? 0) + 1);
      }
      at = { nextSeq: result.nextSeq, head: result.head };
      from = to;
    }
  }
  if (at.nextSeq !== BigInt(manifest.log.nextSeq) || at.head.toString('hex') !== manifest.log.head) {
    throw new Failure(`the entries end at ${at.nextSeq - 1n}, ${at.head.toString('hex').slice(0, 12)}…, but the head says ${BigInt(manifest.log.nextSeq) - 1n}, ${manifest.log.head.slice(0, 12)}…`);
  }
  const chain = `${counted(at.nextSeq)} entries, every link and hash, from the first to the head, each key in its turn`;
  if (keys === null) return `${chain} (without keys: not who wrote them)`;
  const authors = (['app', 'vault'] as const).map((author) => {
    const { authenticated, others, newest } = tally[author];
    if (keys[author].length === 0) return `the ${author}'s not authenticated (no key given)`;
    if (newest === null) return `no entry by the ${author}`;
    if (tally[author].signs !== newest) {
      throw new Failure(`the ${author}'s newest entries are under ${newest}, which the first ${author} key given does not make: it is not the one the ${author} signs with now`);
    }
    const linked = [...others.values()].reduce((sum, n) => sum + n, 0);
    const before = linked === 0 ? '' : `, after ${counted(linked)} under keys not given, linked only (${listed([...others.keys()], 'and')})`;
    return `${counted(authenticated)} by the ${author}, each MAC checked${before}`;
  });
  return `${chain}; ${authors.join('; ')}`;
}

/**
 * Hold an entry to its author's keys' order, as the online verifiers do
 * (`verifyAppEntries` in @coffre/server, `forward` in @coffre/vault): the
 * app writes nothing under a key from the first entry that moves on from
 * it, that entry included; the vault never returns to a key it left. With
 * keys, `current` names the ids the key the author signs with now may
 * make, a vault key two: the first to write is the one, and once it has
 * written, no other writes again.
 */
function keyOrder(entry: StoredEntry, author: Tally, current: ReadonlySet<string> | null): void {
  if (author.signs !== null && entry.keyId !== author.signs) {
    throw new Failure(
      `broken at entry ${entry.seq}: written under ${entry.keyId} after the ${entry.author} signed with ${author.newest}, the key given as its current one: ` +
        `either that is not the one the ${entry.author} signs with now, or ${entry.keyId} wrote out of turn`,
    );
  }
  if (entry.author === 'app' && (MOVES_FROM as readonly string[]).includes(entry.action) && entry.subjectPrincipal !== null) author.moved.add(entry.subjectPrincipal);
  if (author.moved.has(entry.keyId)) {
    throw new Failure(`broken at entry ${entry.seq}: written under ${entry.keyId} after the app moved on from it: a key it replaced verifies only what came before`);
  }
  if (entry.author === 'vault' && entry.keyId !== author.newest) {
    if (author.left.includes(entry.keyId)) {
      throw new Failure(`broken at entry ${entry.seq}: written under ${entry.keyId} after the vault moved to ${author.newest}: a key it replaced verifies only what came before`);
    }
    if (author.newest !== null) author.left.push(author.newest);
  }
  if (author.signs === null && current?.has(entry.keyId)) author.signs = entry.keyId;
  author.newest = entry.keyId;
}

/** Up to a batch of the log's entries, from entry `from` on, as the chain covers them. */
async function entriesFrom(client: PostgresClient, from: bigint): Promise<StoredEntry[]> {
  const rows = await client.unsafe<Record<string, unknown>[]>(
    `SELECT e.seq::text AS seq, author, key_id, occurred_at::text, actor, action, decision, code, subject_principal, project_id, environment_id,
       secret_id, secret_version_id, operation_id, request_id, source_ip, related_seq::text, metadata, prev_hash, mac, hash
     FROM audit_log e WHERE e.seq >= $1 ORDER BY e.seq LIMIT ${BATCH}`,
    [from.toString()],
  );
  return rows.map((row) => ({
    seq: BigInt(row.seq as string),
    author: row.author as Author,
    keyId: row.key_id as string,
    occurredAt: Number(row.occurred_at),
    actor: row.actor as string,
    action: row.action as string,
    decision: row.decision as string,
    code: row.code as string | null,
    subjectPrincipal: row.subject_principal as string | null,
    projectId: row.project_id as string | null,
    environmentId: row.environment_id as string | null,
    secretId: row.secret_id as string | null,
    secretVersionId: row.secret_version_id as string | null,
    operationId: row.operation_id as string | null,
    requestId: row.request_id as string | null,
    sourceIp: row.source_ip as string | null,
    relatedSeq: row.related_seq === null ? null : BigInt(row.related_seq as string),
    metadata: row.metadata as string,
    prevHash: row.prev_hash as Buffer,
    mac: row.mac as Buffer,
    hash: row.hash as Buffer,
  }));
}

type VersionRow = {
  id: string;
  path: string;
  version: number;
  project_id: string;
  environment_id: string;
  secret_id: string;
  owner: string | null;
  sensitive: boolean;
  envelope_version: number;
  ciphertext: Buffer;
  iv: Buffer;
  auth_tag: Buffer;
  wrapped_dek: Buffer;
  kek_provider: string;
  kek_id: string;
  kek_version: string;
  plaintext: string | null;
};

/**
 * Every version of every value, opened as the vault opens it: its data key
 * unwrapped under the vault ID it names, bound to its ids, a personal
 * config's owner and whether it is sensitive, then the value decrypted,
 * which AES-GCM does only for the ciphertext written. Each vault ID is
 * tried with every key given until one opens it, then held to that one: a
 * vault keeps the keys it replaced, and each opens what it wrapped. A plain
 * value must read as the text kept beside it. What opens is never shown or
 * kept.
 */
async function openValues(client: PostgresClient, vaultKeys: string): Promise<string> {
  const keks = decodedKeys(vaultKeys, 'vault key');
  if (keks.length === 0) throw new Skip('not opened: no vault key given');
  // The provider that opened each vault ID and version: the others are tried again on each version none has opened yet.
  const providers = new Map<string, LocalKekProvider>();
  const failed: string[] = [];
  const elsewhere = new Map<string, number>();
  let opened = 0;
  let erased = 0;
  let after = '00000000-0000-0000-0000-000000000000';
  const open = async (provider: LocalKekProvider, row: VersionRow): Promise<'opened' | 'mismatch'> => {
    const ids = { projectId: row.project_id, environmentId: row.environment_id, secretId: row.secret_id };
    const context: SecretContext = { ...ids, ...(row.owner === null ? {} : { owner: ownerKey(row.owner) }), ...(row.sensitive ? { sensitive: true as const } : {}) };
    if (row.envelope_version !== 1) throw new KekBadClaimError(`envelope version ${row.envelope_version}`);
    const dek = await provider.unwrap({ kekProvider: row.kek_provider, kekId: row.kek_id, kekVersion: row.kek_version, bytes: row.wrapped_dek }, context);
    let value: Buffer | null = null;
    try {
      value = decrypt({ envelopeVersion: row.envelope_version, iv: row.iv, authTag: row.auth_tag, ciphertext: row.ciphertext }, ids, dek);
      return row.plaintext !== null && value.toString('utf8') !== row.plaintext ? 'mismatch' : 'opened';
    } finally {
      dek.fill(0);
      value?.fill(0);
    }
  };
  try {
    for (;;) {
      const rows = await client.unsafe<VersionRow[]>(
        `SELECT v.id, p.slug || '/' || e.slug || '/' || s.key AS path, v.version, s.project_id, s.environment_id, s.id AS secret_id, e.owner,
           v.sensitive, v.envelope_version, v.ciphertext, v.iv, v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version, v.plaintext
         FROM secret_versions v JOIN secrets s ON s.id = v.secret_id JOIN environments e ON e.id = s.environment_id JOIN projects p ON p.id = s.project_id
         WHERE v.id > $1 ORDER BY v.id LIMIT 1000`,
        [after],
      );
      if (rows.length === 0) break;
      after = rows.at(-1)!.id;
      for (const row of rows) {
        // Deleted for good: the version stays, as the log names it, with its value gone (`secret_versions_erase_only`).
        if (row.ciphertext.length === 0 && row.wrapped_dek.length === 0 && row.plaintext === null) {
          erased += 1;
          continue;
        }
        if (row.kek_provider !== 'local') {
          elsewhere.set(row.kek_provider, (elsewhere.get(row.kek_provider) ?? 0) + 1);
          continue;
        }
        const name = `${row.kek_id}\0${row.kek_version}`;
        const known = providers.get(name);
        const candidates = known !== undefined ? [known] : keks.map((kek) => new LocalKekProvider(kek, row.kek_id, row.kek_version));
        let outcome: 'opened' | 'mismatch' | null = null;
        for (const provider of candidates) {
          outcome = await open(provider, row).catch(() => null);
          if (outcome !== null) {
            providers.set(name, provider);
            break;
          }
        }
        const shown = `${row.path} v${row.version}`;
        if (outcome === 'opened') opened += 1;
        else failed.push(outcome === 'mismatch' ? `${shown}, whose plain text is not its value` : `${shown} (vault ID ${row.kek_id})`);
      }
    }
  } finally {
    for (const kek of keks) kek.fill(0);
  }
  const notHere = [...elsewhere].map(([provider, n]) => `${counted(n)} in ${provider}, which a key service keeps`);
  if (erased > 0) notHere.push(`${counted(erased)} erased, deleted for good`);
  if (failed.length > 0) {
    failed.sort();
    const shown = failed.length > 3 ? [...failed.slice(0, 3), `${counted(failed.length - 3)} more`] : failed;
    // None opening is the wrong key; some, a vault key it replaced missing.
    const why = opened === 0
      ? 'none of the vault keys given is this instance\'s'
      : 'those under an earlier vault ID open only with the vault key it names, which the vault keeps in previousKeks: give it too';
    throw new Failure(`${counted(failed.length)} of ${counted(failed.length + opened)} versions do not open with the vault keys given: ${listed(shown, 'and')}; ${why}`);
  }
  if (opened === 0) {
    if (elsewhere.size > 0) throw new Skip(`not opened: every version is wrapped in a key service or erased (${notHere.join(', ')})`);
    if (erased > 0) return `no value to open: ${notHere.join(', ')}`;
    return 'no value to open';
  }
  const ids = [...new Set([...providers.keys()].map((name) => name.split('\0')[0]!))];
  return `every one of ${counted(opened)} versions opens, under vault ID ${listed(ids, 'and')}, each plain one as its text${notHere.length > 0 ? `; not opened: ${notHere.join(', ')}` : ''}`;
}
