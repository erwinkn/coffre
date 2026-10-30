// `coffre setup`: a deployment's database and keys, in one go. It asks for
// the database administrator's connection string, never on the command line;
// makes the three runtime logins and the backup login, with fresh passwords
// that reach the database only as SCRAM verifiers; migrates as the
// administrator, with the migrations this CLI was built with, granting the
// backup login its read-only group; checks the boundary by connecting as
// each login; then shows every value once, on a screen of their own, and
// writes no file.
//
// In an empty directory, it first makes a deployment there. In a Workers
// deployment, on a terminal, it offers to do Cloudflare too (workers.ts):
// then the database URLs go straight to Hyperdrive, and the keys, once
// shown, to the Workers it deploys; a GitHub repository then deploys on
// every push (deploy-on-push.ts).
import { createHash, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

import { postgresClient, postgresSession, quoteIdentifier, quoteLiteral, type PostgresClient } from '@coffre/db/connect';
import { migrateDatabase, type MigrationPlan } from '@coffre/db/migrate';

import { cappedLimit, type Connections, connectionsOf, hyperdriveLimit, limitReason, tooFewConnections } from './connections.ts';
import { readDatabaseUrl } from './database-url.ts';
import { deploymentKind, install, installAsLocked, installed } from './deployment.ts';
import { init, KINDS, type Kind } from './init.ts';
import { generateKeys, jsonWarning, keyGuide, keyValues, needsTerminal, type Keys } from './keys.ts';
import { type GuideBlock, type Screen, showSecrets, type Value } from './secrets.ts';
import { StepFailed, Steps } from './steps.ts';
import { Cancelled, type Keyboard, listed, openTerminal, type Output, paragraph, release, row, select, style, type Style } from './tty.ts';
import { cliVersion } from './version.ts';
import { Cloudflare, type Database, deployedSummary, Later } from './workers.ts';

/**
 * The three runtime roles, as the migrations name them, and the Hyperdrive
 * config each gets on Workers: the app's, the vault's, and the vault's hot
 * path's, 0.15's uses, which 0022 makes unable to log in. And the backup
 * login, which `coffre_backup` lets read every row for `coffre backup`, and
 * which no Worker uses.
 */
const ROLES = { app: 'coffre_runtime', vault: 'coffre_vault_runtime', hot: 'coffre_vault_hot', backup: 'coffre_backup_login' } as const;
const HYPERDRIVE = { app: 'coffre', vault: 'coffre-vault', hot: 'coffre-vault-hot' } as const;
type Component = keyof typeof ROLES;
const COMPONENTS = ['app', 'vault', 'hot', 'backup'] as const;
/** The logins that run, each with a Hyperdrive config of its own on Workers. */
type Runtime = Exclude<Component, 'backup'>;
const RUNTIMES = ['app', 'vault', 'hot'] as const;
/** The logins a run gives a password unasked when they cannot log in: nothing logs in as them yet (`provision`). */
const UNASKED = new Set<Component>(['hot', 'backup']);

/** What happened to a login's password: set on a new login, set again on one that existed, or left alone. */
export type Password = 'created' | 'reset' | 'kept';

export type Login = {
  role: string;
  /** What it connects as: its role, with the branch on PlanetScale (`loginFor`). */
  login: string;
  password: Password;
  /** Its connection string, when this run set its password: the only time it can be shown. */
  url: string | null;
};

export type SetupResult = {
  keys: Keys | null;
  app: Login;
  vault: Login;
  hot: Login;
  backup: Login;
  version: string;
  /** What the database lets in, which each Hyperdrive config's limit is a share of (`hyperdriveLimit`). */
  connections: Connections;
};

class SetupError extends Error {}

/**
 * The name a role logs in as. On PlanetScale Postgres, a login names its
 * branch: the administrator connects as `postgres.<branch id>`, and every
 * role on that branch as `<role>.<branch id>`. Elsewhere, the role's name.
 */
export function loginFor(role: string, administrator: string): string {
  const dot = administrator.indexOf('.');
  return dot === -1 ? role : `${role}${administrator.slice(dot)}`;
}

/** The administrator's URL, as `login` with `password`: same host, database and TLS settings. */
export function loginUrl(administrator: URL, login: string, password: string): string {
  const url = new URL(administrator.href);
  url.username = encodeURIComponent(login);
  url.password = password;
  return url.href;
}

/**
 * A wrangler hyperdrive command that reads the URL at a silent prompt, so
 * that no password reaches the shell's history, and drops its parameters:
 * Hyperdrive connects over TLS itself, checking the certificate against
 * public CAs, and takes no `sslrootcert`. `${v%%[?]*}` holds in bash and
 * zsh alike.
 */
export function hyperdriveCommand(target: string, limit: number | null): string {
  const connections = limit === null ? '' : ` --origin-connection-limit=${limit}`;
  return `read -rs COFFRE_DB_URL && pnpm exec wrangler hyperdrive ${target}${connections} --connection-string="\${COFFRE_DB_URL%%[?]*}"; unset COFFRE_DB_URL`;
}

/**
 * What Postgres keeps for a password under SCRAM-SHA-256 (RFC 5802 and
 * 7677), made here, so that the password itself never reaches the server,
 * nor its logs.
 */
export function scramVerifier(password: string, salt = randomBytes(16), iterations = 4096): string {
  const salted = pbkdf2Sync(password, salt, iterations, 32, 'sha256');
  const stored = createHash('sha256').update(createHmac('sha256', salted).update('Client Key').digest()).digest();
  const server = createHmac('sha256', salted).update('Server Key').digest();
  return `SCRAM-SHA-256$${iterations}:${salt.toString('base64')}$${stored.toString('base64')}:${server.toString('base64')}`;
}

/** 24 random bytes, URL-safe: nothing to encode in a connection string. */
function newPassword(): string {
  return randomBytes(24).toString('base64url');
}

// --- the command ---------------------------------------------------------------

export async function setup(args: string[]): Promise<void> {
  const secrets: string[] = [];
  const clean = (error: unknown) => redact(error instanceof Error ? error.message : String(error), secrets);
  let options: Options;
  try {
    options = parseOptions(args);
  } catch (error) {
    return fail(process.stderr, clean(error));
  }
  // Before anything changes: values made with nowhere to show them would be lost.
  const terminal = options.json ? null : openTerminal();
  if (!options.json && terminal === null) return fail(process.stderr, needsTerminal('coffre setup'));
  const out = terminal?.out ?? process.stderr;
  const s = style(out);
  // Questions take the screen's keyboard, or, with --json, stdin when it is a terminal.
  const questions = (): Keyboard | null => terminal?.keys ?? (process.stdin.isTTY ? process.stdin : null);
  const dir = process.cwd();
  let kind = deploymentKind(dir);
  // Cloudflare, on a terminal only, and not on Windows, where wrangler cannot read its secrets from /dev/stdin.
  const offers = terminal !== null && process.platform !== 'win32';
  try {
    const about = offers && (kind === 'workers' || kind === 'empty') ? "a deployment's database, keys and Cloudflare" : "a deployment's database logins, migrations and keys";
    if (s.ansi) out.write(`\n  ${s.bold('coffre setup')}  ${s.dim(about)}\n\n`);
    if (kind === 'empty' && terminal !== null) kind = await scaffold(dir, terminal.keys, out, clean);
    const { url: administrator, secrets: typed } = await readDatabaseUrl(out, s, {
      question: "The database administrator's connection string",
      hint: "Hidden as you type. Your host's admin URL, such as PlanetScale's Connect page gives.",
      command: 'coffre setup',
    });
    secrets.push(...typed);
    // What the database refuses, it refuses here, before setup asks about Cloudflare.
    const database = await inspect(administrator, kind === 'workers', out, clean);
    let cloudflare: Cloudflare | null = null;
    if (offers && kind === 'workers') {
      const choice = await select(terminal.keys, out, s, 'Set Cloudflare up too?', [
        'Yes: Hyperdrive, GitHub sign-in, the keys as secrets, and the deploy',
        "No, I'll do Cloudflare myself",
      ]);
      if (choice === 0) {
        // Cloudflare goes through the deployment's own wrangler, which a fresh clone has yet to install.
        await installFirst(dir, out, clean);
        cloudflare = await Cloudflare.connect(dir, out, terminal.keys, clean, secrets, asRead(administrator, database.used, database.existing), {
          resetPasswords: options.resetPasswords,
        });
      }
    }
    const result = await run(administrator, out, questions, { resetPasswords: options.resetPasswords, cloudflare, connections: database.connections }, secrets, clean);
    if (cloudflare !== null) {
      if (cloudflare.keys !== null || result.backup.url !== null) await showSecrets(terminal!, cloudflare.screen(result.backup.url === null ? null : { values: backupValues(result.backup), guide: BACKUP_GUIDE }));
      // Saved now: only then does the backup login take the password shown (`run`).
      if (result.backup.url !== null) await activate(administrator, result.backup, out, clean);
      await cloudflare.deploy(out, clean, terminal!.keys, { rotateDeployToken: options.rotateDeployToken });
      out.write(deployedSummary(cloudflare, out, result.backup.url !== null));
    } else if (options.json) {
      jsonWarning(process.stderr, listed(shownNames(result), 'and'));
      process.stdout.write(`${JSON.stringify(asJson(result))}\n`);
    } else if (result.keys === null && COMPONENTS.every((component) => result[component].url === null)) {
      out.write(nothingToSave(out));
    } else {
      await showSecrets(terminal!, setupScreen(result));
      out.write(summary(result, out));
    }
  } catch (error) {
    if (error instanceof Cancelled) return fail(out, 'cancelled; nothing after the last step done was changed', 130);
    // Stopped for what only its user can do, which it says: a run after carries on.
    if (error instanceof Later) {
      out.write(error.message);
      process.exit(0);
    }
    // A step shows its own failure; an error outside the steps is shown here.
    if (!(error instanceof StepFailed)) return fail(out, clean(error));
    process.exit(1);
  } finally {
    if (terminal !== null) release(terminal.keys);
  }
}

function fail(out: Output, message: string, code = 1): never {
  const s = style(out);
  out.write(`${s.red('✗')} ${message}\n`);
  process.exit(code);
}

type Options = { resetPasswords: boolean; rotateDeployToken: boolean; json: boolean };

function parseOptions(args: string[]): Options {
  try {
    const { values } = parseArgs({
      args,
      options: {
        'reset-passwords': { type: 'boolean', default: false },
        'rotate-deploy-token': { type: 'boolean', default: false },
        json: { type: 'boolean', default: false },
      },
      allowPositionals: false,
      strict: true,
    });
    return { resetPasswords: values['reset-passwords'], rotateDeployToken: values['rotate-deploy-token'], json: values.json };
  } catch {
    // The error would quote the argument, which may be the connection string itself.
    const leaked = args.some((arg) => /postgres(ql)?:|@/i.test(arg));
    throw new SetupError(
      `coffre setup takes only --reset-passwords, --rotate-deploy-token and --json. It asks for the administrator's connection string, at a hidden prompt or on stdin, ` +
        `never from the command line, where the shell's history and other users can read it.` +
        (leaked ? ' One of the arguments looks like one: change that password, which is in your shell history now.' : ''),
    );
  }
}

/**
 * In an empty directory, a deployment of the kind chosen, its files written
 * as `coffre init` writes them and its packages installed; or none.
 */
async function scaffold(dir: string, keys: Keyboard, out: Output, clean: (error: unknown) => string): Promise<Kind | 'empty'> {
  const s = style(out);
  const names = { workers: 'Cloudflare Workers', node: 'Node' } as const;
  const empty = existsSync(join(dir, '.git')) ? 'This directory holds only .git' : 'This directory is empty';
  const choice = await select(keys, out, s, `${empty}. Make a deployment of coffre here?`, [
    ...KINDS.map((kind) => names[kind]),
    'No, only the database',
  ]);
  const kind = KINDS[choice];
  if (kind === undefined) return 'empty';
  const steps = new Steps(out, [`Write a ${names[kind]} deployment`, 'Install its packages'], () => null, clean);
  try {
    await steps.run(0, async () => `Wrote a ${names[kind]} deployment: ${init(kind, dir, cliVersion()).length} files`);
    await steps.run(1, async () => {
      await install(dir);
      return 'Installed its packages, with pnpm';
    });
  } finally {
    steps.end();
  }
  out.write('\n');
  return kind;
}

/** The database as setup finds it: what it lets in, whether it holds data, and which of its logins exist. */
type Inspected = { connections: Connections; used: boolean; existing: ReadonlyMap<string, boolean> };

/**
 * The database, read before anything changes it or Cloudflare: the
 * administrator connects, and may create roles; a Workers deployment's
 * has room for all three Hyperdrive configs. Each refusal comes before
 * Cloudflare's questions, its domain added or a custom hostname made, and
 * before any login gets a new password its config would never have.
 */
async function inspect(administrator: URL, workers: boolean, out: Output, clean: (error: unknown) => string): Promise<Inspected> {
  const user = decodeURIComponent(administrator.username);
  const where = whereOf(administrator);
  const steps = new Steps(
    out,
    [`Connect to ${where}`, `Check ${user} can create roles`, ...(workers ? [`Check ${where} has room for Hyperdrive`] : [])],
    () => null,
    clean,
  );
  const client = postgresClient(administrator.href, { max: 1, application_name: 'coffre-setup' });
  let inspected!: Inspected;
  try {
    await steps.run(0, async () => {
      inspected = { connections: await connectionsOf(client), used: await holdsData(client), existing: await existingLogins(client) };
      return `Connected to ${where} as ${user}`;
    });
    await steps.run(1, async () => {
      const [self] = await client.unsafe<{ rolsuper: boolean; rolcreaterole: boolean }[]>(
        'SELECT rolsuper, rolcreaterole FROM pg_roles WHERE rolname = current_user',
      );
      if (!self?.rolsuper && !self?.rolcreaterole) {
        throw new SetupError(`${user} cannot create roles: connect as the database's administrator, which has CREATEROLE`);
      }
      return `${user} can create roles`;
    });
    if (workers) {
      await steps.run(2, async () => {
        const limit = hyperdriveLimit(inspected.connections);
        if (limit === null) throw new SetupError(tooFewConnections(inspected.connections));
        return `${where} has room for the three Hyperdrive configs, with a connection limit of ${limit} each`;
      });
    }
  } finally {
    steps.end();
    await client.end().catch(() => {});
  }
  return inspected;
}

/** The database setup was given, as its steps name it: `db.example.com/coffre`. */
function whereOf(administrator: URL): string {
  return `${administrator.hostname}${decodeURIComponent(administrator.pathname)}`;
}

/** The deployment's packages, installed as its lockfile says when they are not, shown as a step of its own. */
async function installFirst(dir: string, out: Output, clean: (error: unknown) => string): Promise<void> {
  if (installed(dir)) return;
  const steps = new Steps(out, ['Install its packages'], () => null, clean);
  try {
    await steps.run(0, async () => {
      await installAsLocked(dir);
      return existsSync(join(dir, 'pnpm-lock.yaml')) ? 'Installed its packages, as pnpm-lock.yaml says' : 'Installed its packages, with pnpm';
    });
  } finally {
    steps.end();
  }
}

async function run(
  administrator: URL,
  out: Output,
  questions: () => Keyboard | null,
  options: { resetPasswords: boolean; cloudflare: Cloudflare | null; connections: Connections },
  secrets: string[],
  clean: (error: unknown) => string,
): Promise<SetupResult> {
  const { cloudflare, connections } = options;
  const user = decodeURIComponent(administrator.username);
  const version = cliVersion();
  const steps = new Steps(
    out,
    [
      'Make the four logins',
      'Migrate the database',
      "Check each login's rights",
      ...(cloudflare === null ? [] : Cloudflare.TITLES),
    ],
    questions,
    clean,
  );
  const step = (i: number, work: Parameters<Steps['run']>[1]) => steps.run(i, work);

  const client = postgresClient(administrator.href, { max: 1, application_name: 'coffre-setup' });
  try {
    let logins!: Record<Component, Login>;
    await step(0, async (progress) => {
      // On Cloudflare, a login gets a new password when its Hyperdrive config needs one, as decided before Cloudflare changed (`newPasswords`).
      const reset =
        cloudflare === null
          ? async (existing: ReadonlyMap<string, boolean>) => {
              // A hot path's or backup login that cannot log in gets a password unasked (`provision`).
              const asked = COMPONENTS.filter((component) => existing.has(ROLES[component]) && !(UNASKED.has(component) && !existing.get(ROLES[component]))).map((component) => ROLES[component]);
              const all =
                options.resetPasswords ||
                (asked.length > 0 && (await progress.ask(`${listed(asked, 'and')} ${asked.length === 1 ? 'exists' : 'exist'} already. Set new passwords?`)));
              return () => all;
            }
          : async (existing: ReadonlyMap<string, boolean>) => {
              // Cloudflare's refusals again, against the database as it is now: it may have changed while setup asked its questions.
              cloudflare.recheck(asRead(administrator, await holdsData(client), existing));
              // No Hyperdrive config holds the backup login's password: only --reset-passwords sets a new one.
              return (component: Component) => (component === 'backup' ? options.resetPasswords : cloudflare.newPasswords[component]);
            };
      logins = await provision(client, administrator, user, reset, secrets, cloudflare !== null);
      return described(logins, cloudflare !== null);
    });
    await step(1, async (progress) => {
      let plan: MigrationPlan = { applied: 0, total: 0, pending: [] };
      await migrateDatabase(administrator.href, {
        backupLogin: ROLES.backup,
        onPlan(planned) {
          plan = planned;
          const pending = planned.total - planned.applied;
          progress.note(pending === 0 ? 'Checking the database is up to date' : `Migrating the database: ${count(pending, 'migration')} to apply`);
        },
      });
      const pending = plan.total - plan.applied;
      return {
        text:
          pending === 0
            ? `The database is up to date, at coffre ${version}'s schema`
            : `Migrated the database to coffre ${version}'s schema: ${count(pending, 'migration')} applied`,
        details: [`${ROLES.backup} is a member of coffre_backup, which reads every row and writes none`],
      };
    });
    let used = false;
    await step(2, async () => {
      const details: string[] = [];
      for (const component of COMPONENTS) {
        const login = logins[component];
        const allowed = login.url === null ? await granted(client, login.role) : await probed(login.url);
        details.push(checked(component, login, allowed));
      }
      const kept = COMPONENTS.map((component) => logins[component]).filter((login) => login.url === null && login.password === 'kept');
      if (kept.length > 0) details.push(`${listed(kept.map(({ role }) => role), 'and')}: from the catalog, with no new password to log in with`);
      if (logins.backup.url === null && logins.backup.password !== 'kept') details.push(`${logins.backup.role}: from the catalog, its password still to come`);
      used = await holdsData(client);
      return { text: 'Each login holds only its rights', details };
    });
    if (cloudflare !== null) {
      // Checked before Cloudflare was asked, and before any of this run's changes (`inspect`).
      const limit = hyperdriveLimit(connections)!;
      let low: Awaited<ReturnType<Cloudflare['hyperdrive']>>['low'] = [];
      await step(3, async () => {
        const made = await cloudflare.hyperdrive(logins, limit);
        low = made.low;
        return { text: made.text, details: [...made.details, limitReason(connections, limit)] };
      });
      // Printed whole, to copy: a step's lines are cut to the terminal's width.
      if (low.length > 0) {
        const one = low.length === 1;
        const names = listed(low.map(({ name }) => name), 'and');
        const limits = [...new Set(low.map(({ limit }) => limit))];
        const below = one
          ? `${names} is at ${low[0]!.limit} connections, below its share of ${limit}`
          : `${names} are at ${limits.length === 1 ? `${limits[0]} connections each` : `${listed(low.map(({ limit }) => String(limit)), 'and')} connections`}, below their share of ${limit}`;
        steps.aside(
          `${below}. Hyperdrive splits a config's connections among its shards, and a transaction holds one to its commit, a wait ` +
            'for a lock included: with few connections, one call waiting on the audit log stops every other on its shard. Unless the ' +
            `database serves more than coffre, raise ${one ? 'it' : 'them'}:`,
        );
        for (const { id } of low) steps.print(`  pnpm exec wrangler hyperdrive update ${id} --origin-connection-limit=${limit}`);
      }
      await step(4, (progress) => cloudflare.github(progress, { aside: (text) => steps.aside(text), link: (label, address) => steps.link(label, address) }));
      await step(5, async () => cloudflare.write());
      // The backup login's new password, to show: it takes it once saved (`activate`). A run that stops before leaves it as it was, or unable to log in, and the next run gives it one (`provision`).
      if (logins.backup.password !== 'kept') {
        const password = newPassword();
        secrets.push(password);
        logins.backup = { ...logins.backup, url: loginUrl(administrator, logins.backup.login, password) };
      }
      return { keys: null, ...logins, version, connections };
    }
    // Keys come with new passwords, for a database that holds no data yet: one that does has its keys already.
    const fresh = !used && (logins.app.url !== null || logins.vault.url !== null);
    return { keys: fresh ? generateKeys() : null, ...logins, version, connections };
  } finally {
    steps.end();
    await client.end().catch(() => {});
  }
}

/** Whether the database holds data: coffre's log has an entry. Before the first migration, it holds none. */
async function holdsData(client: PostgresClient): Promise<boolean> {
  const [migrated] = await client.unsafe<{ migrated: boolean }[]>("SELECT to_regclass('public.audit_log') IS NOT NULL AS migrated");
  if (!migrated!.migrated) return false;
  return (await client.unsafe<{ used: boolean }[]>('SELECT EXISTS (SELECT 1 FROM audit_log) AS used'))[0]!.used;
}

/** The database as Cloudflare's checks take it (`Database`). */
function asRead(administrator: URL, used: boolean, existing: ReadonlyMap<string, boolean>): Database {
  const user = decodeURIComponent(administrator.username);
  const login = (component: Runtime) => ({
    login: loginFor(ROLES[component], user),
    exists: existing.has(ROLES[component]),
    unlocks: UNASKED.has(component) && existing.get(ROLES[component]) === false,
  });
  return { administrator, used, logins: { app: login('app'), vault: login('vault'), hot: login('hot') } };
}

/** Coffre's logins that exist, by role, and whether each may log in. */
async function existingLogins(client: PostgresClient): Promise<Map<string, boolean>> {
  const rows = await client.unsafe<{ rolname: string; rolcanlogin: boolean }[]>('SELECT rolname, rolcanlogin FROM pg_roles WHERE rolname = ANY($1)', [Object.values(ROLES)]);
  return new Map(rows.map(({ rolname, rolcanlogin }) => [rolname, rolcanlogin]));
}

/**
 * Each login, created with a fresh password, or, if it exists, its
 * password set again when `reset`, given the logins that exist, says so;
 * otherwise left as it is. A backup login that cannot log in gets a
 * password too: a run that made it never showed one. So does the hot
 * path's, which 0022 made unable to log in: it is made a login, and said
 * created, as no Hyperdrive config can have logged in as it yet. The
 * hot path's made here, before the migrations, is one 0022 takes as a
 * host's, and grants coffre_vault. With `later`, on Cloudflare, the
 * backup login's password waits until the screen has shown it and it is
 * saved (`activate`): one made now cannot log in, and one that exists
 * keeps its password, until then.
 */
async function provision(
  client: PostgresClient,
  administrator: URL,
  user: string,
  reset: (existing: ReadonlyMap<string, boolean>) => Promise<(component: Component) => boolean>,
  secrets: string[],
  later: boolean,
): Promise<Record<Component, Login>> {
  const existing = await existingLogins(client);
  const resets = await reset(existing);
  const logins = {} as Record<Component, Login>;
  // The backup login and the hot path's first: the ones another role may have made, which this administrator may not change, refused before the others change.
  for (const component of ['backup', 'hot', 'app', 'vault'] as const) {
    const role = ROLES[component];
    const create = !existing.has(role);
    const locked = UNASKED.has(component) && existing.get(role) === false;
    const login: Login = { role, login: loginFor(role, user), password: create || (locked && component === 'hot') ? 'created' : 'reset', url: null };
    const sql = (attributes: string) =>
      `${create ? 'CREATE' : 'ALTER'} ROLE ${quoteIdentifier(role)} ${attributes}${create ? ' INHERIT NOCREATEDB NOCREATEROLE' : ''}`;
    if (!create && !locked && !resets(component)) {
      logins[component] = { ...login, password: 'kept' };
    } else if (component === 'backup' && later) {
      // Changes nothing to a login that exists, but is refused as the password would be.
      await changeRole(client, user, role, sql(create || locked ? 'NOLOGIN' : 'LOGIN'));
      logins[component] = login;
    } else {
      const password = newPassword();
      secrets.push(password);
      await changeRole(client, user, role, sql(`LOGIN PASSWORD ${quoteLiteral(scramVerifier(password))}`));
      logins[component] = { ...login, url: loginUrl(administrator, login.login, password) };
    }
  }
  return logins;
}

/**
 * A role made or changed. The superuser-only attributes are off by
 * default, and a managed owner may not name them, even to turn them off.
 * On Postgres 16 and later, changing a role another made takes its ADMIN.
 */
async function changeRole(client: PostgresClient, user: string, role: string, sql: string): Promise<void> {
  try {
    await client.unsafe(sql);
  } catch (error) {
    if ((error as { code?: string }).code !== '42501' || sql.startsWith('CREATE')) throw error;
    throw new SetupError(`${user} may not change ${role}, which another role made: have that role grant ${user} ADMIN on ${role}, or drop ${role}, then run coffre setup again`);
  }
}

/**
 * On Cloudflare, the backup login's password, once the screen has shown it
 * and it is saved: on a connection of its own, the run's having sat idle
 * through Cloudflare's steps; then checked as the login, as the boundary
 * step checks the others.
 */
async function activate(administrator: URL, backup: Login, out: Output, clean: (error: unknown) => string): Promise<void> {
  const user = decodeURIComponent(administrator.username);
  const steps = new Steps(out, [`Give ${backup.role} the password shown`], () => null, clean);
  const client = postgresClient(administrator.href, { max: 1, application_name: 'coffre-setup' });
  try {
    await steps.run(0, async () => {
      try {
        const verifier = quoteLiteral(scramVerifier(decodeURIComponent(new URL(backup.url!).password)));
        await changeRole(client, user, backup.role, `ALTER ROLE ${quoteIdentifier(backup.role)} LOGIN PASSWORD ${verifier}`);
      } catch (error) {
        throw new SetupError(
          `${clean(error)}. The password shown is not in effect: ${backup.role} ` +
            (backup.password === 'created' ? 'cannot log in, and coffre setup run again shows another.' : 'keeps its earlier one, and coffre setup --reset-passwords shows another.'),
        );
      }
      const allowed = await probed(backup.url!);
      checked('backup', backup, allowed);
      return `${backup.role} logs in with the password shown, and reads the log`;
    });
  } finally {
    steps.end();
    await client.end().catch(() => {});
  }
}

/**
 * The logins step's line: what happened to each, those alike together, and
 * what they log in as on PlanetScale. With `later`, the backup login's
 * password is still to come, and said apart.
 */
function described(logins: Record<Component, Login>, later: boolean): { text: string; details: string[] } {
  const verbs = { created: 'Created', reset: 'Set new passwords for', kept: 'Kept' } as const;
  const all = COMPONENTS.map((component) => logins[component]);
  const pending = later && logins.backup.password !== 'kept' ? logins.backup : null;
  const said = all.filter((login) => login !== pending);
  const happened = [...new Set(said.map(({ password }) => password))];
  const text = happened
    .map((password, i) => {
      const roles = said.filter((login) => login.password === password).map(({ role }) => role);
      const phrase = password === 'reset' && roles.length === 1 ? 'Set a new password for' : verbs[password];
      const verb = i === 0 ? phrase : phrase.toLowerCase();
      return `${verb} ${listed(roles, 'and')}${password === 'kept' ? `, with ${roles.length === 1 ? 'its password' : 'their passwords'}` : ''}`;
    })
    .join('; ');
  const after =
    pending === null
      ? []
      : [`${pending.role}: ${pending.password === 'created' ? 'made, unable to log in' : 'as it was'} until you have saved the password the screen shows`];
  const branch = logins.app.login !== logins.app.role ? [`They log in as ${listed(all.map(({ login }) => login), 'and')}`] : [];
  return { text, details: [...after, ...branch] };
}

// --- the boundary ------------------------------------------------------------------

/** What each login may do that matters, and what it must answer. */
const BOUNDARY = [
  {
    // The backup login's, through coffre_backup: --backup-login granted it.
    what: 'read the log',
    expected: { app: true, vault: true, hot: true, backup: true },
    sql: 'SELECT 1 FROM audit_log LIMIT 1',
    privilege: "has_table_privilege($1, 'public.audit_log', 'SELECT')",
  },
  {
    what: 'write members',
    // The hot path's, through coffre_vault, as the vault's.
    expected: { app: false, vault: true, hot: true, backup: false },
    // A whole row, so that only a privilege can refuse it.
    sql: `INSERT INTO vault_members (principal, status, owner, generation, created_at, created_by, status_changed_at, status_changed_by, access_seq, mac)
          VALUES ('user:coffre-setup@probe.invalid', 'active', false, 0, 0, 'system:coffre-setup', 0, 'system:coffre-setup', 0, decode(repeat('00', 32), 'hex'))`,
    privilege: "has_table_privilege($1, 'public.vault_members', 'INSERT')",
  },
  {
    what: 'delete log entries',
    expected: { app: false, vault: false, hot: false, backup: false },
    sql: 'DELETE FROM audit_log',
    privilege: "has_table_privilege($1, 'public.audit_log', 'DELETE')",
  },
  {
    what: 'create tables',
    expected: { app: false, vault: false, hot: false, backup: false },
    sql: 'CREATE TABLE coffre_setup_probe (probe integer)',
    privilege: "has_schema_privilege($1, 'public', 'CREATE') OR has_database_privilege($1, current_database(), 'CREATE')",
  },
] as const;

/** Each probe, tried as the login in a transaction rolled back: allowed, or refused for want of a privilege. */
async function probed(url: string): Promise<boolean[]> {
  // One session: a probe runs in the transaction rolled back after it, or not at all, never on a connection of its own.
  const client = postgresSession(url, { application_name: 'coffre-setup' });
  try {
    const allowed: boolean[] = [];
    for (const { sql } of BOUNDARY) {
      await client.unsafe('BEGIN');
      try {
        await client.unsafe(sql);
        allowed.push(true);
      } catch (error) {
        if ((error as { code?: string }).code !== '42501') throw error;
        allowed.push(false);
      } finally {
        await client.unsafe('ROLLBACK');
      }
    }
    return allowed;
  } finally {
    await client.end();
  }
}

/** The same, from the catalog, for a login whose password this run did not set: the administrator asks for it. */
async function granted(client: PostgresClient, role: string): Promise<boolean[]> {
  const allowed: boolean[] = [];
  for (const { privilege } of BOUNDARY) {
    allowed.push((await client.unsafe<{ allowed: boolean }[]>(`SELECT ${privilege} AS allowed`, [role]))[0]!.allowed);
  }
  return allowed;
}

/** A login's line under the check, or the error that stops setup when its rights are wrong. */
function checked(component: Component, login: Login, allowed: boolean[]): string {
  const wrong = BOUNDARY.flatMap(({ what, expected }, i) =>
    allowed[i] === expected[component] ? [] : [`${allowed[i] ? 'can' : 'cannot'} ${what}`],
  );
  if (wrong.length > 0) {
    throw new SetupError(
      `${login.role} ${wrong.join(', and ')}: the database's privileges are not what coffre needs. ` +
        'Nothing is shown: fix them, then run coffre setup again with --reset-passwords.',
    );
  }
  const can = BOUNDARY.filter(({ expected }) => expected[component]).map(({ what }) => what);
  const cannot = BOUNDARY.filter(({ expected }) => !expected[component]).map(({ what }) => what);
  return `${login.role.padEnd(20)} ${can.length > 0 ? `can ${listed(can, 'and')}; ` : ''}cannot ${listed(cannot, 'or')}`;
}

// --- what it shows -----------------------------------------------------------------

/** The backup login's URL, when this run set its password: for the backup job, never a Worker or a process. */
export function backupValues(backup: Login): Value[] {
  return backup.url === null
    ? []
    : [
        {
          label: 'Backup database URL',
          value: backup.url,
          mask: 'password',
          about: "The backup login's: reads every row, the log's included, and writes none. Goes where coffre backup runs, as a secret.",
        },
      ];
}

/** Each runtime login's URL, as the screen names it, and where it goes on Node: its file, under its variable. */
const RUNTIME_URLS = {
  app: { label: 'App database URL', file: '.env', variable: 'DATABASE_URL', about: "The app's own database login. Goes in the app: its Hyperdrive config, or DATABASE_URL." },
  vault: { label: 'Vault database URL', file: 'vault.env', variable: 'DATABASE_URL', about: "The vault's own database login. Goes in the vault: its Hyperdrive config, or DATABASE_URL." },
  hot: {
    label: 'Hot path database URL',
    file: 'vault.env',
    variable: 'HOT_DATABASE_URL',
    about: "The vault's login for 0.15's uses, unused until 0.15's log is the default. Goes in the vault: its second Hyperdrive config, HOT_HYPERDRIVE, or HOT_DATABASE_URL.",
  },
} as const satisfies Record<Runtime, { label: string; file: string; variable: string; about: string }>;

/** Whose each runtime login's config is, in a sentence's words. */
const OWNERS = { app: "the app's", vault: "the vault's", hot: "the hot path's" } as const satisfies Record<Runtime, string>;

/** The values to save, by section: the app's key and URL, the vault's ID, key and its two URLs, and the backup's URL, as this run made them. */
export function setupValues({ keys, app, vault, hot, backup }: SetupResult): Record<'app' | 'vault' | 'backup', Value[]> {
  const made = keys === null ? { app: [], vault: [] } : keyValues(keys);
  const database = (login: Login, component: Runtime): Value[] => {
    const { label, about } = RUNTIME_URLS[component];
    return login.url === null ? [] : [{ label, value: login.url, mask: 'password', about }];
  };
  return {
    app: [...made.app, ...database(app, 'app')],
    vault: [...made.vault, ...database(vault, 'vault'), ...database(hot, 'hot')],
    backup: backupValues(backup),
  };
}

/** Where the backup login's URL goes, on any platform. */
export const BACKUP_GUIDE: GuideBlock = {
  title: 'Backups',
  lines: [
    "The backup database URL goes in your backup job's secrets, never in a Worker or in .env: the job pipes it to coffre backup, which reads it on stdin. docs/restore.md has the job.",
  ],
};

/** The screen: the values, and where each goes, with the Hyperdrive commands to copy. */
export function setupScreen(result: SetupResult): Screen {
  const { app, vault, backup } = setupValues(result);
  const set = RUNTIMES.filter((component) => result[component].url !== null);
  const created = set.some((component) => result[component].password === 'created');
  const keys = keyGuide();
  const limit = hyperdriveLimit(result.connections);
  const updated = set.filter((component) => result[component].password !== 'created');
  // A config this run gave no new password: a share of fewer configs may have set its limit, above what each of three gets now.
  const kept = RUNTIMES.filter((component) => result[component].url === null);
  const hyperdrive = set.map((component) => {
    const login = result[component];
    const target = login.password === 'created' ? `create ${HYPERDRIVE[component]} --caching-disabled` : `update <${OWNERS[component]} config id>`;
    // Setup can't see what a config allows now, so an update sets the limit too (`cappedLimit`), and says so.
    return { command: hyperdriveCommand(target, limit === null ? null : cappedLimit(null, limit)) };
  });
  const workers = [
    ...(set.length === 0
      ? []
      : limit === null
        ? [`No Hyperdrive config for each database URL: ${tooFewConnections(result.connections)}.`]
        : [
            `${created ? 'A Hyperdrive config for each database URL, with caching off' : 'Each Hyperdrive config, pointed at its new database URL'}. Run each command, then paste its URL at the silent prompt: it stays out of your shell's history, and the command drops the URL's parameters, since Hyperdrive connects over TLS itself.`,
            ...(updated.length === 0
              ? []
              : [
                  `Setup can't see the limit each config has now, and the update ${updated.length === 1 ? 'command sets' : 'commands set'} it to ${limit}. Below that, a call waiting on a lock stops the others on its Hyperdrive shard: leave --origin-connection-limit out only for a config you keep lower because its database serves more than coffre (pnpm exec wrangler hyperdrive get <id> shows its limit).`,
                ]),
            ...hyperdrive.flatMap((command, i) => [`The ${lowered(RUNTIME_URLS[set[i]!].label)}:`, command]),
            `Each command sets its config's connection limit to ${limit}, so that all three configs fit under the database's max_connections, with some left for migrations (${limitReason(result.connections, limit)}).`,
            ...(kept.length === 0
              ? []
              : [
                  `${listed(kept.map((component) => OWNERS[component]), 'and').replace(/^t/, 'T')} ${kept.length === 1 ? 'config keeps its password, and its limit' : 'configs keep their passwords, and their limits'}, which setup can't see: one a share of two configs set may be above ${limit}. Lower ${kept.length === 1 ? 'it' : 'each'} to ${limit}, unless it is there or below already:`,
                  ...kept.map((component) => ({ command: `pnpm exec wrangler hyperdrive update <${OWNERS[component]} config id> --origin-connection-limit=${limit}` })),
                ]),
            'Or make them in the Cloudflare dashboard, under Hyperdrive.',
            ...(created ? ["Their ids go under hyperdrive: the app's in app/wrangler.jsonc, at HYPERDRIVE; the vault's and the hot path's in vault/wrangler.jsonc, at VAULT_HYPERDRIVE and HOT_HYPERDRIVE."] : []),
          ]),
    ...(result.keys === null ? [] : keys.workers),
  ];
  const node = [
    ...(result.keys === null ? [] : keys.node),
    ...set.map((component) => `${RUNTIME_URLS[component].file} takes the ${lowered(RUNTIME_URLS[component].label)}, as ${RUNTIME_URLS[component].variable}.`),
    'Keep each file readable only by its process (chmod 600).',
  ];
  return {
    title: 'coffre setup',
    sections: [
      ...(app.length > 0 ? [{ title: 'App', values: app }] : []),
      ...(vault.length > 0 ? [{ title: 'Vault', values: vault }] : []),
      ...(backup.length > 0 ? [{ title: 'Backup', values: backup }] : []),
    ],
    guide: [
      ...(app.length + vault.length > 0
        ? [
            { title: 'On Cloudflare Workers', lines: workers },
            { title: 'On Node', lines: node },
          ]
        : []),
      ...(backup.length > 0 ? [BACKUP_GUIDE] : []),
    ],
  };
}

/** What the values were, by name, for the --json warning. */
function shownNames(result: SetupResult): string[] {
  return Object.values(setupValues(result)).flat().filter(({ mask }) => mask !== 'none').map(({ label }) => `the ${lowered(label)}`);
}

/** The same values, for a script: each component's, under the examples' names, and what happened to each login. */
export function asJson({ keys, app, vault, hot, backup }: SetupResult) {
  const database = (login: Login) => (login.url === null ? {} : { DATABASE_URL: login.url });
  return {
    app: { ...(keys === null ? {} : { APP_KEY: keys.APP_KEY }), ...database(app) },
    vault: {
      ...(keys === null ? {} : { VAULT_KEY_ID: keys.VAULT_KEY_ID, VAULT_KEY: keys.VAULT_KEY }),
      ...database(vault),
      ...(hot.url === null ? {} : { HOT_DATABASE_URL: hot.url }),
    },
    backup: database(backup),
    logins: Object.fromEntries([app, vault, hot, backup].map(({ role, login, password }) => [role, { login, password }])),
  };
}

/** After the screen: what happened, and what comes next, with no secret in it. */
export function summary(result: SetupResult, out: Output): string {
  const s = style(out);
  const names = Object.values(setupValues(result)).flat().filter(({ mask }) => mask !== 'none').map(({ label }) => lowered(label));
  const set = RUNTIMES.filter((component) => result[component].url !== null);
  const created = set.filter((component) => result[component].password === 'created');
  const reset = set.filter((component) => result[component].password === 'reset');
  const workers = [
    ...(created.length === 0
      ? []
      : [`a Hyperdrive config for ${created.length === RUNTIMES.length ? 'each database URL' : `the ${listed(created.map((component) => lowered(RUNTIME_URLS[component].label)), 'and')}`}, with caching off`]),
    ...(reset.length === 0
      ? []
      : [reset.length === RUNTIMES.length
          ? 'each Hyperdrive config updated with its new database URL'
          : `${listed(reset.map((component) => OWNERS[component]), 'and')} ${reset.length === 1 ? 'config updated with its new database URL' : 'configs updated with their new database URLs'}`]),
    ...(result.keys === null ? [] : ['VAULT_KEY_ID under vars', 'APP_KEY and VAULT_KEY as secrets']),
  ];
  const fresh = created.length > 0 || result.keys !== null;
  // A new deployment's files, whole; else each URL that changed, and the processes that read it.
  const restarted = set.includes('app') ? (set.length === 1 ? 'the server' : 'both processes') : 'the vault';
  const node =
    result.keys !== null || created.includes('app') || created.includes('vault')
      ? '.env and vault.env, then pnpm vault and pnpm start.'
      : `${listed(set.map((component) => `${RUNTIME_URLS[component].variable} in ${RUNTIME_URLS[component].file}`), 'and')} updated, then ${restarted} restarted.`;
  // Only the backup login's URL, new: the app and the vault go on as they were.
  const runtime = result.keys !== null || set.length > 0;
  return [
    '',
    `  ${s.green('✓')} ${s.bold(`The ${listed(names, 'and')} ${names.length === 1 ? 'was' : 'were'} shown once.`)}`,
    s.dim(paragraph(out, `${names.length === 1 ? "It isn't" : "They aren't"} stored anywhere. A lost database URL comes back with coffre setup --reset-passwords; a lost key can't be recovered.`, 4)),
    '',
    ...(result.keys === null ? [] : [row(out, s, 'Vault ID', `${result.keys.VAULT_KEY_ID}, not a secret`), '']),
    `    ${s.bold('Next')}`,
    ...(runtime
      ? [
          row(out, s, 'Workers', `${workers.join('; ')}${fresh ? '; then pnpm run deploy' : ', which needs no redeploy'}.`),
          row(out, s, 'Node', node),
        ]
      : []),
    ...(result.backup.url === null ? [] : [row(out, s, 'Backups', "the backup database URL in your backup job's secrets, for coffre backup: docs/restore.md.")]),
    s.dim(paragraph(out, 'After every upgrade of coffre, pnpm exec coffre migrate --yes here first, then the deploy or the restart: until it runs, the new version serves nothing. docs/deploy.md has each step.', 4)),
    '',
    '',
  ].join('\n');
}

function nothingToSave(out: Output): string {
  const s = style(out);
  return [
    '',
    `  ${s.green('✓')} ${s.bold('Nothing new to save.')}`,
    s.dim(
      paragraph(
        out,
        'The logins kept their passwords, and setup makes keys only with new ones, for a database that holds no data yet. coffre setup --reset-passwords sets new passwords.',
        4,
      ),
    ),
    '',
    '',
  ].join('\n');
}

// --- plumbing ------------------------------------------------------------------------

/** An error's text without any secret in it: a driver may quote what it was given. */
function redact(text: string, secrets: readonly string[]): string {
  return secrets.filter((secret) => secret.length >= 4).reduce((out, secret) => out.split(secret).join('…'), text);
}

/** A label as a sentence's middle takes it: `the app database URL`. */
function lowered(label: string): string {
  return label.replace(/^[A-Z]/, (c) => c.toLowerCase());
}

function count(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`;
}

