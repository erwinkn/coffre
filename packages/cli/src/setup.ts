// `coffre setup`: a deployment's database and keys, in one go. It asks for
// the database administrator's connection string, never on the command line;
// makes the two runtime logins, with fresh passwords that reach the database
// only as SCRAM verifiers; migrates as the administrator, with the
// migrations this CLI was built with; checks the boundary by connecting as
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

import { postgresConnection } from '@coffre/db/connect';
import { migrateDatabase, type MigrationPlan } from '@coffre/db/migrate';
import pg from 'pg';

import { readDatabaseUrl } from './database-url.ts';
import { deploymentKind, install, installAsLocked, installed } from './deployment.ts';
import { init, KINDS, type Kind } from './init.ts';
import { generateKeys, jsonWarning, keyGuide, keyValues, needsTerminal, type Keys } from './keys.ts';
import { type Screen, showSecrets, type Value } from './secrets.ts';
import { StepFailed, Steps } from './steps.ts';
import { Cancelled, type Keyboard, listed, openTerminal, type Output, paragraph, release, row, select, style, type Style } from './tty.ts';
import { cliVersion } from './version.ts';
import { Cloudflare, deployedSummary, Later } from './workers.ts';

/** The two runtime roles, as the migration names them, and the Hyperdrive config each gets on Workers. */
const ROLES = { app: 'coffre_runtime', vault: 'coffre_vault_runtime' } as const;
const HYPERDRIVE = { app: 'coffre', vault: 'coffre-vault' } as const;
type Component = keyof typeof ROLES;

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
  version: string;
  /** The most connections each Hyperdrive config may open (`hyperdriveLimit`); null when the database has too few for both. */
  hyperdriveLimit: number | null;
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

/** Connections the two Hyperdrive configs leave free: for the administrator, `coffre migrate` and the host's own tools. */
const HELD_BACK = 3;

/** The fewest connections Hyperdrive takes per config, and the most Free allows, which is plenty for coffre. */
const HYPERDRIVE_CONNECTIONS = { fewest: 5, most: 20 } as const;

/**
 * The most connections each of the two Hyperdrive configs may open, out of
 * the `budget` the database lets its logins open (`connectionBudget`):
 * an even share, less what is held back. Hyperdrive opens connections up to
 * its limit before it queues a query, and left at Cloudflare's default, 60
 * on Paid, the two configs outgrow a small database, such as PlanetScale's
 * smallest: it refuses the connection a burst of requests needs ("remaining
 * connection slots are reserved", 53300), and they fail. Under the limit, a
 * query waits its turn instead, which a query holding a connection only
 * while it runs keeps short. Null when the budget is short of the fewest.
 */
export function hyperdriveLimit(budget: number): number | null {
  const share = Math.floor((budget - HELD_BACK) / 2);
  return share < HYPERDRIVE_CONNECTIONS.fewest ? null : Math.min(share, HYPERDRIVE_CONNECTIONS.most);
}

/** Why a database with `budget` connections can have no Hyperdrive config for each login. */
export function tooFewConnections(budget: number): string {
  const needed = 2 * HYPERDRIVE_CONNECTIONS.fewest + HELD_BACK;
  return (
    `the database lets its logins open ${budget} connections, and Hyperdrive takes at least ${HYPERDRIVE_CONNECTIONS.fewest} for each of coffre's two configs, ` +
    `with ${HELD_BACK} left for the administrator: raise its max_connections by ${needed - budget}, or move to a larger plan`
  );
}

/** How many connections Postgres lets anyone but a superuser open: max_connections, less the slots it reserves. */
async function connectionBudget(client: pg.Client): Promise<number> {
  const [row] = (await client.query<{ budget: number }>(
    `SELECT current_setting('max_connections')::int
       - current_setting('superuser_reserved_connections')::int
       - coalesce(current_setting('reserved_connections', true), '0')::int AS budget`,
  )).rows;
  return row!.budget;
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
    let cloudflare: Cloudflare | null = null;
    if (offers && kind === 'workers') {
      const choice = await select(terminal.keys, out, s, 'Set Cloudflare up too?', [
        'Yes: Hyperdrive, GitHub sign-in, the keys as secrets, and the deploy',
        "No, I'll do Cloudflare myself",
      ]);
      if (choice === 0) {
        // Cloudflare goes through the deployment's own wrangler, which a fresh clone has yet to install.
        await installFirst(dir, out, clean);
        cloudflare = await Cloudflare.connect(dir, out, terminal.keys, clean, secrets, administrator);
      }
    }
    const result = await run(administrator, out, questions, { resetPasswords: options.resetPasswords, cloudflare }, secrets, clean);
    if (cloudflare !== null) {
      if (cloudflare.keys !== null) await showSecrets(terminal!, cloudflare.screen());
      await cloudflare.deploy(out, clean, terminal!.keys, { rotateDeployToken: options.rotateDeployToken });
      out.write(deployedSummary(cloudflare, out));
    } else if (options.json) {
      jsonWarning(process.stderr, listed(shownNames(result), 'and'));
      process.stdout.write(`${JSON.stringify(asJson(result))}\n`);
    } else if (result.keys === null && result.app.url === null && result.vault.url === null) {
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
  options: { resetPasswords: boolean; cloudflare: Cloudflare | null },
  secrets: string[],
  clean: (error: unknown) => string,
): Promise<SetupResult> {
  const { cloudflare } = options;
  const user = decodeURIComponent(administrator.username);
  const where = `${administrator.hostname}${decodeURIComponent(administrator.pathname)}`;
  const version = cliVersion();
  const steps = new Steps(
    out,
    [
      `Connect to ${where}`,
      `Check ${user} can create roles`,
      'Make the two logins',
      'Migrate the database',
      "Check each login's rights",
      ...(cloudflare === null ? [] : Cloudflare.TITLES),
    ],
    questions,
    clean,
  );
  const step = (i: number, work: Parameters<Steps['run']>[1]) => steps.run(i, work);

  const client = new pg.Client({ ...postgresConnection(administrator.href), application_name: 'coffre-setup' });
  let budget = 0;
  try {
    await step(0, async () => {
      await client.connect();
      budget = await connectionBudget(client);
      // Before anything changes: a Worker without its key, over a database that holds data, stops setup here.
      cloudflare?.checkKeys(await holdsData(client));
      return `Connected to ${where} as ${user}`;
    });
    await step(1, async () => {
      const [self] = (await client.query<{ rolsuper: boolean; rolcreaterole: boolean }>(
        'SELECT rolsuper, rolcreaterole FROM pg_roles WHERE rolname = current_user',
      )).rows;
      if (!self?.rolsuper && !self?.rolcreaterole) {
        throw new SetupError(`${user} cannot create roles: connect as the database's administrator, which has CREATEROLE`);
      }
      return `${user} can create roles`;
    });
    let logins!: Record<Component, Login>;
    await step(2, async (progress) => {
      // On Cloudflare, a login gets a new password when its Hyperdrive config needs one: the database keeps only its verifier.
      const reset =
        cloudflare === null
          ? async (existing: ReadonlySet<string>) => {
              const all =
                options.resetPasswords ||
                (existing.size > 0 &&
                  (await progress.ask(existing.size === 1 ? `${[...existing][0]} exists already. Set new passwords?` : 'Both logins exist already. Set new passwords?')));
              return () => all;
            }
          : async (existing: ReadonlySet<string>) => {
              const resets = {} as Record<Component, boolean>;
              for (const component of ['app', 'vault'] as const) {
                const login = loginFor(ROLES[component], user);
                resets[component] = options.resetPasswords || cloudflare.needsPassword(component, administrator, login);
                // Both checked before either changes: another deployment's login is never given a new password.
                if (resets[component] && existing.has(ROLES[component])) cloudflare.refuseShared(component, administrator, login);
              }
              return (component: Component) => resets[component];
            };
      logins = await provision(client, administrator, user, reset, secrets);
      return described(logins);
    });
    await step(3, async (progress) => {
      let plan: MigrationPlan = { applied: 0, total: 0, pending: [] };
      await migrateDatabase(administrator.href, (planned) => {
        plan = planned;
        const pending = planned.total - planned.applied;
        progress.note(pending === 0 ? 'Checking the database is up to date' : `Migrating the database: ${count(pending, 'migration')} to apply`);
      });
      const pending = plan.total - plan.applied;
      return pending === 0
        ? `The database is up to date, at coffre ${version}'s schema`
        : `Migrated the database to coffre ${version}'s schema: ${count(pending, 'migration')} applied`;
    });
    let used = false;
    await step(4, async () => {
      const details: string[] = [];
      for (const component of ['app', 'vault'] as const) {
        const login = logins[component];
        const allowed = login.url === null ? await granted(client, login.role) : await probed(login.url);
        details.push(checked(component, login, allowed));
      }
      const kept = [logins.app, logins.vault].filter((login) => login.url === null);
      if (kept.length > 0) details.push(`${listed(kept.map(({ role }) => role), 'and')}: from the catalog, with no new password to log in with`);
      used = await holdsData(client);
      return { text: 'Each login holds only its rights', details };
    });
    if (cloudflare !== null) {
      await step(5, async () => {
        const limit = hyperdriveLimit(budget);
        if (limit === null) throw new SetupError(tooFewConnections(budget));
        return cloudflare.hyperdrive(logins, limit);
      });
      await step(6, (progress) => cloudflare.github(progress, { aside: (text) => steps.aside(text), link: (label, address) => steps.link(label, address) }));
      await step(7, async () => cloudflare.write());
      return { keys: null, ...logins, version, hyperdriveLimit: hyperdriveLimit(budget) };
    }
    // Keys come with new passwords, for a database that holds no data yet: one that does has its keys already.
    const fresh = !used && (logins.app.url !== null || logins.vault.url !== null);
    return { keys: fresh ? generateKeys() : null, ...logins, version, hyperdriveLimit: hyperdriveLimit(budget) };
  } finally {
    steps.end();
    await client.end().catch(() => {});
  }
}

/** Whether the database holds data: coffre's log has an entry. Before the first migration, it holds none. */
async function holdsData(client: pg.Client): Promise<boolean> {
  const [migrated] = (await client.query<{ migrated: boolean }>("SELECT to_regclass('public.audit_log') IS NOT NULL AS migrated")).rows;
  if (!migrated!.migrated) return false;
  return (await client.query<{ used: boolean }>('SELECT EXISTS (SELECT 1 FROM audit_log) AS used')).rows[0]!.used;
}

/**
 * Each runtime login, created with a fresh password, or, if it exists, its
 * password set again when `reset`, given the logins that exist, says so;
 * otherwise left as it is.
 */
async function provision(
  client: pg.Client,
  administrator: URL,
  user: string,
  reset: (existing: ReadonlySet<string>) => Promise<(component: Component) => boolean>,
  secrets: string[],
): Promise<Record<Component, Login>> {
  const existing = new Set(
    (await client.query<{ rolname: string }>('SELECT rolname FROM pg_roles WHERE rolname = ANY($1)', [Object.values(ROLES)])).rows.map(
      (row) => row.rolname,
    ),
  );
  const resets = await reset(existing);
  const logins = {} as Record<Component, Login>;
  for (const component of ['app', 'vault'] as const) {
    const role = ROLES[component];
    const login = loginFor(role, user);
    const create = !existing.has(role);
    if (!create && !resets(component)) {
      logins[component] = { role, login, password: 'kept', url: null };
      continue;
    }
    const password = newPassword();
    secrets.push(password);
    const verifier = client.escapeLiteral(scramVerifier(password));
    // The superuser-only attributes are off by default, and a managed owner may not name them, even to turn them off.
    await client.query(
      create
        ? `CREATE ROLE ${client.escapeIdentifier(role)} LOGIN INHERIT NOCREATEDB NOCREATEROLE PASSWORD ${verifier}`
        : `ALTER ROLE ${client.escapeIdentifier(role)} LOGIN PASSWORD ${verifier}`,
    );
    logins[component] = { role, login, password: create ? 'created' : 'reset', url: loginUrl(administrator, login, password) };
  }
  return logins;
}

/** The logins step's line: what happened to each, and what they log in as on PlanetScale. */
function described(logins: Record<Component, Login>): { text: string; details: string[] } {
  const verbs = { created: 'Created', reset: 'Set new passwords for', kept: 'Kept' } as const;
  const both = logins.app.password === logins.vault.password;
  const text = both
    ? `${verbs[logins.app.password]} ${logins.app.role} and ${logins.vault.role}${logins.app.password === 'kept' ? ', with their passwords' : ''}`
    : `${verbs[logins.app.password]} ${logins.app.role}; ${verbs[logins.vault.password].toLowerCase()} ${logins.vault.role}`;
  const branch = logins.app.login !== logins.app.role ? [`They log in as ${logins.app.login} and ${logins.vault.login}`] : [];
  return { text, details: branch };
}

// --- the boundary ------------------------------------------------------------------

/** What each login may do that matters, and what it must answer. */
const BOUNDARY = [
  {
    what: 'write members',
    expected: { app: false, vault: true },
    // A whole row, so that only a privilege can refuse it.
    sql: `INSERT INTO vault_members (principal, status, owner, generation, created_at, created_by, status_changed_at, status_changed_by, access_seq, mac)
          VALUES ('user:coffre-setup@probe.invalid', 'active', false, 0, 0, 'system:coffre-setup', 0, 'system:coffre-setup', 0, decode(repeat('00', 32), 'hex'))`,
    privilege: "has_table_privilege($1, 'public.vault_members', 'INSERT')",
  },
  {
    what: 'delete log entries',
    expected: { app: false, vault: false },
    sql: 'DELETE FROM audit_log',
    privilege: "has_table_privilege($1, 'public.audit_log', 'DELETE')",
  },
  {
    what: 'create tables',
    expected: { app: false, vault: false },
    sql: 'CREATE TABLE coffre_setup_probe (probe integer)',
    privilege: "has_schema_privilege($1, 'public', 'CREATE') OR has_database_privilege($1, current_database(), 'CREATE')",
  },
] as const;

/** Each probe, tried as the login in a transaction rolled back: allowed, or refused for want of a privilege. */
async function probed(url: string): Promise<boolean[]> {
  const client = new pg.Client({ ...postgresConnection(url), application_name: 'coffre-setup' });
  await client.connect();
  try {
    const allowed: boolean[] = [];
    for (const { sql } of BOUNDARY) {
      await client.query('BEGIN');
      try {
        await client.query(sql);
        allowed.push(true);
      } catch (error) {
        if ((error as { code?: string }).code !== '42501') throw error;
        allowed.push(false);
      } finally {
        await client.query('ROLLBACK');
      }
    }
    return allowed;
  } finally {
    await client.end();
  }
}

/** The same, from the catalog, for a login whose password this run did not set: the administrator asks for it. */
async function granted(client: pg.Client, role: string): Promise<boolean[]> {
  const allowed: boolean[] = [];
  for (const { privilege } of BOUNDARY) {
    allowed.push((await client.query<{ allowed: boolean }>(`SELECT ${privilege} AS allowed`, [role])).rows[0]!.allowed);
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

/** The values to save, by component: the app's key and URL, the vault's ID, key and URL, as this run made them. */
export function setupValues({ keys, app, vault }: SetupResult): { app: Value[]; vault: Value[] } {
  const made = keys === null ? { app: [], vault: [] } : keyValues(keys);
  const database = (login: Login, component: Component): Value[] =>
    login.url === null
      ? []
      : [
          {
            label: `${component === 'app' ? 'App' : 'Vault'} database URL`,
            value: login.url,
            mask: 'password',
            about: `The ${component}'s own database login. Goes in the ${component}: its Hyperdrive config, or DATABASE_URL.`,
          },
        ];
  return {
    app: [...made.app, ...database(app, 'app')],
    vault: [...made.vault, ...database(vault, 'vault')],
  };
}

/** The screen: the values, and where each goes, with the Hyperdrive commands to copy. */
export function setupScreen(result: SetupResult): Screen {
  const { app, vault } = setupValues(result);
  const set = (['app', 'vault'] as const).filter((component) => result[component].url !== null);
  const created = set.some((component) => result[component].password === 'created');
  const keys = keyGuide();
  const hyperdrive = set.map((component) => {
    const login = result[component];
    const target = login.password === 'created' ? `create ${HYPERDRIVE[component]} --caching-disabled` : `update <the ${component}'s config id>`;
    return { command: hyperdriveCommand(target, result.hyperdriveLimit) };
  });
  const workers = [
    ...(set.length === 0
      ? []
      : [
          `${created ? 'A Hyperdrive config for each database URL, with caching off' : 'Each Hyperdrive config, pointed at its new database URL'}. Run each command, then paste its URL at the silent prompt: it stays out of your shell's history, and the command drops the URL's parameters, since Hyperdrive connects over TLS itself.`,
          ...hyperdrive.flatMap((command, i) => [`The ${set[i]} database URL:`, command]),
          'Or make them in the Cloudflare dashboard, under Hyperdrive.',
          ...(created ? ['Their ids go under hyperdrive, in app/wrangler.jsonc and vault/wrangler.jsonc.'] : []),
        ]),
    ...(result.keys === null ? [] : keys.workers),
  ];
  const node = [
    ...(result.keys === null ? [] : keys.node),
    ...set.map((component) => `${component === 'app' ? '.env' : 'vault.env'} takes the ${component} database URL, as DATABASE_URL.`),
    'Keep each file readable only by its process (chmod 600).',
  ];
  return {
    title: 'coffre setup',
    sections: [
      ...(app.length > 0 ? [{ title: 'App', values: app }] : []),
      ...(vault.length > 0 ? [{ title: 'Vault', values: vault }] : []),
    ],
    guide: [
      { title: 'On Cloudflare Workers', lines: workers },
      { title: 'On Node', lines: node },
    ],
  };
}

/** What the values were, by name, for the --json warning. */
function shownNames(result: SetupResult): string[] {
  const { app, vault } = setupValues(result);
  return [...app, ...vault].filter(({ mask }) => mask !== 'none').map(({ label }) => `the ${label.replace(/^[A-Z]/, (c) => c.toLowerCase())}`);
}

/** The same values, for a script: each component's, under the examples' names, and what happened to each login. */
export function asJson({ keys, app, vault }: SetupResult) {
  const database = (login: Login) => (login.url === null ? {} : { DATABASE_URL: login.url });
  return {
    app: { ...(keys === null ? {} : { APP_KEY: keys.APP_KEY }), ...database(app) },
    vault: { ...(keys === null ? {} : { VAULT_KEY_ID: keys.VAULT_KEY_ID, VAULT_KEY: keys.VAULT_KEY }), ...database(vault) },
    logins: Object.fromEntries([app, vault].map(({ role, login, password }) => [role, { login, password }])),
  };
}

/** After the screen: what happened, and what comes next, with no secret in it. */
export function summary(result: SetupResult, out: Output): string {
  const s = style(out);
  const { app, vault } = setupValues(result);
  const names = [...app, ...vault].filter(({ mask }) => mask !== 'none').map(({ label }) => label.replace(/^[A-Z]/, (c) => c.toLowerCase()));
  const created = result.app.password === 'created' || result.vault.password === 'created';
  const reset = result.app.password === 'reset' || result.vault.password === 'reset';
  const workers = [
    ...(created ? ['a Hyperdrive config for each database URL, with caching off'] : reset ? ['each Hyperdrive config updated with its new database URL'] : []),
    ...(result.keys === null ? [] : ['VAULT_KEY_ID under vars', 'APP_KEY and VAULT_KEY as secrets']),
  ];
  const fresh = created || result.keys !== null;
  return [
    '',
    `  ${s.green('✓')} ${s.bold(`The ${listed(names, 'and')} were shown once.`)}`,
    s.dim(paragraph(out, "They aren't stored anywhere. A lost database URL comes back with coffre setup --reset-passwords; a lost key can't be recovered.", 4)),
    '',
    ...(result.keys === null ? [] : [row(out, s, 'Vault ID', `${result.keys.VAULT_KEY_ID}, not a secret`), '']),
    `    ${s.bold('Next')}`,
    row(out, s, 'Workers', `${workers.join('; ')}${fresh ? '; then pnpm run deploy' : ', which needs no redeploy'}.`),
    row(out, s, 'Node', fresh ? '.env and vault.env, then pnpm vault and pnpm start.' : 'each DATABASE_URL updated, then both processes restarted.'),
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

function count(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`;
}

