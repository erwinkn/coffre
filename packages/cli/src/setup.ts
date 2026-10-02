// `coffre setup`: a deployment's database and keys, in one go. It asks for
// the database administrator's connection string, never on the command line;
// makes the two runtime logins, with fresh passwords that reach the database
// only as SCRAM verifiers; migrates as the administrator, with the
// migrations this CLI was built with; checks the boundary by connecting as
// each login; then shows every value once, on a screen of their own, and
// writes no file.
import { createHash, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import { postgresConnection } from '@coffre/db/connect';
import { migrateDatabase, type MigrationPlan } from '@coffre/db/migrate';
import pg from 'pg';

import { generateKeys, jsonWarning, keyGuide, keyValues, needsTerminal, type Keys } from './keys.ts';
import { type Screen, showSecrets, type Value } from './secrets.ts';
import { Steps } from './steps.ts';
import { Cancelled, hiddenLine, type Keyboard, openTerminal, type Output, paragraph, release, row, style, type Style } from './tty.ts';

/** Where the administrator's connection string comes from, when not from a hidden prompt. */
const URL_VARIABLE = 'COFFRE_SETUP_DATABASE_URL';

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

export type SetupResult = { keys: Keys | null; app: Login; vault: Login; version: string };

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
export function hyperdriveCommand(target: string): string {
  return `read -rs COFFRE_DB_URL && pnpm exec wrangler hyperdrive ${target} --connection-string="\${COFFRE_DB_URL%%[?]*}"; unset COFFRE_DB_URL`;
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
  let options: { resetPasswords: boolean; json: boolean };
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
  try {
    if (s.ansi) out.write(`\n  ${s.bold('coffre setup')}  ${s.dim("a deployment's database logins, migrations and keys")}\n\n`);
    const text = await readAdministrator(out, s);
    secrets.push(text);
    const administrator = administratorUrl(text);
    if (administrator.password !== '') secrets.push(administrator.password, decodeURIComponent(administrator.password));
    const result = await run(administrator, out, questions, { resetPasswords: options.resetPasswords }, secrets, clean);
    if (options.json) {
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
    // A step shows its own failure; an error before the steps is shown here.
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

function parseOptions(args: string[]): { resetPasswords: boolean; json: boolean } {
  try {
    const { values } = parseArgs({
      args,
      options: { 'reset-passwords': { type: 'boolean', default: false }, json: { type: 'boolean', default: false } },
      allowPositionals: false,
      strict: true,
    });
    return { resetPasswords: values['reset-passwords'], json: values.json };
  } catch {
    // The error would quote the argument, which may be the connection string itself.
    const leaked = args.some((arg) => /postgres(ql)?:|@/i.test(arg));
    throw new SetupError(
      `coffre setup takes only --reset-passwords and --json. It reads the administrator's connection string from a hidden prompt, ` +
        `${URL_VARIABLE} or stdin, never from the command line, where the shell's history and other users can read it.` +
        (leaked ? ' One of the arguments looks like one: change that password, which is in your shell history now.' : ''),
    );
  }
}

/** The connection string: from the environment, from stdin when it is piped, or typed at a hidden prompt. */
async function readAdministrator(out: Output, s: Style): Promise<string> {
  const given = process.env[URL_VARIABLE];
  delete process.env[URL_VARIABLE];
  if (given !== undefined && given.trim() !== '') return given.trim();
  if (!process.stdin.isTTY) {
    const line = readFileSync(0, 'utf8').split('\n').find((candidate) => candidate.trim() !== '');
    if (line === undefined) throw new SetupError(`no connection string: pipe it to stdin, or set ${URL_VARIABLE}`);
    return line.trim();
  }
  const text = await hiddenLine(
    process.stdin,
    out,
    s,
    "The database administrator's connection string",
    "Hidden as you type. Your host's admin URL, such as PlanetScale's Connect page gives.",
  );
  if (text === '') throw new SetupError('no connection string given');
  return text;
}

function administratorUrl(text: string): URL {
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new SetupError('that is not a connection string, such as postgresql://user:password@host:5432/database');
  }
  if (url.protocol !== 'postgres:' && url.protocol !== 'postgresql:') {
    throw new SetupError('coffre setup needs a Postgres connection string, postgresql://…');
  }
  if (url.username === '' || url.hostname === '' || url.pathname.length <= 1) {
    throw new SetupError('the connection string must name a user, a host and a database');
  }
  return url;
}

/** A step failed, and said so on its own line. */
class StepFailed extends Error {}

async function run(
  administrator: URL,
  out: Output,
  questions: () => Keyboard | null,
  options: { resetPasswords: boolean },
  secrets: string[],
  clean: (error: unknown) => string,
): Promise<SetupResult> {
  const user = decodeURIComponent(administrator.username);
  const where = `${administrator.hostname}${decodeURIComponent(administrator.pathname)}`;
  const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
  const steps = new Steps(
    out,
    [`Connect to ${where}`, `Check ${user} can create roles`, 'Make the two logins', 'Migrate the database', "Check each login's rights"],
    questions,
    clean,
  );
  const step = async (i: number, work: Parameters<Steps['run']>[1]) => {
    try {
      await steps.run(i, work);
    } catch (error) {
      if (error instanceof Cancelled) throw error;
      throw new StepFailed(clean(error));
    }
  };

  const client = new pg.Client({ ...postgresConnection(administrator.href), application_name: 'coffre-setup' });
  try {
    await step(0, async () => {
      await client.connect();
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
      logins = await provision(client, administrator, user, options.resetPasswords, progress.ask, secrets);
      return described(logins);
    });
    await step(3, async (progress) => {
      let plan: MigrationPlan = { applied: 0, total: 0 };
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
      used = (await client.query<{ used: boolean }>('SELECT EXISTS (SELECT 1 FROM audit_log) AS used')).rows[0]!.used;
      return { text: 'Each login holds only its rights', details };
    });
    // Keys come with new passwords, for a database that holds no data yet: one that does has its keys already.
    const fresh = !used && (logins.app.url !== null || logins.vault.url !== null);
    return { keys: fresh ? generateKeys() : null, ...logins, version };
  } finally {
    steps.end();
    await client.end().catch(() => {});
  }
}

/**
 * Each runtime login, created with a fresh password, or, if it exists, its
 * password set again when asked to; otherwise left as it is.
 */
async function provision(
  client: pg.Client,
  administrator: URL,
  user: string,
  resetPasswords: boolean,
  ask: (question: string) => Promise<boolean>,
  secrets: string[],
): Promise<Record<Component, Login>> {
  const existing = new Set(
    (await client.query<{ rolname: string }>('SELECT rolname FROM pg_roles WHERE rolname = ANY($1)', [Object.values(ROLES)])).rows.map(
      (row) => row.rolname,
    ),
  );
  const reset =
    resetPasswords ||
    (existing.size > 0 &&
      (await ask(existing.size === 1 ? `${[...existing][0]} exists already. Set new passwords?` : 'Both logins exist already. Set new passwords?')));
  const logins = {} as Record<Component, Login>;
  for (const component of ['app', 'vault'] as const) {
    const role = ROLES[component];
    const login = loginFor(role, user);
    const create = !existing.has(role);
    if (!create && !reset) {
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
    return { command: hyperdriveCommand(target) };
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
    ...set.map((component) => `${component === 'app' ? 'server.env' : 'vault.env'} takes the ${component} database URL, as DATABASE_URL.`),
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
    row(out, s, 'Node', fresh ? 'server.env and vault.env, then pnpm vault and pnpm start.' : 'each DATABASE_URL updated, then both processes restarted.'),
    s.dim(paragraph(out, 'After every upgrade of coffre, pnpm migrate. docs/deploy.md has each step.', 4)),
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

/** "a, b or c". */
function listed(items: readonly string[], last: 'and' | 'or'): string {
  return items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} ${last} ${items.at(-1)}`;
}

