// `coffre setup`: a deployment's database and keys, in one go. It asks for
// the database administrator's connection string, never on the command line;
// makes the two runtime logins, with fresh passwords that reach the database
// only as SCRAM verifiers; migrates as the administrator, with the
// migrations this CLI was built with; checks the boundary by connecting as
// each login; then shows every value once, and writes no file.
import { createHash, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { Writable } from 'node:stream';
import { parseArgs } from 'node:util';

import { postgresConnection } from '@coffre/db/connect';
import { migrateDatabase } from '@coffre/db/migrate';
import pg from 'pg';

import { generateKeys, KEYS_EXPLAINED, type Keys } from './keys.ts';

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

export type SetupResult = { keys: Keys | null; app: Login; vault: Login };

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
 * A login's URL for Hyperdrive, without its parameters: Hyperdrive always
 * connects over TLS, checking the certificate against public CAs, and takes
 * no `sslrootcert`.
 */
export function hyperdriveUrl(url: string): string {
  const bare = new URL(url);
  bare.search = '';
  bare.hash = '';
  return bare.href;
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
  try {
    const options = parseOptions(args);
    const { text, interactive } = await readAdministrator();
    secrets.push(text);
    const administrator = administratorUrl(text);
    if (administrator.password !== '') secrets.push(administrator.password, decodeURIComponent(administrator.password));
    const result = await run(administrator, { ...options, interactive }, secrets);
    process.stdout.write(options.json ? `${JSON.stringify(asJson(result))}\n` : formatSetup(result));
  } catch (error) {
    process.stderr.write(`coffre setup: ${redact(error instanceof Error ? error.message : String(error), secrets)}\n`);
    process.exit(1);
  }
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
      `it takes only --reset-passwords and --json. It reads the administrator's connection string from a hidden prompt, ` +
        `${URL_VARIABLE} or stdin, never from the command line, where the shell's history and other users can read it.` +
        (leaked ? ' One of the arguments looks like one: change that password, which is in your shell history now.' : ''),
    );
  }
}

/** The connection string: from the environment, from stdin when it is not a terminal, or typed at a hidden prompt. */
async function readAdministrator(): Promise<{ text: string; interactive: boolean }> {
  const terminal = process.stdin.isTTY === true;
  const given = process.env[URL_VARIABLE];
  delete process.env[URL_VARIABLE];
  if (given !== undefined && given.trim() !== '') return { text: given.trim(), interactive: terminal };
  if (!terminal) {
    const line = readFileSync(0, 'utf8').split('\n').find((candidate) => candidate.trim() !== '');
    if (line === undefined) throw new SetupError(`no connection string: pipe it to stdin, or set ${URL_VARIABLE}`);
    return { text: line.trim(), interactive: false };
  }
  const text = await hidden("The database administrator's connection string (hidden): ");
  if (text === '') throw new SetupError('no connection string given');
  return { text, interactive: true };
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

async function run(
  administrator: URL,
  options: { resetPasswords: boolean; interactive: boolean },
  secrets: string[],
): Promise<SetupResult> {
  const user = decodeURIComponent(administrator.username);
  const logins = await provision(administrator, user, options, secrets);
  const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
  note(`migrating the database to coffre ${version}'s schema, as ${user}`);
  await migrateDatabase(administrator.href);
  note('checking the boundary, as each login');
  const used = await withClient(administrator.href, async (client) => {
    for (const component of ['app', 'vault'] as const) {
      const login = logins[component];
      const allowed = login.url === null ? await granted(client, login.role) : await probed(login.url);
      check(component, login, allowed);
    }
    return (await client.query<{ used: boolean }>('SELECT EXISTS (SELECT 1 FROM audit_log) AS used')).rows[0]!.used;
  });
  // Keys come with new passwords, for a database that holds no data yet: one that does has its keys already.
  const fresh = !used && (logins.app.url !== null || logins.vault.url !== null);
  return { keys: fresh ? generateKeys() : null, ...logins };
}

/**
 * Each runtime login, created with a fresh password, or, if it exists, its
 * password set again when asked to; otherwise left as it is.
 */
async function provision(
  administrator: URL,
  user: string,
  options: { resetPasswords: boolean; interactive: boolean },
  secrets: string[],
): Promise<Record<Component, Login>> {
  return withClient(administrator.href, async (client) => {
    const [self] = (await client.query<{ rolsuper: boolean; rolcreaterole: boolean }>(
      'SELECT rolsuper, rolcreaterole FROM pg_roles WHERE rolname = current_user',
    )).rows;
    if (!self?.rolsuper && !self?.rolcreaterole) {
      throw new SetupError(`${user} cannot create roles: connect as the database's administrator, which has CREATEROLE`);
    }
    const existing = new Set(
      (await client.query<{ rolname: string }>('SELECT rolname FROM pg_roles WHERE rolname = ANY($1)', [Object.values(ROLES)])).rows.map(
        (row) => row.rolname,
      ),
    );
    let reset = options.resetPasswords;
    if (existing.size > 0 && !reset) {
      const [names, one] = [[...existing].join(' and '), existing.size === 1];
      if (options.interactive) {
        note(`${names} ${one ? 'exists' : 'exist'} already`);
        reset = await confirm('Set new passwords? Each component then needs its new connection string [y/N] ');
      } else {
        note(`${names} ${one ? 'exists' : 'exist'} already, and ${one ? 'keeps its password' : 'keep their passwords'}: --reset-passwords sets new ones`);
      }
    }
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
      note(`${create ? 'created' : 'set a new password for'} ${role}${login === role ? '' : `, which logs in as ${login}`}`);
      logins[component] = { role, login, password: create ? 'created' : 'reset', url: loginUrl(administrator, login, password) };
    }
    return logins;
  });
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
  return withClient(url, async (client) => {
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
  });
}

/** The same, from the catalog, for a login whose password this run did not set: the administrator asks for it. */
async function granted(client: pg.Client, role: string): Promise<boolean[]> {
  const allowed: boolean[] = [];
  for (const { privilege } of BOUNDARY) {
    allowed.push((await client.query<{ allowed: boolean }>(`SELECT ${privilege} AS allowed`, [role])).rows[0]!.allowed);
  }
  return allowed;
}

function check(component: Component, login: Login, allowed: boolean[]): void {
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
  const how = login.url === null ? ', by the catalog: its password is unchanged' : '';
  note(`  ${login.role.padEnd(20)} ${can.length > 0 ? `can ${listed(can, 'and')}; ` : ''}cannot ${listed(cannot, 'or')}${how}`);
}

// --- what it shows -----------------------------------------------------------------

/**
 * Every value, once, as a dotenv block for each component, then, as
 * comments, where each goes: Node's env files, or Workers' Hyperdrive
 * configs, vars and secrets.
 */
export function formatSetup({ keys, app, vault }: SetupResult): string {
  const lines: string[] = [];
  const say = (...text: string[]) => lines.push(...text);
  if (keys === null && app.url === null && vault.url === null) {
    return `# Nothing to save. The logins kept their passwords, and this database
# holds a deployment's data already, whose keys are the ones it was set up
# with. For new passwords: coffre setup --reset-passwords.
`;
  }
  say(
    '# SAVE THESE NOW, in your password manager. They are shown once: coffre',
    '# keeps no copy, and the database holds only the passwords\' verifiers.',
  );
  if (keys === null) {
    say('#', '# No keys: this database holds a deployment\'s data already, whose keys', '# are the ones it was set up with.');
  }
  const url = (login: Login) =>
    login.url === null
      ? `# DATABASE_URL: ${login.role} kept its password; coffre setup --reset-passwords sets a new one.`
      : `DATABASE_URL=${login.url}`;
  say('', '# The app: server.env on Node; Worker secrets and Hyperdrive on Workers.');
  if (keys !== null) say(`AUDIT_CHAIN_KEY=${keys.AUDIT_CHAIN_KEY}`);
  say(url(app), '', '# The vault: vault.env on Node; a var, a secret and Hyperdrive on Workers.');
  if (keys !== null) say(`KEK_ID=${keys.KEK_ID}`, `KEK=${keys.KEK}`);
  say(url(vault), '');

  say(
    '# On Node, the app\'s block goes in server.env and the vault\'s in vault.env,',
    '# beside the settings their .example files list, each readable only by',
    '# its process\'s user (chmod 600).',
  );
  const set = [app, vault].filter((login) => login.url !== null);
  if (set.length > 0) {
    say(
      '#',
      '# On Workers, from the deployment\'s directory: each login reaches the',
      '# database through a Hyperdrive config of its own, with caching off, so',
      '# that a revoked session or grant stops at once. Hyperdrive always',
      '# connects over TLS, checking the certificate against public CAs, so',
      '# these URLs leave the parameters out:',
      '#',
    );
    for (const [component, login] of [['app', app], ['vault', vault]] as const) {
      if (login.url === null) continue;
      const target = login.password === 'created'
        ? `create ${HYPERDRIVE[component]} --caching-disabled`
        : `update <the ${component}'s config id>`;
      say(`#   pnpm exec wrangler hyperdrive ${target} \\`, `#     --connection-string='${hyperdriveUrl(login.url)}'`);
    }
  }
  const places = [
    ...(set.some((login) => login.password === 'created') ? ['the ids they print under hyperdrive, in app/wrangler.jsonc and vault/wrangler.jsonc'] : []),
    ...(keys === null ? [] : ['KEK_ID under vars in vault/wrangler.jsonc']),
  ];
  if (places.length > 0) say('#', ...comment(`Put ${places.join(', and ')}.${keys === null ? '' : ' Then set the two secrets, each pasted at its prompt:'}`));
  if (keys !== null) {
    say(
      '#',
      '#   pnpm exec wrangler secret put AUDIT_CHAIN_KEY -c app/wrangler.jsonc',
      '#   pnpm exec wrangler secret put KEK -c vault/wrangler.jsonc',
      '#',
      KEYS_EXPLAINED.trimEnd(),
    );
  }
  say(
    '#',
    '# The database is migrated, and each login holds only its rights. Run',
    '# `pnpm migrate` in the deployment after every upgrade of coffre.',
  );
  return `${lines.join('\n')}\n`;
}

/** `text` as comment lines of at most 76 columns. */
function comment(text: string): string[] {
  const lines: string[] = [];
  let line = '#';
  for (const word of text.split(' ')) {
    if (line.length + 1 + word.length > 76) {
      lines.push(line);
      line = '#';
    }
    line += ` ${word}`;
  }
  return [...lines, line];
}

/** "a, b or c". */
function listed(items: readonly string[], last: 'and' | 'or'): string {
  return items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} ${last} ${items.at(-1)}`;
}

/** The same values, for a script: each component's, and what happened to each login. */
function asJson({ keys, app, vault }: SetupResult) {
  const database = (login: Login) => (login.url === null ? {} : { DATABASE_URL: login.url });
  return {
    app: { ...(keys === null ? {} : { AUDIT_CHAIN_KEY: keys.AUDIT_CHAIN_KEY }), ...database(app) },
    vault: { ...(keys === null ? {} : { KEK_ID: keys.KEK_ID, KEK: keys.KEK }), ...database(vault) },
    logins: Object.fromEntries([app, vault].map(({ role, login, password }) => [role, { login, password }])),
  };
}

// --- plumbing ------------------------------------------------------------------------

async function withClient<T>(url: string, use: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ ...postgresConnection(url), application_name: 'coffre-setup' });
  await client.connect();
  try {
    return await use(client);
  } finally {
    await client.end();
  }
}

/** Progress, on stderr: stdout holds only what to save. */
function note(text: string): void {
  process.stderr.write(`${text}\n`);
}

/** An error's text without any secret in it: a driver may quote what it was given. */
function redact(text: string, secrets: readonly string[]): string {
  return secrets.filter((secret) => secret.length >= 4).reduce((out, secret) => out.split(secret).join('…'), text);
}

async function hidden(question: string): Promise<string> {
  const muted = new Writable({ write: (_chunk, _encoding, done) => done() });
  const prompt = createInterface({ input: process.stdin, output: muted, terminal: true });
  prompt.on('SIGINT', () => {
    process.stderr.write('\n');
    process.exit(130);
  });
  process.stderr.write(question);
  try {
    return (await prompt.question('')).trim();
  } finally {
    prompt.close();
    process.stderr.write('\n');
  }
}

async function confirm(question: string): Promise<boolean> {
  const prompt = createInterface({ input: process.stdin, output: process.stderr });
  try {
    return /^y(es)?$/i.test((await prompt.question(question)).trim());
  } finally {
    prompt.close();
  }
}
