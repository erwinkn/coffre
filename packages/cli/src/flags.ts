/**
 * What the CLI is told, it is told on its command line: it reads no COFFRE_*
 * variable. The session flags come before the command, and say which coffre
 * to talk to and how to sign in there, for that one command:
 *
 *   coffre --url https://coffre.example.com --token-file - export app/prod
 *
 * A value on the command line is in `ps`, the shell's history and CI logs,
 * so a secret comes in a file a flag names, or on stdin for `-`, which one
 * flag at most may read.
 */
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import type { SessionFlags } from './instance.ts';
import { listed } from './tty.ts';

/** The session flags, each a string, and each overriding the saved session for one command. */
export const SESSION_OPTIONS = {
  url: { type: 'string' },
  'token-file': { type: 'string' },
  service: { type: 'string' },
  'id-token-file': { type: 'string' },
  'access-client-id': { type: 'string' },
  'access-client-secret-file': { type: 'string' },
  'auth-mode': { type: 'string' },
} as const;

type SessionName = keyof typeof SESSION_OPTIONS;

/** The session flags as given, their files not read yet. */
export type SessionArgs = { [name in SessionName]?: string };

/** The session flags each command takes, when not all of them: none where it talks to no instance. */
const TAKES: Record<string, readonly SessionName[]> = {
  init: [],
  keys: [],
  setup: [],
  update: [],
  use: [],
  roles: [],
  login: ['url', 'auth-mode'],
  logout: ['url'],
};

/** A command's own flags that share a session flag's name: `coffre grant … --service` names a service's grant. */
const OWN: Record<string, readonly string[]> = { grant: ['service'], offboard: ['service'] };

/**
 * The commands that refuse any flag but theirs themselves, and say more: that
 * an argument looks like a connection string, which the shell's history now
 * holds.
 */
const SELF = new Set(['setup', 'migrate']);

/**
 * `coffre [session flags] <command> [args…]`, split. Throws, saying what to
 * do, on a session flag that is malformed, misplaced after the command, or
 * given to a command it does nothing for.
 */
export function commandLine(argv: readonly string[]): { session: SessionArgs; command: string | undefined; rest: string[] } {
  let at = 0;
  for (; at < argv.length; at++) {
    const [name, value] = argv[at]!.startsWith('--') ? argv[at]!.slice(2).split(/=(.*)/s) : [];
    if (name === undefined || !(name in SESSION_OPTIONS)) break;
    if (value === undefined) at++;
  }
  const session: SessionArgs = { ...parseArgs({ args: argv.slice(0, at), options: SESSION_OPTIONS, strict: true }).values };
  const [command, ...rest] = argv.slice(at);
  if (command === undefined || command.startsWith('-')) return { session, command, rest };

  const own = OWN[command] ?? [];
  const end = rest.indexOf('--');
  for (const arg of SELF.has(command) ? [] : end === -1 ? rest : rest.slice(0, end)) {
    const name = arg.startsWith('--') ? arg.slice(2).split('=')[0]! : '';
    if (name in SESSION_OPTIONS && !own.includes(name)) {
      throw new Error(`--${name} is a session flag, which goes before the command: coffre --${name} ${placeholder(name)} ${command} …`);
    }
  }
  const takes = TAKES[command];
  const extra = takes === undefined ? [] : Object.keys(session).filter((name) => !takes.includes(name as SessionName));
  if (extra.length > 0) {
    throw new Error(`${listed(extra.map((name) => `--${name}`), 'and')} ${extra.length === 1 ? 'does' : 'do'} nothing for coffre ${command}`);
  }
  return { session, command, rest };
}

function placeholder(name: string): string {
  if (name.endsWith('-file')) return '<path|->';
  return { url: '<url>', service: '<name>', 'access-client-id': '<id>', 'auth-mode': 'signin|cloudflare' }[name] ?? '…';
}

/** The session flags with their files read: a credential's secret is never a flag's value. */
export function readSession(args: SessionArgs): SessionFlags {
  const file = (name: SessionName) => (args[name] === undefined ? undefined : secretFile(`--${name}`, args[name]));
  return {
    url: args.url,
    token: file('token-file'),
    service: args.service,
    idToken: file('id-token-file'),
    accessClientId: args['access-client-id'],
    accessClientSecret: file('access-client-secret-file'),
    authMode: args['auth-mode'],
  };
}

/** The flag that read stdin, once one has: no other may. */
let stdinReader: string | null = null;

/**
 * A secret, from the file `path` names, or from stdin for `-`: trimmed, and
 * never empty. `flag` names it in what goes wrong.
 */
export function secretFile(flag: string, path: string): string {
  let text: string;
  if (path === '-') {
    if (stdinReader !== null) throw new Error(`${stdinReader} and ${flag} both read stdin: give one of them a path`);
    if (process.stdin.isTTY) throw new Error(`${flag} - reads stdin, which is this terminal: pipe the value in, or give a path`);
    stdinReader = flag;
    text = readFileSync(0, 'utf8');
  } else {
    try {
      text = readFileSync(path, 'utf8');
    } catch (error) {
      throw new Error(`${flag} names ${path}, which could not be read: ${(error as NodeJS.ErrnoException).code ?? String(error)}`);
    }
  }
  const value = text.trim();
  if (value === '') throw new Error(path === '-' ? `${flag} -: nothing came on stdin` : `${flag} names ${path}, which is empty`);
  return value;
}

/** The flag that read stdin, if one did: for a command that reads stdin itself, or hands it on. */
export function stdinReadBy(): string | null {
  return stdinReader;
}

/** The variables earlier CLIs read, and what took each one's place; `command` when only that one read it. */
export const REMOVED: readonly { variable: string; flag: string; command?: readonly string[] }[] = [
  { variable: 'COFFRE_API_URL', flag: '--url <url>' },
  { variable: 'COFFRE_TOKEN', flag: '--token-file <path|->' },
  { variable: 'COFFRE_SERVICE', flag: '--service <name>' },
  { variable: 'COFFRE_ID_TOKEN', flag: '--id-token-file <path|->' },
  { variable: 'COFFRE_ID_TOKEN_FILE', flag: '--id-token-file <path|->' },
  { variable: 'COFFRE_ACCESS_CLIENT_ID', flag: '--access-client-id <id>' },
  { variable: 'COFFRE_ACCESS_CLIENT_SECRET', flag: '--access-client-secret-file <path|->' },
  { variable: 'COFFRE_AUTH_MODE', flag: '--auth-mode signin|cloudflare' },
  { variable: 'COFFRE_MIGRATE_DATABASE_URL', flag: 'coffre migrate --database-url-file <path|->', command: ['migrate'] },
  { variable: 'COFFRE_SETUP_DATABASE_URL', flag: 'coffre setup --database-url-file <path|->', command: ['setup'] },
  { variable: 'COFFRE_VAULT_KEY', flag: 'coffre verify keys --vault-key-file <path|->', command: ['verify', 'keys'] },
  { variable: 'COFFRE_APP_KEY', flag: 'coffre verify keys --app-key-file <path|->', command: ['verify', 'keys'] },
  { variable: 'COFFRE_VAULT_KEY_ID', flag: 'coffre verify keys --vault-id <id>', command: ['verify', 'keys'] },
  { variable: 'COFFRE_CONFORMANCE_CANARY', flag: 'coffre verify instance --canary-value-file <path|->', command: ['verify', 'instance'] },
];

/**
 * Why the command `words` start with will not run while a variable an
 * earlier CLI read for it is set, in one line; null when none is. A variable
 * left from before would otherwise do nothing, silently: the run would go
 * elsewhere, or as someone else, than its author meant.
 */
export function removedVariables(env: Readonly<Record<string, string | undefined>>, words: readonly string[]): string | null {
  const reads = (only: readonly string[] | undefined) => only === undefined || only.every((word, i) => words[i] === word);
  const set = REMOVED.filter(({ variable, command }) => reads(command) && env[variable]?.trim());
  if (set.length === 0) return null;
  const flags = [...new Set(set.map(({ flag }) => flag))];
  const [them, are] = set.length === 1 ? ['it', 'is'] : ['them', 'are'];
  return `${listed(set.map(({ variable }) => variable), 'and')} ${are} no longer read: unset ${them}, and pass ${listed(flags, 'and')}`;
}
