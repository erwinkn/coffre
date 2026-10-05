/**
 * What the CLI is told, it is told on its command line, and it reads no
 * COFFRE_* variable. Flags configure; a secret is never one, but asked for
 * (`secret.ts`). The session flags come before the command, and say which
 * coffre to talk to, and as which service, for that one command:
 *
 *   coffre --url https://coffre.example.com --service api-deploy export app/prod
 *
 * The credential itself is the session `coffre login` saved: a person's,
 * or a CI run's, with a bearer token or an Access service token it asked
 * for, or an ID token traded for a credential.
 */
import { parseArgs } from 'node:util';

import type { SessionFlags } from './instance.ts';
import { listed } from './tty.ts';

/** The session flags, each a string, and each overriding the saved session for one command. */
export const SESSION_OPTIONS = {
  url: { type: 'string' },
  service: { type: 'string' },
  'auth-mode': { type: 'string' },
} as const;

type SessionName = keyof typeof SESSION_OPTIONS;

/** The session flags as given. */
export type SessionArgs = { [name in SessionName]?: string };

/** The session flags each command takes, when not all of them: none where it talks to no instance. */
const TAKES: Record<string, readonly SessionName[]> = {
  init: [],
  keys: [],
  setup: [],
  update: [],
  use: [],
  roles: [],
  help: [],
  login: ['url', 'auth-mode'],
  logout: ['url'],
};

/**
 * A command's own flags that share a session flag's name: `coffre grant …
 * --service` names a service's grant, `coffre login <url> --service <name>`
 * the service a CI run signs in as.
 */
const OWN: Record<string, readonly string[]> = { admit: ['service'], grant: ['service'], revoke: ['service'], offboard: ['service'], login: ['service'] };

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
    if (name === undefined || !Object.hasOwn(SESSION_OPTIONS, name)) break;
    if (value === undefined) at++;
  }
  const session: SessionArgs = { ...parseArgs({ args: argv.slice(0, at), options: SESSION_OPTIONS, strict: true }).values };
  const [command, ...rest] = argv.slice(at);
  if (command === undefined || command.startsWith('-')) return { session, command, rest };

  const own = OWN[command] ?? [];
  const end = rest.indexOf('--');
  for (const arg of SELF.has(command) ? [] : end === -1 ? rest : rest.slice(0, end)) {
    const name = arg.startsWith('--') ? arg.slice(2).split('=')[0]! : '';
    if (Object.hasOwn(SESSION_OPTIONS, name) && !own.includes(name)) {
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
  return { url: '<url>', service: '<name>', 'auth-mode': 'signin|cloudflare' }[name] ?? '…';
}

/**
 * The session flags, trimmed. An empty one is refused, never read as left
 * out: it is what an unset variable expands to, and left out would mean the
 * saved session, another instance or another person than the script meant.
 */
export function readSession(args: SessionArgs): SessionFlags {
  for (const [name, value] of Object.entries(args)) {
    if (value.trim() === '') throw new Error(`--${name} is empty: an unset variable, perhaps`);
  }
  return { url: args.url?.trim(), service: args.service?.trim(), authMode: args['auth-mode']?.trim() };
}

/** The variables earlier CLIs read, and what took each one's place; `command` when only that one read it. */
export const REMOVED: readonly { variable: string; instead: string; command?: readonly string[] }[] = [
  { variable: 'COFFRE_API_URL', instead: 'pass --url <url>, or `coffre login <url>` once' },
  { variable: 'COFFRE_TOKEN', instead: 'run `coffre login <url> --token` and paste the token, or pipe it in' },
  { variable: 'COFFRE_SERVICE', instead: 'pass --service <name>' },
  { variable: 'COFFRE_ID_TOKEN', instead: 'pipe the ID token to `coffre login <url> --service <name> --id-token`' },
  { variable: 'COFFRE_ID_TOKEN_FILE', instead: 'redirect the file to `coffre login <url> --service <name> --id-token`' },
  { variable: 'COFFRE_ACCESS_CLIENT_ID', instead: 'run `coffre login <url> --access-client-id <id>` and paste the secret, or pipe it in' },
  { variable: 'COFFRE_ACCESS_CLIENT_SECRET', instead: 'run `coffre login <url> --access-client-id <id>` and paste the secret, or pipe it in' },
  { variable: 'COFFRE_AUTH_MODE', instead: 'pass --auth-mode signin|cloudflare' },
  { variable: 'COFFRE_MIGRATE_DATABASE_URL', instead: 'paste the URL when coffre migrate asks, or pipe it in', command: ['migrate'] },
  { variable: 'COFFRE_SETUP_DATABASE_URL', instead: 'paste the URL when coffre setup asks, or pipe it in', command: ['setup'] },
  { variable: 'COFFRE_VAULT_KEY', instead: 'paste the keys when coffre verify keys asks, or pipe them in, the vault key first', command: ['verify', 'keys'] },
  { variable: 'COFFRE_APP_KEY', instead: 'paste the keys when coffre verify keys asks, or pipe them in, the vault key first', command: ['verify', 'keys'] },
  { variable: 'COFFRE_VAULT_KEY_ID', instead: 'pass coffre verify keys --vault-id <id>', command: ['verify', 'keys'] },
  { variable: 'COFFRE_CONFORMANCE_CANARY', instead: 'paste the value when coffre verify instance asks, or pipe it in', command: ['verify', 'instance'] },
];

/**
 * Why the command `words` start with will not run while a variable an
 * earlier CLI read for it is set, in one line; null when none is. A
 * command that talks to no instance never read the session's. A variable
 * left from before would otherwise do nothing, silently: the run would go
 * elsewhere, or as someone else, than its author meant.
 */
export function removedVariables(env: Readonly<Record<string, string | undefined>>, words: readonly string[]): string | null {
  // The session's variables, for a command that talks to an instance; another's, for that command alone.
  const local = TAKES[words[0] ?? '']?.length === 0;
  const reads = (only: readonly string[] | undefined) => (only === undefined ? !local : only.every((word, i) => words[i] === word));
  const set = REMOVED.filter(({ variable, command }) => reads(command) && env[variable]?.trim());
  if (set.length === 0) return null;
  const instead = [...new Set(set.map(({ instead }) => instead))];
  const [them, are] = set.length === 1 ? ['it', 'is'] : ['them', 'are'];
  return `${listed(set.map(({ variable }) => variable), 'and')} ${are} no longer read: unset ${them}; instead, ${instead.join('; ')}`;
}
