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
  migrate: [],
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
const OWN: Record<string, readonly string[]> = { access: ['service'], admit: ['service'], grant: ['service'], revoke: ['service'], offboard: ['service'], login: ['service'] };

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
