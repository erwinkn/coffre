// `coffre verify`: every check of an instance under one command, and, on a
// terminal, a choice among them when none is named.
import { Cancelled, openTerminal, release, select, style } from '../tty.ts';
import { stop } from './checks.ts';

export { INSTANCE_USAGE, verifyInstance } from './instance.ts';
export { KEYS_USAGE, verifyKeys } from './keys.ts';

/** The checks, in the order they are offered: each one's name, and what it checks. */
export const CHECKS = [
  ['instance', 'the instance from outside: as no one, then as you, an owner'],
  ['keys', 'the vault key or signing key you keep, against the instance'],
] as const;

export type Check = (typeof CHECKS)[number][0];

export const VERIFY_USAGE = `usage: coffre verify instance | keys | backup <dump>

${CHECKS.map(([name, what]) => `  ${name.padEnd(10)}${what}`).join('\n')}
  backup    a dump coffre backup made, restored into an empty database;
            not in 0.16 yet

The whole audit log is no check of coffre verify in 0.16.0: the vault signs
it and checks it every minute, and the audit page proves each entry it shows.

On a terminal, \`coffre verify\` alone asks which. \`coffre verify <check> --help\`
says more about each.`;

/** The check named, or, with none, the one chosen on the terminal; without a terminal, the list, and exit 2. */
export async function pickCheck(): Promise<Check> {
  const terminal = openTerminal();
  if (terminal === null) stop(2, VERIFY_USAGE);
  const s = style(terminal.out);
  try {
    const at = await select(terminal.keys, terminal.out, s, 'Which check?', CHECKS.map(([name, what]) => `${name.padEnd(10)}${s.dim(what)}`));
    terminal.out.write('\n');
    return CHECKS[at]![0];
  } catch (error) {
    if (error instanceof Cancelled) process.exit(130);
    throw error;
  } finally {
    release(terminal.keys);
  }
}
