// `coffre verify`: every check of an instance under one command, and, on a
// terminal, a choice among them when none is named.
import { Cancelled, openTerminal, release, select, style } from '../tty.ts';
import { stop } from './checks.ts';

export { INSTANCE_USAGE, verifyInstance } from './instance.ts';
export { KEYS_USAGE, verifyKeys } from './keys.ts';

/** The checks, in the order they are offered: each one's name, and what it checks. */
export const CHECKS = [
  ['instance', 'the instance from outside: as no one, then as you, an owner'],
  ['keys', 'the vault key and app key you keep, against the instance'],
  ['log', 'the whole audit log, as you, an owner'],
] as const;

export type Check = (typeof CHECKS)[number][0];

export const VERIFY_USAGE = `usage: coffre verify instance | keys | log

${CHECKS.map(([name, what]) => `  ${name.padEnd(10)}${what}`).join('\n')}

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
