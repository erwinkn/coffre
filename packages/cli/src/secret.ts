// A secret, as every command takes one: asked for, never a flag. On a
// terminal, at a hidden prompt that says what it wants; otherwise, from
// stdin, which is where a script pipes it (`printenv DATABASE_OWNER_URL |
// coffre migrate --yes`) or a file is redirected (`< /run/secrets/db`). The
// shell's history, `ps` and a CI log see neither.
import { readFileSync } from 'node:fs';

import { hiddenLine, style } from './tty.ts';

/** What is asked for: its label, as the prompt says it, and a line under it. */
export type Asked = { label: string; hint: string };

/**
 * One secret: typed at a hidden prompt on a terminal, or the whole of stdin,
 * trimmed. Empty is refused, saying where it was looked for.
 */
export async function readSecret(asked: Asked): Promise<string> {
  if (process.stdin.isTTY) {
    const value = await hiddenLine(process.stdin, process.stderr, style(process.stderr), `${asked.label}:`, asked.hint);
    if (value === '') throw new Error(`no ${lower(asked.label)} given`);
    return value;
  }
  const value = readFileSync(0, 'utf8').trim();
  if (value === '') throw new Error(`no ${lower(asked.label)}: none came on stdin, and there is no terminal to ask on`);
  return value;
}

function lower(label: string): string {
  return label.charAt(0).toLowerCase() + label.slice(1);
}
