// A database's owner URL, as `coffre setup` and `coffre migrate` take it:
// typed at a hidden prompt on a terminal, or piped in, as a pipeline does
// (`printenv DATABASE_OWNER_URL | coffre migrate --yes`); never from the
// command line, where the shell's history and other users can read it.
import { readFileSync } from 'node:fs';

import { hiddenLine, type Output, type Style } from './tty.ts';

/** Why there is no usable URL, said as it is. */
export class DatabaseUrlError extends Error {}

export type Asking = {
  question: string;
  hint: string;
  /** The command, as messages name it: `coffre setup`. */
  command: string;
};

/**
 * The connection string: typed at a hidden prompt on a terminal, or the
 * whole of stdin. With it, every form of its secrets, as typed and decoded,
 * for the caller to keep out of anything it shows.
 */
export async function readDatabaseUrl(out: Output, s: Style, asking: Asking): Promise<{ url: URL; secrets: string[] }> {
  let text: string;
  if (process.stdin.isTTY) {
    text = await hiddenLine(process.stdin, out, s, asking.question, asking.hint);
    if (text === '') throw new DatabaseUrlError('no connection string given');
  } else {
    text = readFileSync(0, 'utf8').trim();
    if (text === '') throw new DatabaseUrlError(`no connection string: pipe it in, as \`printenv DATABASE_OWNER_URL | ${asking.command} …\`, or run it on a terminal`);
  }
  const url = databaseUrl(text, asking.command);
  return { url, secrets: url.password === '' ? [text] : [text, url.password, decodeURIComponent(url.password)] };
}

export function databaseUrl(text: string, command: string): URL {
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new DatabaseUrlError('that is not a connection string, such as postgresql://user:password@host:5432/database');
  }
  if (url.protocol !== 'postgres:' && url.protocol !== 'postgresql:') {
    throw new DatabaseUrlError(`${command} needs a Postgres connection string, postgresql://…`);
  }
  if (url.username === '' || url.hostname === '' || url.pathname.length <= 1) {
    throw new DatabaseUrlError('the connection string must name a user, a host and a database');
  }
  return url;
}
