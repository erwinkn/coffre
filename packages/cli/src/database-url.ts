// A database's owner URL, as `coffre setup` and `coffre migrate` take it:
// from the file --database-url-file names, from stdin for `-`, or typed at a
// hidden prompt; never from the command line, where the shell's history and
// other users can read it.
import { secretFile } from './flags.ts';
import { hiddenLine, type Output, type Style } from './tty.ts';

/** Why there is no usable URL, said as it is. */
export class DatabaseUrlError extends Error {}

export type Asking = {
  /** What --database-url-file names: a path, or `-` for stdin. */
  file: string | undefined;
  question: string;
  hint: string;
  /** The command, as messages name it: `coffre setup`. */
  command: string;
};

/**
 * The connection string: from the file, or typed at a hidden prompt. With
 * it, every form of its secrets, as typed and decoded, for the caller to
 * keep out of anything it shows.
 */
export async function readDatabaseUrl(out: Output, s: Style, asking: Asking): Promise<{ url: URL; secrets: string[] }> {
  let text: string;
  if (asking.file !== undefined) {
    try {
      text = secretFile('--database-url-file', asking.file);
    } catch (error) {
      throw new DatabaseUrlError((error as Error).message);
    }
  } else if (process.stdin.isTTY) {
    text = await hiddenLine(process.stdin, out, s, asking.question, asking.hint);
    if (text === '') throw new DatabaseUrlError('no connection string given');
  } else {
    throw new DatabaseUrlError('no connection string, and no terminal to ask for it on: pass --database-url-file <path>, or - for stdin');
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
