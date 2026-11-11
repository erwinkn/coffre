/**
 * The sessions `coffre --service <name> run --proof oidc[:<file>]` keeps for
 * the next run (docs/design/oidc.md, section 9.4). An ID token is spent once,
 * and a platform such as Capy writes one an hour, so a second run on the same
 * token would be refused (`replayed`). The first run keeps the key-bound
 * session the token bought, and each later run with the same token goes on
 * with it, until the earlier of the session's hard end and the token's `exp`.
 *
 * Each session is sealed by the token that bought it: its file's name is an
 * HMAC of the instance and the service under the token, and its contents are
 * encrypted with AES-256-GCM under a key HKDF derives from the token, the
 * name as associated data. A copy of the file without the token opens
 * nothing, and with the token it is what the token was worth unspent. In
 * clear, only when it ends, so that ended ones are deleted unread:
 *
 *   ~/.coffre/sessions/3f9c…e1.json   { "v": 1, "until": 1794358800000, "iv": "…", "data": "…" }
 */
import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes } from 'node:crypto';
import { chmodSync, linkSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

import type { KeptSession } from '@coffre/client/workload';

/** Where kept sessions live: beside the CLI's credentials, in a directory only you can enter. */
export function keptDirectory(): string {
  return join(homedir(), '.coffre', 'sessions');
}

/** When a lock its run has not kept fresh is a dead run's. */
const LOCK_MS = 30_000;
const LOCK_POLL_MS = 100;
/** How often a run holding a lock keeps it fresh: well within `LOCK_MS`. */
const LOCK_FRESH_MS = 5_000;

/** What one token's kept session is, to a run that holds the token. */
export type Kept = {
  /** The session the token bought, while it lasts; null for none, or one ended, which is deleted. */
  open(): KeptSession | null;
  /** Keep the session, sealed, until it or the token ends; null deletes it. */
  save(session: KeptSession | null): void;
  /** One run exchanges a token at a time, the others waiting for its file: held until the returned function is called. */
  hold(): Promise<() => void>;
};

/**
 * A token's own `exp`, in ms, from its payload: unverified, and only ever
 * an upper bound on how long its session is kept. Null for a token with
 * none, or that is no JWT: such a token's session is not kept.
 */
export function tokenExpiry(token: string): number | null {
  const payload = token.split('.')[1];
  if (payload === undefined) return null;
  try {
    const exp = (JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { exp?: unknown }).exp;
    return typeof exp === 'number' && Number.isSafeInteger(exp) && exp > 0 ? exp * 1000 : null;
  } catch {
    return null;
  }
}

/** The session `token` bought as `service` at `origin`, kept in `directory`; null for a token whose session is not kept (no `exp`). */
export function keptFor(directory: string, origin: string, service: string, token: string): Kept | null {
  const expires = tokenExpiry(token);
  if (expires === null) return null;
  const context = `${origin}\0${service}`;
  const name = createHmac('sha256', token).update(`coffre.session.v1 name\0${context}`).digest('hex');
  const key = Buffer.from(hkdfSync('sha256', token, Buffer.alloc(0), `coffre.session.v1 key\0${context}`, 32));
  const path = join(directory, `${name}.json`);
  const lock = join(directory, `${name}.lock`);

  const open = (): KeptSession | null => {
    prune(directory);
    let file: { v?: unknown; until?: unknown; iv?: unknown; data?: unknown };
    try {
      if (lstatSync(path).isSymbolicLink()) return null;
      file = JSON.parse(readFileSync(path, 'utf8')) as typeof file;
    } catch {
      return null;
    }
    try {
      if (file.v !== 1 || typeof file.until !== 'number' || file.until <= Date.now() || typeof file.iv !== 'string' || typeof file.data !== 'string') throw new Error('ended');
      const sealed = Buffer.from(file.data, 'base64');
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(file.iv, 'base64'));
      decipher.setAAD(Buffer.from(name));
      decipher.setAuthTag(sealed.subarray(sealed.length - 16));
      const session = JSON.parse(Buffer.concat([decipher.update(sealed.subarray(0, sealed.length - 16)), decipher.final()]).toString('utf8')) as KeptSession;
      return { ...session, notAfter: Math.min(session.notAfter, file.until) };
    } catch {
      // Ended, or not sealed by this token: of no use to anyone who holds it.
      rmSync(path, { force: true });
      return null;
    }
  };

  const save = (session: KeptSession | null): void => {
    if (session === null) return void rmSync(path, { force: true });
    const until = Math.min(session.notAfter, expires);
    if (until <= Date.now()) return void rmSync(path, { force: true });
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(name));
    const sealed = Buffer.concat([cipher.update(JSON.stringify(session), 'utf8'), cipher.final(), cipher.getAuthTag()]);
    writePrivate(path, JSON.stringify({ v: 1, until, iv: iv.toString('base64'), data: sealed.toString('base64') }));
  };

  const hold = async (): Promise<() => void> => {
    privateDirectory(directory);
    // Each hold's own: a lock is released, kept fresh or taken over only as the one its file names.
    const owner = randomBytes(16).toString('hex');
    for (;;) {
      try {
        writeFileSync(lock, owner, { flag: 'wx', mode: 0o600 });
        break;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      }
      // A run holding the lock keeps it fresh while it waits on the instance (an approval may take minutes): one left
      // stale is a run that died holding it, taken over. A live one is waited for, however long its exchange takes.
      const held = lockOf(lock);
      if (held === null) continue;
      if (Date.now() - held.at > LOCK_MS) {
        takeOver(lock, held.owner);
        continue;
      }
      await new Promise((resolve) => setTimeout(resolve, LOCK_POLL_MS));
    }
    const fresh = setInterval(() => {
      if (lockOf(lock)?.owner !== owner) return;
      const now = new Date();
      utimesSync(lock, now, now);
    }, LOCK_FRESH_MS);
    fresh.unref();
    return () => {
      clearInterval(fresh);
      if (lockOf(lock)?.owner === owner) rmSync(lock, { force: true });
    };
  };

  return { open, save, hold };
}

/** The run a lock names, and when it last kept it fresh; null for none. */
function lockOf(lock: string): { owner: string; at: number } | null {
  try {
    const at = statSync(lock).mtimeMs;
    return { owner: readFileSync(lock, 'utf8'), at };
  } catch {
    return null;
  }
}

/**
 * A stale lock removed, if it is still the one found stale: moved aside
 * first, in one step, then read. Another run that took it over meanwhile
 * made a fresh one, which is put back where it was.
 */
function takeOver(lock: string, stale: string): void {
  const aside = `${lock}.${randomBytes(8).toString('hex')}`;
  try {
    renameSync(lock, aside);
  } catch {
    return;
  }
  try {
    if (readFileSync(aside, 'utf8') !== stale) linkSync(aside, lock);
  } catch {
    // Put back only where no lock is now: a run that made one since holds it.
  } finally {
    rmSync(aside, { force: true });
  }
}

/** Delete the sessions that have ended, by the end each says in clear. */
function prune(directory: string): void {
  let names: string[];
  try {
    names = readdirSync(directory).filter((name) => name.endsWith('.json'));
  } catch {
    return;
  }
  for (const name of names) {
    const path = join(directory, name);
    try {
      const { until } = JSON.parse(readFileSync(path, 'utf8')) as { until?: unknown };
      if (typeof until !== 'number' || until <= Date.now()) rmSync(path, { force: true });
    } catch {
      rmSync(path, { force: true });
    }
  }
}

/** A directory only you can enter, and no symbolic link, its parent (`~/.coffre`) too. */
function privateDirectory(directory: string): void {
  for (const each of [dirname(directory), directory]) {
    mkdirSync(each, { recursive: true, mode: 0o700 });
    if (lstatSync(each).isSymbolicLink()) throw new Error(`${each} is a symbolic link, which a kept session never goes through`);
    chmodSync(each, 0o700);
  }
}

/** Write a file readable by you alone: a fresh one, renamed over the old, so a shared inode never receives a session. */
function writePrivate(path: string, text: string): void {
  privateDirectory(dirname(path));
  const temporary = join(dirname(path), `.write-${randomBytes(8).toString('hex')}`);
  try {
    writeFileSync(temporary, `${text}\n`, { mode: 0o600, flag: 'wx' });
    renameSync(temporary, path);
  } finally {
    rmSync(temporary, { force: true });
  }
}
