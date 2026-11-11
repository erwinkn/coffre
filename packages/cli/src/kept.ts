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
import { chmodSync, closeSync, fstatSync, futimesSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
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
    // Seconds, fractional or not, as the instance takes them: down to the ms, so that the session is never kept past it.
    return typeof exp === 'number' && Number.isFinite(exp) && exp > 0 ? Math.floor(exp * 1000) : null;
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
      if (Date.now() - held.at > LOCK_MS && takeOver(lock, held)) continue;
      await new Promise((resolve) => setTimeout(resolve, LOCK_POLL_MS));
    }
    const fresh = setInterval(() => {
      try {
        withLock(lock, (now, fd) => {
          if (now.owner !== owner) return;
          const at = new Date();
          futimesSync(fd, at, at);
        });
      } catch {
        // A refresh that fails leaves the lock to go stale, as a run that died would: never a crash mid-run.
      }
    }, LOCK_FRESH_MS);
    fresh.unref();
    return () => {
      clearInterval(fresh);
      // Under the same mutex as a takeover, so that a run that took it over after this one stalled keeps its own. The
      // mutex is held for as long as removing a file takes, so it is waited for here, the run being about to exit.
      for (let tries = 0; tries < 500 && breaking(lock, () => removeIf(lock, (now) => now.owner === owner)) === null; tries++) Atomics.wait(PAUSE, 0, 0, 2);
    };
  };

  return { open, save, hold };
}

/** For a release's pauses: a run exits right after it, so it cannot wait on a timer. */
const PAUSE = new Int32Array(new SharedArrayBuffer(4));

/** A lock as one file says it: who holds it, when they last kept it fresh, and which file it is. */
export type Lock = { owner: string; at: number; ino: number };

/**
 * `use` the lock file now at `lock`, read through one descriptor, so that its
 * holder, its freshness and its identity are all the same file's, however
 * the name moves meanwhile. Undefined for none.
 */
function withLock<T>(lock: string, use: (held: Lock, fd: number) => T): T | undefined {
  let fd: number;
  try {
    fd = openSync(lock, 'r');
  } catch (error) {
    // Only a lock gone meanwhile is none: one that cannot be read (EACCES, ELOOP) is an error to report, not a lock to
    // wait out, which `hold` would retry without end (review r3 of #561).
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
  try {
    const { mtimeMs, ino } = fstatSync(fd);
    const buffer = Buffer.alloc(64);
    const owner = buffer.subarray(0, readSync(fd, buffer, 0, buffer.length, 0)).toString('utf8');
    return use({ owner, at: mtimeMs, ino }, fd);
  } finally {
    closeSync(fd);
  }
}

/** The run a lock names, when it last kept it fresh, and which file it is; null for none. */
export function lockOf(lock: string): Lock | null {
  return withLock(lock, (held) => held) ?? null;
}

/**
 * Remove the stale lock `found` at `lock`, if it is still that file and
 * still stale; whether it did. Another run's lock made since, fresh or not
 * yet found stale, stays.
 */
export function takeOver(lock: string, found: Lock): boolean {
  return breaking(lock, () => removeIf(lock, (now) => now.ino === found.ino && Date.now() - now.at > LOCK_MS)) === true;
}

/** Remove the lock file at `lock` if `still` holds of it, read again now; whether it did. */
function removeIf(lock: string, still: (now: Lock) => boolean): boolean {
  const now = lockOf(lock);
  if (now === null || !still(now)) return false;
  rmSync(lock, { force: true });
  return true;
}

/**
 * Run `act` holding the lock's mutex (`<lock>.break`), which every removal
 * of the lock takes: a takeover, after it reads the lock again and finds it
 * the same stale file, and a release, after it finds it its own. With no
 * other run able to remove it meanwhile, and none to make one while it is
 * there, the file a removal checked is the one it removes. `act`'s answer,
 * or null without the mutex, held by another run (for the moment it takes
 * to remove a file); one left by a run that died holding it is removed once
 * stale. (Two runs finding that one stale at once could each remove the
 * other's: the one place left where two removals may race, after a run died
 * within those microseconds.)
 */
function breaking(lock: string, act: () => boolean): boolean | null {
  const mutex = `${lock}.break`;
  try {
    writeFileSync(mutex, '', { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    try {
      if (Date.now() - statSync(mutex).mtimeMs > LOCK_MS) rmSync(mutex, { force: true });
    } catch {
      // Gone already.
    }
    return null;
  }
  try {
    return act();
  } finally {
    rmSync(mutex, { force: true });
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
