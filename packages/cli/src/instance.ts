/**
 * Which coffre the CLI talks to, and how it proves who you are there.
 *
 * One person often has several instances (a company's and their own), so
 * sessions are kept per origin in one file, and `coffre login <url>` makes
 * that origin the default one:
 *
 *   {
 *     "version": 2,
 *     "current": "https://coffre.example.com",
 *     "instances": {
 *       "https://coffre.example.com": { "mode": "signin", "token": "coffre_cli_…", … },
 *       "https://coffre.acme.example": { "mode": "cloudflare", … }
 *     }
 *   }
 *
 * A CI run signs in the same way, with what `coffre login` asks it for: a
 * bearer token (`--token`), an Access service token's secret
 * (`--access-client-id`), or the credential its ID token buys
 * (`--service`); each saved as the instance's session. The session flags
 * pick another instance than the one a command would use, `--url`, or sign
 * one command in as a service by its ID token, `--service` (`flags.ts`).
 *
 * `coffre login <url>` also pins the directory it ran in to that origin,
 * for it and every directory below, in a file of its own beside the
 * sessions (`Pins`). A repository can name its instance for everyone who
 * clones it, in a `coffre.json` it commits (`parseRepoFile`). A command uses
 * `--url`, else the nearest pinned directory or `coffre.json` above where it
 * runs, a pin before a file in the same directory, else the default.
 */

import { dirname, isAbsolute, join, relative, sep } from 'node:path';
import { apiMember, type AuthInfo } from '@coffre/client';

/** Who vouches for you there: coffre's own sign-in, or Cloudflare Access in front of it. */
export type AuthMode = 'signin' | 'cloudflare';

/**
 * Whose a saved session is, besides a person's by a device login or
 * cloudflared: a bearer token's, an Access service token's, or a CI run's,
 * the five-minute credential its ID token bought.
 */
export type SessionKind = 'token' | 'access' | 'run';

export type Session = {
  mode: AuthMode;
  /** A person's, when absent. */
  kind?: SessionKind;
  /** Absent for Cloudflare Access, whose token cloudflared keeps and refreshes, or a bearer token's id and secret. */
  token?: string;
  /** An Access service token, `kind: 'access'`. */
  clientId?: string;
  clientSecret?: string;
  principal?: { type: string; id: string };
  expiresAt?: string | null;
  obtainedAt: string;
};

export type Store = {
  version: 2;
  current: string | null;
  instances: Record<string, Session>;
};

export type Credential =
  | { kind: 'token'; token: string }
  | { kind: 'access-service-token'; clientId: string; clientSecret: string }
  /** Ask `cloudflared access token -app=<origin>` at request time. */
  | { kind: 'cloudflared' }
  /**
   * A CI run's ID token, a fresh one from GitHub's runner, traded for a
   * five-minute credential of `service` before the first request
   * (`workload.ts`).
   */
  | { kind: 'workload'; service: string };

/**
 * Where a request goes, what it carries, and whose it is: a person's saved
 * session, a saved bearer token, Access service token or run's credential,
 * or `--service`, this command's own.
 */
export type Target = { origin: string; mode: AuthMode; by: 'person' | SessionKind | 'service'; credential: Credential };

/** What the session flags say (`flags.ts`). */
export type SessionFlags = {
  url?: string;
  service?: string;
  authMode?: string;
};

/**
 * Which instance each pinned directory uses, by its real path, in
 * `~/.coffre/directories.json`:
 *
 *   {
 *     "version": 1,
 *     "directories": { "/home/ada/Code/acme": "https://coffre.acme.example" }
 *   }
 *
 * Not in the credentials file: a CLI from before pins rewrites that one in
 * the shape it knows, which would drop them unseen, and leaves this one
 * alone. It holds no secret.
 */
export type Pins = { version: 1; directories: Record<string, string> };

/** The pin that applies in a directory: its own, or its nearest pinned parent's. */
export type Pin = { directory: string; origin: string };

/**
 * What names the instance where a command runs: a pinned directory, or a
 * directory's `coffre.json`, whichever is nearer.
 */
export type Local = { origin: string; by: 'pin' | 'file'; directory: string };

/** Which instance a command means, and why: `--url`, the directory's pin or `coffre.json`, or the default. */
export type Choice = { origin: string; by: 'url' } | { origin: string; by: 'default' } | Local;

/** The file a repository names its instance in. */
export const REPO_FILE = 'coffre.json';

const MODES: readonly AuthMode[] = ['signin', 'cloudflare'];
const KINDS: readonly SessionKind[] = ['token', 'access', 'run'];

export function emptyStore(): Store {
  return { version: 2, current: null, instances: {} };
}

/**
 * Read the credentials file. Anything unrecognised reads as empty: the worst
 * case is one extra login, never a token sent to the wrong place.
 */
export function parseStore(text: string): Store {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return emptyStore();
  }
  if (typeof raw !== 'object' || raw === null) return emptyStore();
  const candidate = raw as Partial<Store>;
  if (candidate.version !== 2 || typeof candidate.instances !== 'object' || candidate.instances === null) {
    return emptyStore();
  }
  const instances: Record<string, Session> = {};
  for (const [origin, session] of Object.entries(candidate.instances)) {
    if (typeof session === 'object' && session !== null && MODES.includes(session.mode) && (session.kind === undefined || KINDS.includes(session.kind))) {
      instances[origin] = session;
    }
  }
  const current =
    typeof candidate.current === 'string' && candidate.current in instances
      ? candidate.current
      : null;
  return { version: 2, current, instances };
}

export function emptyPins(): Pins {
  return { version: 1, directories: {} };
}

/**
 * Read the pins file. Unlike the sessions, one this CLI cannot read is an
 * error, not an empty file: that would send a pinned directory's commands
 * to the default instance.
 */
export function parsePins(text: string): Pins {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new Error('it is not JSON');
  }
  const candidate = (typeof raw === 'object' && raw !== null ? raw : {}) as Partial<Pins>;
  if (candidate.version !== 1 || typeof candidate.directories !== 'object' || candidate.directories === null || Array.isArray(candidate.directories)) {
    throw new Error('this CLI does not know its shape: a later coffre wrote it, perhaps');
  }
  const directories: Record<string, string> = {};
  for (const [directory, origin] of Object.entries(candidate.directories)) {
    if (!isAbsolute(directory) || typeof origin !== 'string') throw new Error(`it pins ${JSON.stringify(directory)} to ${JSON.stringify(origin)}`);
    directories[directory] = instanceOrigin(origin);
  }
  return { version: 1, directories };
}

/** Whether `directory` is `ancestor` or below it. */
export function within(directory: string, ancestor: string): boolean {
  const path = relative(ancestor, directory);
  return path === '' || (path !== '..' && !path.startsWith(`..${sep}`) && !isAbsolute(path));
}

/** The pin that applies in `directory`, a real path: the longest pinned one it is in. */
export function pinFor(pins: Pins, directory: string): Pin | null {
  let found: Pin | null = null;
  for (const [pinned, origin] of Object.entries(pins.directories)) {
    if (within(directory, pinned) && (found === null || pinned.length > found.directory.length)) found = { directory: pinned, origin };
  }
  return found;
}

/** Pin `directory` to `origin`. */
export function withPin(pins: Pins, directory: string, origin: string): Pins {
  return { version: 1, directories: { ...pins.directories, [directory]: origin } };
}

/** Every pin to `origin` taken out, and the directories they pinned. */
export function withoutPins(pins: Pins, origin: string): { pins: Pins; unpinned: string[] } {
  const kept = Object.entries(pins.directories).filter(([, pinned]) => pinned !== origin);
  const unpinned = Object.entries(pins.directories).filter(([, pinned]) => pinned === origin).map(([directory]) => directory);
  return { pins: { version: 1, directories: Object.fromEntries(kept) }, unpinned };
}

/**
 * The origin a repository's `coffre.json` names, committed beside its code
 * so that a clone uses its instance with no `--url` and no pin:
 *
 *   { "url": "https://coffre.acme.example" }
 *
 * Only that: a file anyone can commit picks where the CLI goes, never what
 * it carries, which stays that instance's own session. So it holds no
 * credential and nothing else, and its URL is an origin as written.
 */
export function parseRepoFile(text: string): string {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new Error('it is not JSON');
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) throw new Error('expected { "url": "https://…" }');
  const others = Object.keys(raw).filter((key) => key !== 'url');
  if (others.length > 0) throw new Error(`it holds only "url", never a credential or anything else: not ${others.map((key) => JSON.stringify(key)).join(', ')}`);
  const { url } = raw as { url?: unknown };
  if (typeof url !== 'string') throw new Error('expected { "url": "https://…" }');
  const origin = instanceOrigin(url);
  if (origin !== url) throw new Error(`"url" is an origin, written as one: ${JSON.stringify(origin)}, not ${JSON.stringify(url)}`);
  return origin;
}

/**
 * What names the instance in `directory`, a real path: walking up from it,
 * the first directory pinned or holding a `coffre.json`, the pin first.
 * Your home and the directories above it hold no project's `coffre.json`,
 * as a login there pins nothing. `read` gives a file's text, or null if
 * there is none; a file there that cannot be read or used is an error,
 * never a reason to look further up.
 */
export function localFor(pins: Pins, directory: string, home: string, read: (path: string) => string | null): Local | null {
  const pin = pinFor(pins, directory);
  for (let at = directory; !within(home, at) && !(pin !== null && within(pin.directory, at)); at = dirname(at)) {
    const path = join(at, REPO_FILE);
    const text = read(path);
    if (text !== null) {
      try {
        return { origin: parseRepoFile(text), by: 'file', directory: at };
      } catch (error) {
        throw new Error(`cannot use ${path}: ${(error as Error).message}`);
      }
    }
    if (dirname(at) === at) break;
  }
  return pin === null ? null : { ...pin, by: 'pin' };
}

/**
 * The instance a command means: `--url`, else the pin or `coffre.json` that
 * applies where it runs, else the default. That instance is the one, signed
 * in there or not: never another one's session in its place.
 */
export function choose(flags: SessionFlags, store: Store, local: Local | null): Choice {
  if (flags.url !== undefined) return { origin: instanceOrigin(flags.url), by: 'url' };
  if (local !== null) return { ...local, origin: instanceOrigin(local.origin) };
  if (store.current !== null) return { origin: instanceOrigin(store.current), by: 'default' };
  throw new Error('not signed in anywhere yet: run `coffre login <url>`');
}

export function parseMode(raw: string | undefined): AuthMode | undefined {
  if (raw === undefined) return undefined;
  if (!(MODES as readonly string[]).includes(raw)) {
    throw new Error(`--auth-mode must be one of ${MODES.join(', ')}, not "${raw}"`);
  }
  return raw as AuthMode;
}

function isLoopback(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname === '[::1]' ||
    /^127(?:\.\d{1,3}){3}$/.test(hostname)
  );
}

/**
 * Normalise what someone typed into an origin the CLI will send credentials
 * to. Plain HTTP is refused except on this machine, where there is no wire to
 * listen on. A bare host name means HTTPS, or HTTP for this machine:
 * `coffre.example.com` and `127.0.0.1:3000` both do what they look like.
 */
export function instanceOrigin(raw: string): string {
  const value = raw.trim();
  const invalid = () =>
    new Error(`"${raw}" is not a coffre address; expected something like https://coffre.example.com`);
  let url: URL;
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
      url = new URL(value);
    } else {
      url = new URL(`https://${value}`);
      if (isLoopback(url.hostname)) url.protocol = 'http:';
    }
  } catch {
    throw invalid();
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw invalid();
  if (url.username !== '' || url.password !== '') {
    throw new Error('the coffre address must not contain a user name or password');
  }
  if ((url.pathname !== '/' && url.pathname !== '') || url.search !== '' || url.hash !== '') {
    throw new Error(`the coffre address must be an origin, like ${url.origin}, without a path`);
  }
  if (url.protocol === 'http:' && !isLoopback(url.hostname)) {
    throw new Error(`refusing to send credentials over plain HTTP; use https://${url.host}`);
  }
  return url.origin;
}

export function isJsonContentType(value: string | null): boolean {
  if (value === null) return false;
  const mediaType = value.split(';', 1)[0].trim().toLowerCase();
  return mediaType === 'application/json' || mediaType.endsWith('+json');
}

/**
 * How to sign in somewhere, from its answer to `GET /api/auth` without a
 * credential. coffre says how it signs people in. Cloudflare Access, in front
 * of it, turns the CLI away first, with a redirect to its own login page:
 *
 *   200 { signin: { providers: […] }, access: null }   → a device login
 *   200 { signin: null, access: { … } }                 → cloudflared
 *   302 Location: https://acme.cloudflareaccess.com/…   → cloudflared
 */
export function loginMode(origin: string, status: number, body: unknown): AuthMode {
  if (status >= 300 && status < 400) return 'cloudflare';
  const auth = status === 200 && typeof body === 'object' && body !== null ? (body as Partial<AuthInfo>) : null;
  if (auth?.signin) return 'signin';
  if (auth?.access) return 'cloudflare';
  if (status === 401 || status === 403) {
    // Access can be set to answer clients that are not browsers with a bare
    // 401 or 403 rather than a redirect.
    throw new Error(
      `${origin} turned the CLI away (status ${status}). If it is behind Cloudflare Access,\n` +
        `  run \`coffre --auth-mode cloudflare login ${origin}\``,
    );
  }
  throw new Error(`${origin} does not look like coffre: GET /api/auth answered ${status}`);
}

/**
 * Decide where the next request goes and what it carries, or explain why it
 * cannot be sent. Pure, so every precedence rule is testable. A flag given
 * is given: `readSession` refused an empty one, which falling back to the
 * saved session would have taken for none.
 */
export function resolveTarget(flags: SessionFlags, store: Store, local: Local | null = null, now: Date = new Date()): Target {
  const explicitMode = parseMode(flags.authMode);
  const choice = choose(flags, store, local);
  const { origin } = choice;

  if (flags.service !== undefined) {
    if (explicitMode === 'cloudflare') {
      throw new Error("--service signs a CI run in with its ID token, which coffre's own sign-in takes: behind Cloudflare Access, use an Access service token");
    }
    // `deploy`, `service:deploy` or `token:deploy`: the API's token:deploy.
    const named = apiMember(flags.service);
    const service = named.startsWith('token:') ? named : `token:${named}`;
    return { origin, mode: 'signin', by: 'service', credential: { kind: 'workload', service } };
  }

  const stored = store.instances[origin];
  const mode: AuthMode = explicitMode ?? stored?.mode ?? 'signin';
  const relogin = `run \`coffre login ${origin}\``;
  if (stored === undefined || stored.mode !== mode) {
    // A clone's first command: where the instance came from, so that a URL the repository chose is not taken for one you did.
    const named = choice.by === 'file' ? `, which ${join(choice.directory, REPO_FILE)} names` : '';
    throw new Error(`not signed in to ${origin}${named}: ${relogin}`);
  }
  const by = stored.kind ?? 'person';
  if (mode === 'cloudflare') {
    if (by !== 'access') return { origin, mode, by, credential: { kind: 'cloudflared' } };
    if (!stored.clientId || !stored.clientSecret) throw new Error(`not signed in to ${origin}: ${relogin}`);
    return { origin, mode, by, credential: { kind: 'access-service-token', clientId: stored.clientId, clientSecret: stored.clientSecret } };
  }
  if (!stored.token) throw new Error(`not signed in to ${origin}: ${relogin}`);
  if (stored.expiresAt && Date.parse(stored.expiresAt) <= now.getTime()) {
    throw new Error(
      by === 'run'
        ? `the credential this run's ID token bought on ${origin} lasted until ${stored.expiresAt.slice(11, 19)}: sign in again, \`coffre login ${origin} --service ${stored.principal?.id ?? '<name>'}\``
        : `your session on ${origin} ended on ${stored.expiresAt.slice(0, 10)}: ${relogin}`,
    );
  }
  return { origin, mode, by, credential: { kind: 'token', token: stored.token } };
}

/**
 * The headers that carry a credential, per mode. coffre's own sign-in takes a
 * standard bearer token. Cloudflare Access takes its user token, or a service
 * token's id and secret, at the edge, and hands coffre its own assertion.
 */
export function credentialHeaders(mode: AuthMode, credential: Credential, issued?: string): Record<string, string> {
  switch (credential.kind) {
    case 'access-service-token':
      return {
        'cf-access-client-id': credential.clientId,
        'cf-access-client-secret': credential.clientSecret,
      };
    case 'cloudflared':
      if (!issued) throw new Error('cloudflared did not return a token');
      return { 'cf-access-token': issued };
    case 'workload':
      if (!issued) throw new Error('the run was not signed in: no credential was exchanged');
      return { authorization: `Bearer ${issued}` };
    case 'token':
      return mode === 'cloudflare'
        ? { 'cf-access-token': credential.token }
        : { authorization: `Bearer ${credential.token}` };
  }
}

export function withSession(store: Store, origin: string, session: Session): Store {
  return { version: 2, current: origin, instances: { ...store.instances, [origin]: session } };
}

export function withoutSession(store: Store, origin: string): Store {
  const { [origin]: _removed, ...instances } = store.instances;
  const current =
    store.current === origin ? (Object.keys(instances)[0] ?? null) : store.current;
  return { version: 2, current, instances };
}
