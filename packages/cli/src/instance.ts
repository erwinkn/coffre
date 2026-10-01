import type { AuthMode } from '../../core/src/identity/auth-mode.ts';
import { cliAuthHeader } from './auth-mode.ts';

/**
 * Which coffre the CLI talks to, and how it proves who you are there.
 *
 * One person often has several instances (a company's and their own), so
 * sessions are kept per origin in one file, and `coffre login <url>` makes
 * that origin the current one:
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
 * Environment variables override the file for one command, which is how CI
 * uses the CLI: `COFFRE_API_URL` picks the instance, `COFFRE_TOKEN` (a
 * service token) or `COFFRE_ACCESS_CLIENT_ID`/`_SECRET` (a Cloudflare Access
 * service token) authenticates, and nothing is written to disk.
 */

export type Session = {
  mode: AuthMode;
  /** Absent for Cloudflare Access, whose token cloudflared keeps and refreshes. */
  token?: string;
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
  | { kind: 'cloudflared' };

export type Target = { origin: string; mode: AuthMode; credential: Credential };

type Environment = Readonly<Record<string, string | undefined>>;

const MODES: readonly AuthMode[] = ['signin', 'cloudflare', 'dev'];

export function emptyStore(): Store {
  return { version: 2, current: null, instances: {} };
}

/**
 * Read the credentials file. Anything unrecognised, including the single-token
 * file older CLIs wrote, reads as empty: the worst case is one extra login,
 * never a token sent to the wrong place.
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
    if (typeof session === 'object' && session !== null && MODES.includes(session.mode)) {
      instances[origin] = session;
    }
  }
  const current =
    typeof candidate.current === 'string' && candidate.current in instances
      ? candidate.current
      : null;
  return { version: 2, current, instances };
}

export function parseMode(raw: string | undefined): AuthMode | undefined {
  const value = raw?.trim();
  if (value === undefined || value === '') return undefined;
  if (!(MODES as readonly string[]).includes(value)) {
    throw new Error(`COFFRE_AUTH_MODE must be one of ${MODES.join(', ')}, not "${value}"`);
  }
  return value as AuthMode;
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
export function instanceOrigin(raw: string, mode: AuthMode = 'signin'): string {
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
  if (url.protocol === 'http:' && mode !== 'dev' && !isLoopback(url.hostname)) {
    throw new Error(`refusing to send credentials over plain HTTP; use https://${url.host}`);
  }
  return url.origin;
}

/**
 * Decide where the next request goes and what it carries, or explain why it
 * cannot be sent. Pure, so every precedence rule is testable.
 */
export function resolveTarget(env: Environment, store: Store, now: Date = new Date()): Target {
  const explicitMode = parseMode(env.COFFRE_AUTH_MODE);
  const requested = env.COFFRE_API_URL?.trim() || store.current;
  if (!requested) {
    throw new Error('not signed in anywhere yet: run `coffre login <url>`');
  }

  const session = lookupSession(store, requested);
  const accessClientId = env.COFFRE_ACCESS_CLIENT_ID?.trim();
  const mode: AuthMode =
    explicitMode ?? session?.mode ?? (accessClientId ? 'cloudflare' : 'signin');
  const origin = instanceOrigin(requested, mode);

  const token = env.COFFRE_TOKEN?.trim();
  if (token) return { origin, mode, credential: { kind: 'token', token } };

  if (mode === 'cloudflare' && accessClientId) {
    const clientSecret = env.COFFRE_ACCESS_CLIENT_SECRET?.trim();
    if (!clientSecret) {
      throw new Error('COFFRE_ACCESS_CLIENT_ID is set but COFFRE_ACCESS_CLIENT_SECRET is not');
    }
    return { origin, mode, credential: { kind: 'access-service-token', clientId: accessClientId, clientSecret } };
  }

  const stored = store.instances[origin];
  if (stored === undefined || stored.mode !== mode) {
    throw new Error(`not signed in to ${origin}: run \`coffre login ${origin}\``);
  }
  if (mode === 'cloudflare') return { origin, mode, credential: { kind: 'cloudflared' } };
  if (!stored.token) {
    throw new Error(`not signed in to ${origin}: run \`coffre login ${origin}\``);
  }
  if (stored.expiresAt && Date.parse(stored.expiresAt) <= now.getTime()) {
    throw new Error(
      `your session on ${origin} ended on ${stored.expiresAt.slice(0, 10)}: run \`coffre login ${origin}\``,
    );
  }
  return { origin, mode, credential: { kind: 'token', token: stored.token } };
}

/** The stored session for an address, however it was typed. */
function lookupSession(store: Store, requested: string): Session | undefined {
  try {
    return store.instances[instanceOrigin(requested, 'dev')];
  } catch {
    return undefined;
  }
}

/**
 * The headers that carry a credential, per mode. coffre's own sign-in takes a
 * standard bearer token. Cloudflare Access takes its user token, or a service
 * token's id and secret, at the edge. Dev hands the API an Access-shaped
 * assertion directly.
 */
export function credentialHeaders(mode: AuthMode, credential: Credential, cloudflaredToken?: string): Record<string, string> {
  switch (credential.kind) {
    case 'access-service-token':
      return {
        'cf-access-client-id': credential.clientId,
        'cf-access-client-secret': credential.clientSecret,
      };
    case 'cloudflared':
      if (!cloudflaredToken) throw new Error('cloudflared did not return a token');
      return cliAuthHeader('cloudflare', cloudflaredToken);
    case 'token':
      return mode === 'signin'
        ? { authorization: `Bearer ${credential.token}` }
        : cliAuthHeader(mode, credential.token);
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
