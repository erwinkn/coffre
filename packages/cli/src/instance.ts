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
 * A CI run signs in the same way, with what `coffre login` asks it for: a
 * bearer token (`--token`), an Access service token's secret
 * (`--access-client-id`), or the credential its ID token buys
 * (`--service`); each saved as the instance's session. The session flags
 * pick another instance than the current one, `--url`, or sign one command
 * in as a service by its ID token, `--service` (`flags.ts`).
 */

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

const MODES: readonly AuthMode[] = ['signin', 'cloudflare'];
const KINDS: readonly SessionKind[] = ['token', 'access', 'run'];

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
export function resolveTarget(flags: SessionFlags, store: Store, now: Date = new Date()): Target {
  const explicitMode = parseMode(flags.authMode);
  const requested = flags.url ?? store.current;
  if (!requested) {
    throw new Error('not signed in anywhere yet: run `coffre login <url>`');
  }
  const origin = instanceOrigin(requested);

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
  if (stored === undefined || stored.mode !== mode) throw new Error(`not signed in to ${origin}: ${relogin}`);
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
