import { getCookie, getRequestHeader } from '@tanstack/react-start/server';

const API_URL = process.env.COFFRE_API_URL ?? 'http://127.0.0.1:8080';

/** Set by the dev-login flow only. In production the header below is used. */
export const DEV_TOKEN_COOKIE = 'coffre_dev_token';

/**
 * Obtain the caller's Access token.
 *
 * In production Cloudflare Access sits in front of this UI and forwards
 * `Cf-Access-Jwt-Assertion` on every request; we pass that straight through to
 * the API so the API authenticates the *end user*, not the UI. The UI holds no
 * credential of its own and cannot read anything the user could not.
 *
 * This holds for both kinds of request TanStack Start makes. On the initial
 * SSR render the header is on the document request; on a client-side
 * navigation the loader calls a server function, which is a same-origin fetch
 * that passes through Access and so arrives with the header too.
 */
function currentToken(): string | null {
  const forwarded = getRequestHeader('cf-access-jwt-assertion');
  if (forwarded) return forwarded;

  return getCookie(DEV_TOKEN_COOKIE) ?? null;
}

export type ApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; error: string };

/**
 * Call the coffre API as the current user.
 *
 * Note there is no database client anywhere in this app. That is deliberate:
 * a UI that read Postgres directly would return secret values without writing
 * an audit row, which would quietly defeat the entire point of the service.
 *
 * This module is only ever imported by server-function handlers, so it never
 * reaches the client bundle -- and the import of
 * `@tanstack/react-start/server` above would fail loudly if it ever did.
 */
export async function coffreFetch<T>(
  path: string,
  init: RequestInit = {},
): Promise<ApiResult<T>> {
  const token = currentToken();
  if (token === null) {
    return { ok: false, status: 401, error: 'You are not signed in.' };
  }

  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      ...init,
      headers: {
        'cf-access-jwt-assertion': token,
        // Fastify rejects an empty request carrying application/json before it
        // reaches the route. Bodyless DELETEs therefore must not claim to have
        // JSON; calls with a body in this app always serialise JSON.
        ...(init.body === undefined ? {} : { 'content-type': 'application/json' }),
        ...(init.headers ?? {}),
      },
      cache: 'no-store',
    });
  } catch {
    return {
      ok: false,
      status: 503,
      error: 'The coffre API is unreachable. Nothing was read or written.',
    };
  }

  if (!response.ok) {
    // Say what happened and what to do about it. "403" tells the reader
    // nothing, and a bare "forbidden" tells them nothing they can act on.
    const message =
      response.status === 401
        ? 'Your session has expired. Sign in again to continue.'
        : response.status === 403
          ? 'You hold no grant that covers this. Someone with grant.manage on the project can add one.'
          : response.status === 404
            ? 'Not found. It may have been renamed or archived.'
            : `The API returned ${response.status}. Nothing was changed.`;
    return { ok: false, status: response.status, error: message };
  }

  return { ok: true, data: (await response.json()) as T };
}

export type Me = {
  principal: { type: 'user' | 'service'; id: string };
  instanceRole: 'user' | 'owner' | 'root-admin';
  environments: { project: string; environment: string; permissions: Permission[] }[];
};

export type SecretKey = {
  key: string;
  archived: boolean;
  version: number | null;
  updatedAt: string | null;
  updatedBy: string | null;
};

export type Permission =
  | 'secret.read'
  | 'secret.write'
  | 'secret.archive'
  | 'audit.read'
  | 'environment.manage'
  | 'grant.manage'
  | 'project.manage';

export type ProjectSummary = {
  slug: string;
  name: string;
  archivedAt: string | null;
  /** What the caller may do at PROJECT scope. */
  permissions: Permission[];
  environments: {
    slug: string;
    name: string;
    archivedAt: string | null;
    secretCount: number;
  }[];
};

export type GrantRow = {
  id: string;
  principalType: 'user' | 'service';
  principalId: string;
  role: string;
  roleName: string;
  permissions: Permission[];
  scope: 'project' | 'environment';
  environmentSlug: string | null;
  expiresAt: string | null;
};

export type RoleRow = {
  slug: string;
  name: string;
  description: string;
  permissions: Permission[];
  assignableToEnvironment: boolean;
};

/** An audit row exactly as the API returns it. Stays on the server. */
export type AuditEntry = {
  seq: number;
  occurredAt: string;
  actorType: string;
  actorId: string;
  action: string;
  decision: 'allow' | 'deny';
  bundleId: string | null;
  metadata: Record<string, unknown>;
};

/**
 * An audit row as the browser receives it.
 *
 * `metadata` is arbitrary JSON and the table renders one derived string from
 * it, so the projection happens on the server and the rest never leaves it.
 * That is not only tidier: audit metadata is written by the API and may grow
 * fields nobody has audited for disclosure, and shipping the whole object to
 * a browser on the strength of "the UI only reads two keys" is how that goes
 * wrong quietly.
 */
export type AuditRow = {
  seq: number;
  occurredAt: string;
  actorType: string;
  actorId: string;
  action: string;
  decision: 'allow' | 'deny';
  subject: string;
};

/** An identity registered with this Coffre instance. */
export type DirectoryPrincipal = {
  principalType: 'user' | 'service';
  principalId: string;
  instanceRole: 'user' | 'owner' | 'root-admin';
  isRootAdmin: boolean;
};

export type SecretVersion = {
  version: number;
  createdAt: string;
  createdBy: string;
  current: boolean;
  kek: string;
};

export type ImportPlanEntry = {
  key: string;
  action: 'create' | 'update' | 'unchanged';
  version: number | null;
};

export type ImportProblem = { line: number; text: string; reason: string };
