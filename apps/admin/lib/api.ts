import { cookies, headers } from 'next/headers';

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
 */
async function currentToken(): Promise<string | null> {
  const requestHeaders = await headers();
  const forwarded = requestHeaders.get('cf-access-jwt-assertion');
  if (forwarded) return forwarded;

  const store = await cookies();
  return store.get(DEV_TOKEN_COOKIE)?.value ?? null;
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
 */
export async function coffreFetch<T>(
  path: string,
  init: RequestInit = {},
): Promise<ApiResult<T>> {
  const token = await currentToken();
  if (token === null) {
    return { ok: false, status: 401, error: 'not signed in' };
  }

  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      ...init,
      headers: {
        'cf-access-jwt-assertion': token,
        'content-type': 'application/json',
        ...(init.headers ?? {}),
      },
      cache: 'no-store',
    });
  } catch {
    return { ok: false, status: 503, error: 'coffre API is unreachable' };
  }

  if (!response.ok) {
    const message =
      response.status === 401
        ? 'not signed in'
        : response.status === 403
          ? 'you do not have a grant for this environment'
          : response.status === 404
            ? 'not found'
            : `request failed (${response.status})`;
    return { ok: false, status: response.status, error: message };
  }

  return { ok: true, data: (await response.json()) as T };
}

export type Me = {
  principal: { type: 'user' | 'service'; id: string };
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
