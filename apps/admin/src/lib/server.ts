import { createServerFn } from '@tanstack/react-start';
import { getRequestHeader, setCookie } from '@tanstack/react-start/server';
import { authConfig } from './auth-runtime';
import {
  coffreFetch,
  DEV_TOKEN_COOKIE,
  type AuditEntry,
  type AuditRow,
  type GrantRow,
  type ImportPlanEntry,
  type ImportProblem,
  type Me,
  type Permission,
  type DirectoryPrincipal,
  type ProjectSummary,
  type RoleRow,
  type SecretKey,
  type SecretVersion,
} from './api';

/*
 * Every function in this file is a thin wrapper over the coffre API. None of
 * them touch Postgres: the API is what authorises a call and writes the audit
 * row, so routing anything around it would leave it unrecorded.
 *
 * These replace what were Next.js server components (reads) and server actions
 * (writes). The split that matters is unchanged -- the browser never holds a
 * credential and never talks to the API directly.
 *
 * Note there is no delete anywhere. `audit_log` holds ON DELETE RESTRICT
 * references to projects, environments and secrets, so archiving is the real
 * operation.
 */

/**
 * How long a local sign-in lasts, for both the token and the cookie holding it.
 *
 * A working day. This is not a security parameter: dev sign-in exists only
 * because Cloudflare Access is not in front of the app locally, and in
 * production the session lifetime is Access's to decide. The old fifteen
 * minutes was the JWT default rather than a decision, and it meant signing in
 * again four times an hour, since nothing here renews on activity.
 */
const DEV_SESSION_SECONDS = 8 * 60 * 60;

/** Identity, and the project tree the sidebar draws. Needed by every screen. */
export const getShell = createServerFn({ method: 'GET' }).handler(async () => {
  // A principal with no project grants -- an auditor, say -- gets an empty
  // tree rather than an error. The audit log is still theirs to read, and
  // failing here would lock them out of the one screen they are entitled to.
  const [me, projects] = await Promise.all([
    coffreFetch<Me>('/v1/me'),
    coffreFetch<{ projects: ProjectSummary[] }>('/v1/admin/projects'),
  ]);

  return {
    principal: me.ok ? me.data.principal : null,
    instanceRole: me.ok ? me.data.instanceRole : null,
    signInError: me.ok ? null : me.error,
    projects: projects.ok ? projects.data.projects : [],
  };
});

/**
 * Public information needed to render the login boundary accurately.
 *
 * The assertion itself never crosses back to the browser.
 */
export const getLoginAuthState = createServerFn({ method: 'GET' }).handler(async () => ({
  mode: authConfig.mode,
  hasForwardedAccessJwt:
    authConfig.mode === 'cloudflare' &&
    Boolean(getRequestHeader('cf-access-jwt-assertion')),
}));

export const listProjects = createServerFn({ method: 'GET' }).handler(async () => {
  const result = await coffreFetch<{ projects: ProjectSummary[] }>('/v1/admin/projects');
  return result.ok
    ? { ok: true as const, projects: result.data.projects }
    : { ok: false as const, error: result.error };
});

/** One project, plus its real project grants if the caller may manage access. */
export const getProject = createServerFn({ method: 'GET' })
  .inputValidator((data: { project: string }) => data)
  .handler(async ({ data }) => {
    const projects = await coffreFetch<{ projects: ProjectSummary[] }>('/v1/admin/projects');
    if (!projects.ok) return { ok: false as const, error: projects.error };

    const project = projects.data.projects.find((entry) => entry.slug === data.project);
    if (!project) return { ok: false as const, error: null };

    // Only grant.manage holders may see the access list, so everyone else gets
    // the page without it rather than an error page.
    const canManageGrants = project.permissions.includes('grant.manage');
    const grants = canManageGrants
      ? await coffreFetch<{ grants: GrantRow[] }>(
          `/v1/admin/projects/${data.project}/grants`,
        )
      : null;

    return {
      ok: true as const,
      project,
      grants: grants?.ok ? grants.data.grants : [],
      grantsError: grants && !grants.ok ? grants.error : null,
    };
  });

export const listKeys = createServerFn({ method: 'GET' })
  .inputValidator((data: { project: string; environment: string }) => data)
  .handler(async ({ data }) => {
    const result = await coffreFetch<{ permissions: Permission[]; keys: SecretKey[] }>(
      `/v1/projects/${data.project}/environments/${data.environment}/keys`,
    );
    return result.ok
      ? { ok: true as const, permissions: result.data.permissions, keys: result.data.keys }
      : { ok: false as const, error: result.error };
  });

export const listAudit = createServerFn({ method: 'GET' })
  .inputValidator((data: { decision?: 'deny'; actorId?: string }) => data)
  .handler(async ({ data }) => {
    const query = new URLSearchParams({ limit: '200' });
    if (data.decision === 'deny') query.set('decision', 'deny');
    if (data.actorId) query.set('actorId', data.actorId);

    const result = await coffreFetch<{ entries: AuditEntry[] }>(`/v1/audit?${query}`);
    if (!result.ok) return { ok: false as const, error: result.error };

    // Project to the columns the table draws; see AuditRow for why metadata
    // does not cross to the browser.
    const entries: AuditRow[] = result.data.entries.map((entry) => ({
      seq: entry.seq,
      occurredAt: entry.occurredAt,
      actorType: entry.actorType,
      actorId: entry.actorId,
      action: entry.action,
      decision: entry.decision,
      subject:
        (typeof entry.metadata.key === 'string' ? entry.metadata.key : null) ??
        (typeof entry.metadata.reason === 'string' ? entry.metadata.reason : null) ??
        '--',
    }));

    return { ok: true as const, entries };
  });

export const listDirectoryPrincipals = createServerFn({ method: 'GET' }).handler(async () => {
  const result = await coffreFetch<{ principals: DirectoryPrincipal[] }>(
    '/v1/admin/directory',
  );
  if (!result.ok && result.status === 403) {
    return {
      ok: false as const,
      error: 'Only owners can manage users and service accounts.',
    };
  }
  return result.ok
    ? { ok: true as const, principals: result.data.principals }
    : { ok: false as const, error: result.error };
});

/* -------------------------------------------------------------------------- */
/* Secrets                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Reveal a secret value.
 *
 * This goes through the API like everything else, so it authorises the user
 * and writes an audit row. Revealing a secret in the UI is a read, and is
 * recorded as one -- that is the property that makes the UI safe to have.
 *
 * POST rather than GET so it is never a cacheable, prefetchable or
 * link-shaped request. A reveal must happen exactly when someone asks for it,
 * because each one costs an audit row with their name on it.
 */
export const revealSecret = createServerFn({ method: 'POST' })
  .inputValidator((data: { project: string; environment: string; key: string }) => data)
  .handler(async ({ data }) => {
    const result = await coffreFetch<{ value: string }>(
      `/v1/projects/${data.project}/environments/${data.environment}/secrets/${data.key}`,
    );
    return result.ok
      ? { ok: true as const, value: result.data.value }
      : { ok: false as const, error: result.error };
  });

export const saveSecret = createServerFn({ method: 'POST' })
  .inputValidator(
    (data: { project: string; environment: string; key: string; value: string }) => data,
  )
  .handler(async ({ data }) => {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(data.key)) {
      return { ok: false as const, error: 'Key must look like AN_ENV_VAR.' };
    }

    const result = await coffreFetch<{ version: number }>(
      `/v1/projects/${data.project}/environments/${data.environment}/secrets/${data.key}`,
      { method: 'PUT', body: JSON.stringify({ value: data.value }) },
    );
    return result.ok
      ? { ok: true as const, version: result.data.version }
      : { ok: false as const, error: result.error };
  });

export const renameSecret = createServerFn({ method: 'POST' })
  .inputValidator(
    (data: { project: string; environment: string; key: string; nextKey: string }) => data,
  )
  .handler(async ({ data }) => {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(data.nextKey)) {
      return { ok: false as const, error: 'Key must look like AN_ENV_VAR.' };
    }

    const result = await coffreFetch(
      `/v1/projects/${data.project}/environments/${data.environment}/secrets/${data.key}`,
      { method: 'PATCH', body: JSON.stringify({ key: data.nextKey }) },
    );
    return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
  });

/**
 * Retire or restore a secret.
 *
 * Not a delete: archiving stops it being served and drops it from bulk fetch,
 * so a rotated-out credential stops being injected into processes -- while its
 * history stays intact.
 */
export const setSecretArchived = createServerFn({ method: 'POST' })
  .inputValidator(
    (data: { project: string; environment: string; key: string; archived: boolean }) => data,
  )
  .handler(async ({ data }) => {
    const result = await coffreFetch(
      `/v1/projects/${data.project}/environments/${data.environment}/secrets/${data.key}/archive`,
      { method: 'POST', body: JSON.stringify({ archived: data.archived }) },
    );
    return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
  });

/** Version history. Metadata only -- no values are returned or logged as read. */
export const listVersions = createServerFn({ method: 'POST' })
  .inputValidator((data: { project: string; environment: string; key: string }) => data)
  .handler(async ({ data }) => {
    const result = await coffreFetch<{ versions: SecretVersion[] }>(
      `/v1/projects/${data.project}/environments/${data.environment}/secrets/${data.key}/versions`,
    );
    return result.ok
      ? { ok: true as const, versions: result.data.versions }
      : { ok: false as const, error: result.error };
  });

/**
 * Roll back to an earlier version.
 *
 * Repoints the current pointer; nothing is copied or rewritten, because
 * versions are append-only. Audited with both the old and new version.
 */
export const rollbackSecret = createServerFn({ method: 'POST' })
  .inputValidator(
    (data: { project: string; environment: string; key: string; version: number }) => data,
  )
  .handler(async ({ data }) => {
    const result = await coffreFetch(
      `/v1/projects/${data.project}/environments/${data.environment}/secrets/${data.key}/rollback`,
      { method: 'POST', body: JSON.stringify({ version: data.version }) },
    );
    return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
  });

/**
 * Bulk import a .env file. `dryRun` returns the plan without writing.
 *
 * Parsing happens server-side so the UI and CLI cannot disagree about what a
 * .env file means.
 */
export const importEnv = createServerFn({ method: 'POST' })
  .inputValidator(
    (data: { project: string; environment: string; content: string; dryRun: boolean }) => data,
  )
  .handler(async ({ data }) => {
    const result = await coffreFetch<{ plan: ImportPlanEntry[]; problems: ImportProblem[] }>(
      `/v1/projects/${data.project}/environments/${data.environment}/import`,
      {
        method: 'POST',
        body: JSON.stringify({ content: data.content, dryRun: data.dryRun }),
      },
    );
    return result.ok
      ? {
          ok: true as const,
          plan: result.data.plan,
          problems: result.data.problems ?? [],
        }
      : { ok: false as const, error: result.error };
  });

/* -------------------------------------------------------------------------- */
/* Audit                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Recompute the chain, for the status shown on the audit page.
 *
 * GET rather than POST because this is a read that a loader runs on every
 * visit, not an action someone triggers. There is no button for it: a control
 * you have to press to learn whether your audit log is intact is one nobody
 * presses on the day it matters.
 */
export const verifyAuditChain = createServerFn({ method: 'GET' }).handler(async () => {
  const result = await coffreFetch<
    { ok: true; rows: number; head: string } | { ok: false; failedAtSeq: number; reason: string }
  >('/v1/audit/verify');

  if (!result.ok) return { ok: false as const, error: result.error };
  if (!result.data.ok) {
    return {
      ok: false as const,
      error: `Chain broken at seq ${result.data.failedAtSeq}: ${result.data.reason}`,
    };
  }
  return { ok: true as const, rows: result.data.rows, head: result.data.head };
});

/* -------------------------------------------------------------------------- */
/* Projects, environments and grants                                           */
/* -------------------------------------------------------------------------- */

const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;

function badSlug(value: string): string | null {
  return SLUG.test(value)
    ? null
    : 'must be lowercase letters, digits and hyphens, starting with a letter or digit';
}

export const createProject = createServerFn({ method: 'POST' })
  .inputValidator((data: { slug: string; name: string }) => data)
  .handler(async ({ data }) => {
    const invalid = badSlug(data.slug);
    if (invalid) return { ok: false as const, error: `Slug ${invalid}.` };
    if (data.name.trim() === '') return { ok: false as const, error: 'Name is required.' };

    const result = await coffreFetch('/v1/admin/projects', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
  });

export const updateProject = createServerFn({ method: 'POST' })
  .inputValidator((data: { project: string; slug: string; name: string }) => data)
  .handler(async ({ data }) => {
    const invalid = badSlug(data.slug);
    if (invalid) return { ok: false as const, error: `Slug ${invalid}.` };

    const result = await coffreFetch(`/v1/admin/projects/${data.project}`, {
      method: 'PATCH',
      body: JSON.stringify({ slug: data.slug, name: data.name }),
    });
    return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
  });

export const setProjectArchived = createServerFn({ method: 'POST' })
  .inputValidator((data: { project: string; archived: boolean }) => data)
  .handler(async ({ data }) => {
    const result = await coffreFetch(`/v1/admin/projects/${data.project}/archive`, {
      method: 'POST',
      body: JSON.stringify({ archived: data.archived }),
    });
    return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
  });

export const createEnvironment = createServerFn({ method: 'POST' })
  .inputValidator((data: { project: string; slug: string; name: string }) => data)
  .handler(async ({ data }) => {
    const invalid = badSlug(data.slug);
    if (invalid) return { ok: false as const, error: `Slug ${invalid}.` };
    if (data.name.trim() === '') return { ok: false as const, error: 'Name is required.' };

    const result = await coffreFetch(`/v1/admin/projects/${data.project}/environments`, {
      method: 'POST',
      body: JSON.stringify({ slug: data.slug, name: data.name }),
    });
    return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
  });

export const updateEnvironment = createServerFn({ method: 'POST' })
  .inputValidator(
    (data: { project: string; environment: string; slug: string; name: string }) => data,
  )
  .handler(async ({ data }) => {
    const invalid = badSlug(data.slug);
    if (invalid) return { ok: false as const, error: `Slug ${invalid}.` };

    const result = await coffreFetch(
      `/v1/admin/projects/${data.project}/environments/${data.environment}`,
      { method: 'PATCH', body: JSON.stringify({ slug: data.slug, name: data.name }) },
    );
    return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
  });

export const setEnvironmentArchived = createServerFn({ method: 'POST' })
  .inputValidator(
    (data: { project: string; environment: string; archived: boolean }) => data,
  )
  .handler(async ({ data }) => {
    const result = await coffreFetch(
      `/v1/admin/projects/${data.project}/environments/${data.environment}/archive`,
      { method: 'POST', body: JSON.stringify({ archived: data.archived }) },
    );
    return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
  });

export const createGrant = createServerFn({ method: 'POST' })
  .inputValidator(
    (data: {
      project: string;
      principalType: 'user' | 'service';
      principalId: string;
      role: string;
      environmentSlug: string | null;
      expiresAt: string | null;
    }) => data,
  )
  .handler(async ({ data }) => {
    const { project, ...input } = data;
    if (input.principalId.trim() === '') {
      return { ok: false as const, error: 'Principal is required.' };
    }

    const result = await coffreFetch(`/v1/admin/projects/${project}/grants`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
    return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
  });

export const revokeGrant = createServerFn({ method: 'POST' })
  .inputValidator((data: { project: string; grantId: string }) => data)
  .handler(async ({ data }) => {
    const result = await coffreFetch(
      `/v1/admin/projects/${data.project}/grants/${data.grantId}`,
      { method: 'DELETE' },
    );
    return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
  });

export const updateGrant = createServerFn({ method: 'POST' })
  .inputValidator((data: { project: string; grantId: string; role: string }) => data)
  .handler(async ({ data }) => {
    const result = await coffreFetch(
      `/v1/admin/projects/${data.project}/grants/${data.grantId}`,
      { method: 'PATCH', body: JSON.stringify({ role: data.role }) },
    );
    return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
  });

export const createDirectoryPrincipal = createServerFn({ method: 'POST' })
  .inputValidator(
    (data: {
      principalType: 'user' | 'service';
      principalId: string;
      instanceRole: 'user' | 'owner';
    }) => data,
  )
  .handler(async ({ data }) => {
    if (data.principalId.trim() === '') {
      return { ok: false as const, error: 'Identity is required.' };
    }
    const result = await coffreFetch('/v1/admin/directory', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
  });

export const updateDirectoryPrincipalRole = createServerFn({ method: 'POST' })
  .inputValidator(
    (data: { principalId: string; instanceRole: 'user' | 'owner' }) => data,
  )
  .handler(async ({ data }) => {
    const result = await coffreFetch(
      `/v1/admin/directory/user/${encodeURIComponent(data.principalId)}`,
      {
        method: 'PATCH',
        body: JSON.stringify({ instanceRole: data.instanceRole }),
      },
    );
    return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
  });

export const removeDirectoryPrincipal = createServerFn({ method: 'POST' })
  .inputValidator(
    (data: { principalType: 'user' | 'service'; principalId: string }) => data,
  )
  .handler(async ({ data }) => {
    const result = await coffreFetch(
      `/v1/admin/directory/${data.principalType}/${encodeURIComponent(data.principalId)}`,
      { method: 'DELETE' },
    );
    return result.ok ? { ok: true as const } : { ok: false as const, error: result.error };
  });

/* -------------------------------------------------------------------------- */
/* Dev sign-in                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Dev-only sign-in.
 *
 * In production this does not exist in any meaningful sense: Cloudflare Access
 * authenticates the user before the request reaches this app and forwards
 * `Cf-Access-Jwt-Assertion`, and lib/api.ts reads only that header in
 * Cloudflare mode. This exists so the same UI can run locally against the dev
 * IdP, and it refuses to do anything unless the validated mode is explicitly
 * `dev`.
 */
export const devSignIn = createServerFn({ method: 'POST' })
  .inputValidator((data: { email: string }) => data)
  .handler(async ({ data }) => {
    if (authConfig.mode !== 'dev') {
      return { ok: false as const, error: 'Dev sign-in is disabled.' };
    }

    const url = new URL('/dev/mint', authConfig.devIdpUrl);
    url.searchParams.set('email', data.email);
    url.searchParams.set('aud', authConfig.access.audience);
    url.searchParams.set('expires_in', String(DEV_SESSION_SECONDS));

    let minted: Response;
    try {
      minted = await fetch(url);
    } catch {
      return { ok: false as const, error: 'The dev IdP is unreachable.' };
    }
    if (!minted.ok) return { ok: false as const, error: 'The dev IdP refused to mint a token.' };

    const { token } = (await minted.json()) as { token: string };
    // Same lifetime as the token inside it. A cookie that outlives its token
    // buys nothing: the API rejects the expired JWT and you are sent back to
    // sign in regardless.
    setCookie(DEV_TOKEN_COOKIE, token, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: DEV_SESSION_SECONDS,
    });

    return { ok: true as const };
  });
