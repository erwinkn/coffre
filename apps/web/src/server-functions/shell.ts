import { missingIdentityMessage } from '../lib/auth-mode.ts';
import { deriveUiCapabilities } from '../lib/capabilities.ts';
import { getMe } from '../server/queries/me.ts';
import { getRuntime } from '../server/runtime.ts';
import { sessionServerFn } from '../server/server-fn.ts';
import type { ProjectSummary } from '../shared/models.ts';
import { currentIdentity, currentRequestContext } from './session.ts';
import { uiResult } from './result.ts';

/** Identity and project tree used by the application shell. */
export const getShell = sessionServerFn({ method: 'GET' }).handler(async () => {
  const identity = currentIdentity();
  if (identity?.principal !== null && identity?.principal !== undefined && !identity.registered) {
    return {
      principal: { type: identity.principal.type, id: identity.principal.id },
      instanceRole: null,
      signInError: null,
      projects: [] as ProjectSummary[],
      capabilities: deriveUiCapabilities(null, []),
      registrationRequired: true,
    };
  }

  if (identity === undefined || identity.principal === null) {
    return {
      principal: null,
      instanceRole: null,
      signInError: missingIdentityMessage(getRuntime().auth),
      projects: [] as ProjectSummary[],
      capabilities: deriveUiCapabilities(null, []),
      registrationRequired: false,
    };
  }

  const runtime = getRuntime();
  const ctx = currentRequestContext();
  const [meResult, projectsResult] = await Promise.all([
    uiResult(async () => ({ me: await getMe(runtime, ctx) })),
    uiResult(async () => ({ projects: await runtime.admin.listProjects(ctx) })),
  ]);
  const me = meResult.ok ? meResult.me : null;
  const projects = projectsResult.ok ? projectsResult.projects : [];

  return {
    principal: me?.principal ?? null,
    instanceRole: me?.instanceRole ?? null,
    signInError: meResult.ok ? null : meResult.error,
    projects,
    capabilities: deriveUiCapabilities(me, projects),
    registrationRequired: false,
  };
});
