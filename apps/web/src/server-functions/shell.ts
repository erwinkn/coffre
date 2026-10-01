import { missingIdentityMessage } from '../lib/auth-mode.ts';
import { deriveUiCapabilities } from '../lib/capabilities.ts';
import { getRuntime } from '../server/runtime.ts';
import { sessionServerFn } from '../server/server-fn.ts';
import type { ProjectSummary } from '../shared/models.ts';
import { api, currentIdentity } from './session.ts';
import { uiResult } from './result.ts';

/** Identity and project tree used by the application shell. */
export const getShell = sessionServerFn({ method: 'GET' }).handler(async () => {
  const identity = currentIdentity();
  const authMode = getRuntime().auth.mode;
  if (identity?.principal !== null && identity?.principal !== undefined && !identity.registered) {
    return {
      principal: { type: identity.principal.type, id: identity.principal.id },
      instanceRole: null,
      signInError: null,
      projects: [] as ProjectSummary[],
      capabilities: deriveUiCapabilities(null, []),
      registrationRequired: true,
      authMode,
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
      authMode,
    };
  }

  const coffre = api();
  const [meResult, projectsResult] = await Promise.all([
    uiResult(async () => ({ me: await coffre.me() })),
    uiResult(() => coffre.projects.list()),
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
    authMode,
  };
});
