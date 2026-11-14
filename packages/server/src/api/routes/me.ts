import type { Me } from '@coffre/client';
import { runsInstance, type Filter, type Scope } from '@coffre/core/access';

import { places, type PlaceRow } from '../../db/queries/places.ts';
import { canAnywhere, permissionsAt, placeOf, projectsReached } from '../caller.ts';
import { route } from '../route.ts';

/** A scope as the API tells it: its projects by slug, those among `known`. */
function scopeView(scope: Scope, known: readonly PlaceRow[]): Scope {
  const names = new Map(known.map((project) => [project.id, project.slug]));
  const named = (ids: readonly string[]) => ids.flatMap((id) => names.get(id) ?? []).sort();
  const projects: Filter = scope.projects === 'all' ? 'all' : 'only' in scope.projects ? { only: named(scope.projects.only) } : { except: named(scope.projects.except) };
  return { projects, environments: scope.environments };
}

export const meRoutes = {
  /**
   * Who is asking, and every live environment they hold something in:
   * what every page's shell reads first. One call to the vault, shared by
   * all the calls of one render, and one statement.
   *
   * Three of its fields are other areas' to answer, and say "none" until
   * they are served: `setsUpServices` past whoever runs the instance and
   * `serviceSetup` (the policy's row), `personalToken` (the token's label),
   * `features` (what sign-in turns on).
   */
  ...route('GET /me', {
    run: async (ctx): Promise<Me> => {
      const who = await ctx.caller();
      const known = await places(ctx.db, projectsReached(who));
      const environments: Me['environments'] = [];
      for (const project of known) {
        if (project.archived) continue;
        for (const environment of project.environments) {
          if (environment.archived) continue;
          // Someone else's personal config is no place of yours; your own goes by `dev@me`, while the environment it is a config of is there.
          const { parent } = environment;
          if (environment.owner !== null && (environment.owner !== who.principal || parent === null || parent.archived)) continue;
          const permissions = permissionsAt(who, placeOf(project, environment));
          if (permissions.length === 0) continue;
          environments.push({ project: project.slug, environment: environment.owner === null ? environment.slug : `${parent!.slug}@me`, permissions });
        }
      }
      const service = who.principal.startsWith('token:');
      const runs = runsInstance(who.holds);
      return {
        principal: { type: service ? 'service' : 'user', id: who.principal.slice(who.principal.indexOf(':') + 1) },
        // Anyone else is refused before here: the vault has one answer for a credential that does not stand.
        registered: true,
        tampered: false,
        instanceRole: who.holds.role,
        scope: scopeView(who.holds.scope, known),
        runsInstance: runs,
        canReadAudit: canAnywhere(who, 'audit.read'),
        setsUpServices: runs,
        serviceSetup: null,
        features: { mcp: null, workloads: false },
        personalToken: null,
        credentialExpiresAt: who.credential.expiresAt,
        environments,
      };
    },
  }),
};
