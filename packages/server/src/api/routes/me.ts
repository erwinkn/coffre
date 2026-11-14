import type { Me } from '@coffre/client';
import { runsInstance, type Filter, type Scope } from '@coffre/core/access';
import type { Called } from '@coffre/core/vault';

import { placesWithSetup, type PlaceRow } from '../../db/queries/places.ts';
import { canAnywhere, permissionsAt, placeOf, projectsReached, settingOf, setsUpAnywhere } from '../caller.ts';
import { mcpOf, resourceOf } from '../../mcp/oauth.ts';
import { route } from '../route.ts';
import { scopePaths } from './tokens.ts';

/** A scope as the API tells it: its projects by slug, those among `known`. */
function scopeView(scope: Scope, known: readonly PlaceRow[]): Scope {
  const names = new Map(known.map((project) => [project.id, project.slug]));
  const named = (ids: readonly string[]) => ids.flatMap((id) => names.get(id) ?? []).sort();
  const projects: Filter = scope.projects === 'all' ? 'all' : 'only' in scope.projects ? { only: named(scope.projects.only) } : { except: named(scope.projects.except) };
  return { projects, environments: scope.environments };
}

/** The personal token a request came in on, as 0.14.7 named it: none for any other credential. */
function personalToken({ credential, holds }: Called, known: readonly PlaceRow[]): Me['personalToken'] {
  if (credential.kind !== 'personal' || holds.credentialScope == null) return null;
  const slugs = Object.fromEntries(known.flatMap((project) => [[project.id, project.slug], ...project.environments.map((environment) => [environment.id, environment.slug])]));
  return { id: credential.id, label: credential.label ?? '', expiresAt: credential.expiresAt, scope: scopePaths(holds.credentialScope, slugs) };
}

export const meRoutes = {
  /**
   * Who is asking, and every live environment they hold something in:
   * what every page's shell reads first. One call to the vault, shared by
   * all the calls of one render, and one statement, which also reads the
   * instance's setting and, for a person who does not run the instance,
   * every project role: whether they set up service accounts
   * (`setsUpAnywhere`), and the setting (`serviceSetup`), projects by
   * slug, those the caller reaches; none for a service account.
   *
   * A personal token is named (`personalToken`): its label, which the
   * vault's `caller` answers, and its scope by path, from the places read.
   */
  ...route('GET /me', {
    run: async (ctx): Promise<Me> => {
      const who = await ctx.caller();
      const runs = runsInstance(who.holds);
      const person = who.principal.startsWith('user:');
      // The roles weigh only for a person on a credential with no scope, who does not run the instance (`setsUpAnywhere`).
      const read = await placesWithSetup(ctx.db, projectsReached(who), person && !runs && who.holds.credentialScope == null);
      const known = read.places;
      const setting = person ? settingOf(read.setting) : null;
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
      // Where MCP clients connect, when the deployment serves MCP.
      const mcp = mcpOf(ctx.auth);
      return {
        principal: { type: person ? 'user' : 'service', id: who.principal.slice(who.principal.indexOf(':') + 1) },
        // Anyone else is refused before here: the vault has one answer for a credential that does not stand.
        registered: true,
        tampered: false,
        instanceRole: who.holds.role,
        scope: scopeView(who.holds.scope, known),
        runsInstance: runs,
        canReadAudit: canAnywhere(who, 'audit.read'),
        setsUpServices: setsUpAnywhere(who, setting, read.roles, known),
        serviceSetup: setting === null ? null : scopeView(setting, known),
        features: { mcp: mcp === null ? null : resourceOf(mcp.publicUrl), workloads: ctx.auth.mode === 'signin' && ctx.auth.signin.workloads !== null },
        personalToken: personalToken(who, known),
        credentialExpiresAt: who.credential.expiresAt,
        environments,
      };
    },
  }),
};
