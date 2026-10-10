import { managesService, runsInstance, setsUpServices, type Place, type Role, type ServiceAccount, type ServiceSetting } from '@coffre/core/access';
import type { Access, Vault } from '@coffre/core/vault';
import type { Queryable } from '@coffre/db';

import { places, type PlaceRow, type StoredGrant } from '../db/queries.ts';
import type { Caller } from './caller.ts';
import { placeOf } from './caller.ts';
import { denied, Refusal, type ApiContext } from './context.ts';
import { forbidden } from './errors.ts';
import { formatMember } from './paths.ts';

// Setting up service accounts without running the instance
// (docs/design/instance-roles.md, "Setting up service accounts"): the
// rules are core's (`givesService`, `managesService`); the vault holds the
// setting and decides on members and grants, and the app on the tokens and
// trust bindings it keeps, by the same rules.

/** The instance's setting as it applies to the caller: null for a service account, which sets none up. */
export async function serviceSettingFor(vault: Vault, caller: Caller): Promise<ServiceSetting | null> {
  if (caller.principal.type !== 'user' || !caller.registered) return null;
  return (await vault.settings()).serviceAccounts;
}

/** Every project and environment there is, as a permission check names them. */
export function everyPlace(known: readonly PlaceRow[]): Place[] {
  return known.flatMap((project) => [placeOf(project, null), ...project.environments.map((environment) => placeOf(project, environment))]);
}

/** Whether the caller sets up any service account: who runs the instance, or a person who could give one a grant somewhere. */
export function setsUp(caller: Caller, setting: ServiceSetting | null, known: readonly PlaceRow[]): boolean {
  return runsInstance(caller) || setsUpServices(caller, setting, everyPlace(known));
}

/**
 * A service account as `managesService` weighs it, from its grants as
 * stored or as the vault answers them: those on a place that is gone reach
 * nothing, and are left out.
 */
export function accountOf(
  grants: readonly Pick<StoredGrant, 'projectId' | 'environmentId' | 'role'>[],
  admittedBy: string | null,
  known: readonly PlaceRow[],
): ServiceAccount {
  return {
    grants: grants.flatMap((grant) => {
      const project = known.find((candidate) => candidate.id === grant.projectId);
      const environment = grant.environmentId === null ? null : project?.environments.find((candidate) => candidate.id === grant.environmentId);
      if (project === undefined || environment === undefined) return [];
      return [{ role: grant.role as Role, place: placeOf(project, environment) }];
    }),
    admittedBy,
  };
}

/**
 * One service account as the vault has it now, and whether the caller
 * manages it: issues and revokes its tokens, adds and removes its trust
 * bindings. Who runs the instance manages every one, removed or not, as
 * before; anyone else, an active one whose every grant they reach. With
 * the setting as it applies to the caller: null for who runs the instance.
 */
export async function managedAccount(
  deps: { db: Queryable; vault: Vault },
  caller: Caller,
  serviceId: string,
): Promise<{ standing: Access; managed: boolean; setting: ServiceSetting | null }> {
  const member = `token:${serviceId}`;
  const standing = await deps.vault.access(member);
  if (runsInstance(caller)) return { standing, managed: true, setting: null };
  const setting = await serviceSettingFor(deps.vault, caller);
  if (setting === null || standing.status !== 'active') return { standing, managed: false, setting };
  const account = accountOf(standing.grants, standing.by, await places(deps.db));
  return { standing, managed: managesService(caller, setting, formatMember(caller.principal), account), setting };
}

/** Why a person may not change a service account's grants, in the vault's words too. */
export const NOT_THEIRS = 'a person gives a service account at most what they hold, where the instance lets people set them up, and only to one whose every grant they hold';

/** Refuse, and log the refusal, for someone who does not manage the service account. */
export function notManager(ctx: Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'>, action: string, metadata: Record<string, unknown>, what: string): Refusal {
  return new Refusal(
    forbidden(`only those who manage this service account may ${what}: who runs the instance, or a person who holds everything it holds, where the instance lets people set service accounts up`),
    denied(ctx, action, 'not_service_manager', { metadata }),
  );
}
