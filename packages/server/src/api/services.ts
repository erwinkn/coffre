import {
  assignableToEnvironment,
  isCredentialScope,
  issuesCredential,
  managesService,
  runsInstance,
  setsUpServices,
  type CredentialScope,
  type Place,
  type Role,
  type ServiceAccount,
  type ServiceSetting,
} from '@coffre/core/access';
import type { Access, Vault } from '@coffre/core/vault';
import type { Database, Queryable } from '@coffre/db';
import { unsealedCredentials } from '@coffre/db/grants';
import { credentials, serviceBindings } from '@coffre/db/schema';

import { places, updateAuth, type PlaceRow, type StoredGrant } from '../db/queries.ts';
import type { Caller } from './caller.ts';
import { placeOf } from './caller.ts';
import { denied, Refusal, type ApiContext } from './context.ts';
import { badRequest, forbidden, notFound } from './errors.ts';
import { formatMember, formatPath, parsePath } from './paths.ts';

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

// Credentials' scopes (docs/design/instance-roles.md, "Credentials' scopes"):
// each token and trust binding carries its own, at most what its account
// held and its issuer could give when it was made (`issuesCredential`), and
// a request made with it holds what both it and the account hold now.

/** A credential's scope as the API names it: each place by its path, `market` or `market/dev`, and the role there. */
export type ScopeByPath = Record<string, Role>;

/** A scope as a token's or binding's row stores it, under its MAC: its grants as JSON, by place. */
export function storedScope(scope: CredentialScope): string {
  const key = (grant: CredentialScope[number]) => `${grant.projectId}/${grant.environmentId ?? ''}`;
  return JSON.stringify(
    [...scope]
      .sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0))
      .map(({ projectId, environmentId, role }) => ({ projectId, environmentId, role })),
  );
}

/**
 * The scope a row stores: null for one 0.4 made, not sealed yet, which
 * reaches all its account holds, as then. One its MAC checked but that
 * does not read as a scope reaches nothing.
 */
export function readScope(stored: string | null): CredentialScope | null {
  if (stored === null) return null;
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(stored);
  } catch {}
  return isCredentialScope(parsed) ? parsed : [];
}

/** A scope by path, as the caller would name its places now; one deleted is left out, as it reaches nothing. */
export function scopeByPath(scope: CredentialScope | null, known: readonly PlaceRow[]): ScopeByPath | null {
  if (scope === null) return null;
  const named = scope.flatMap((grant): [string, Role][] => {
    const project = known.find((candidate) => candidate.id === grant.projectId);
    if (project === undefined) return [];
    if (grant.environmentId === null) return [[project.slug, grant.role]];
    const environment = project.environments.find((candidate) => candidate.id === grant.environmentId);
    return environment === undefined ? [] : [[`${project.slug}/${environment.slug}`, grant.role]];
  });
  return Object.fromEntries(named.sort(([a], [b]) => (a < b ? -1 : 1)));
}

/**
 * The scope a token or a trust binding of an account is made with, as the
 * caller asked for it, by path, or everything the account holds when they
 * did not: checked, each grant one the account holds and the caller could
 * give it (`issuesCredential`). A scope that reaches nothing is refused:
 * the account needs a grant first, since nothing it is given later reaches
 * a credential made before.
 */
export async function issuedScope(
  db: Queryable,
  ctx: Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'>,
  setting: ServiceSetting | null,
  standing: Access,
  wanted: ScopeByPath | undefined,
  refused: { action: 'token.create' | 'token.bind'; metadata: Record<string, unknown> },
): Promise<{ scope: CredentialScope; byPath: ScopeByPath }> {
  const known = await places(db);
  const account = accountOf(standing.grants, standing.by, known);
  const scope = wanted === undefined
    ? account.grants
    : Object.entries(wanted).map(([raw, role]) => {
      const path = parsePath(raw, [1, 2]);
      const project = known.find((candidate) => candidate.slug === path.project);
      if (project === undefined) throw notFound(`no project "${path.project}"`);
      if (path.environment === undefined) return { role, place: placeOf(project, null) };
      const environment = project.environments.find((candidate) => candidate.slug === path.environment);
      if (environment === undefined) throw notFound(`no environment "${formatPath(path)}"`);
      if (!assignableToEnvironment(role)) throw badRequest(`${role} includes permissions that only make sense on a whole project; name "${path.project}"`);
      return { role, place: placeOf(project, environment) };
    });
  if (new Set(scope.map(({ place }) => `${place.projectId}/${place.environmentId ?? ''}`)).size !== scope.length) throw badRequest('name each place once');
  if (scope.length === 0) {
    throw badRequest('a credential reaches only what its account holds when it is made: give the account a grant first');
  }
  const actor = formatMember(ctx.caller.principal);
  const beyond = scope.find((grant) => !issuesCredential(ctx.caller, setting, actor, account, [grant]));
  if (beyond !== undefined) {
    const path = Object.keys(scopeByPath([asGrant(beyond)], known)!)[0]!;
    throw new Refusal(
      forbidden(`a credential reaches at most what its account holds and what you could give it: not ${path}`),
      denied(ctx, refused.action, 'beyond_account', { metadata: { ...refused.metadata, path } }),
    );
  }
  const issued = scope.map(asGrant);
  return { scope: issued, byPath: scopeByPath(issued, known)! };
}

function asGrant({ role, place }: ServiceAccount['grants'][number]): CredentialScope[number] {
  return { projectId: place.projectId, environmentId: place.environmentId ?? null, role };
}

/**
 * Seal the tokens and trust bindings 0.4 made, which carry no scope, with
 * what their account holds now: once a process, before it checks its first
 * credential (`SigninService.verify`), so each keeps what it reached and
 * nothing granted after reaches it. A row 0.4 still makes while both run
 * reaches all its account holds, as then, until the next process seals it.
 * Each update matches the row's MAC as read, so two processes at once seal
 * a row once. Returns how many rows it sealed.
 */
export async function sealScopes(db: Database, chainKey: Buffer, vault: Vault): Promise<number> {
  const unsealed = await unsealedCredentials(db, new Date());
  let sealed = 0;
  for (const principal of new Set(unsealed.map((row) => row.principal))) {
    const access = await vault.access(principal);
    if (access.status !== 'active') continue;
    const scope = storedScope(access.grants.map(({ projectId, environmentId, role }) => ({ projectId, environmentId, role })));
    for (const row of unsealed.filter((candidate) => candidate.principal === principal)) {
      sealed += row.kind === 'token'
        ? await updateAuth(db, chainKey, credentials, { id: row.id, scope: null }, { scope })
        : await updateAuth(db, chainKey, serviceBindings, { id: row.id, scope: null }, { scope });
    }
  }
  return sealed;
}
