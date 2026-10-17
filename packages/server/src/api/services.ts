import {
  allows,
  assignableToEnvironment,
  delegable,
  DELEGABLE_ROLES,
  isCredentialScope,
  issuesCredential,
  managesService,
  NOTHING,
  ROLES,
  runsInstance,
  setsUpServices,
  type CredentialScope,
  type Holdings,
  type Place,
  type Role,
  type ServiceAccount,
  type ServiceSetting,
} from '@coffre/core/access';
import type { Access, Vault } from '@coffre/core/vault';
import type { Database, Queryable } from '@coffre/db';
import { unsealedCredentials, type Unsealed } from '@coffre/db/grants';
import { credentials, serviceBindings } from '@coffre/db/schema';

import { memberOf, places, updateAuth, type PlaceRow, type StoredGrant } from '../db/queries.ts';
import type { Caller } from './caller.ts';
import { placeOf } from './caller.ts';
import { audited, denied, Refusal, type ApiContext } from './context.ts';
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
 * A scope as asked, by path, checked as far as it can be without the
 * database: each path a project or an environment, and each role one its
 * place takes.
 */
export function parseScope(wanted: ScopeByPath): { path: ReturnType<typeof parsePath>; role: Role }[] {
  return Object.entries(wanted).map(([raw, role]) => {
    const path = parsePath(raw, [1, 2]);
    if (path.environment !== undefined && !assignableToEnvironment(role)) {
      throw badRequest(`${role} includes permissions that only make sense on a whole project; name "${path.project}"`);
    }
    return { path, role };
  });
}

/**
 * The scope a token or a trust binding of an account is made with, as the
 * caller asked for it, by path; when they did not, everything the account
 * holds, or for a binding that takes the place of others, what those
 * reached of what the account still holds (`inherited`), so that trusting
 * a workload again never widens it. Checked, each grant one the account
 * holds and the caller could give it (`issuesCredential`). A scope that
 * reaches nothing is refused: the account needs a grant first, since
 * nothing it is given later reaches a credential made before.
 */
export async function issuedScope(
  db: Queryable,
  ctx: Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'>,
  setting: ServiceSetting | null,
  standing: Access,
  wanted: ScopeByPath | undefined,
  refused: { action: 'token.create' | 'token.bind'; metadata: Record<string, unknown> },
  inherited?: CredentialScope,
): Promise<{ scope: CredentialScope; byPath: ScopeByPath }> {
  const known = await places(db);
  const account = accountOf(standing.grants, standing.by, known);
  let scope: ServiceAccount['grants'];
  if (wanted !== undefined) {
    scope = placedScope(wanted, known);
  } else if (inherited !== undefined) {
    // What the replaced bindings reached and the account still holds: a place deleted, or a role it lost, drops out.
    const held: Holdings = { ...NOTHING, grants: account.grants.map(asGrant) };
    scope = accountOf(inherited, null, known).grants
      .filter(({ role, place }) => ROLES[role].permissions.every((permission) => allows(held, permission, place)));
    if (scope.length === 0) throw badRequest('the bindings it replaces reach nothing the account still holds: say what it reaches');
  } else {
    scope = account.grants;
  }
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

/**
 * A scope asked by path, each place found as it is now: one that is not
 * there is not found. Each place once.
 */
function placedScope(wanted: ScopeByPath, known: readonly PlaceRow[]): ServiceAccount['grants'] {
  const scope = parseScope(wanted).map(({ path, role }) => {
    const project = known.find((candidate) => candidate.slug === path.project);
    if (project === undefined) throw notFound(`no project "${path.project}"`);
    if (path.environment === undefined) return { role, place: placeOf(project, null) };
    const environment = project.environments.find((candidate) => candidate.slug === path.environment);
    if (environment === undefined) throw notFound(`no environment "${formatPath(path)}"`);
    return { role, place: placeOf(project, environment) };
  });
  if (new Set(scope.map(({ place }) => `${place.projectId}/${place.environmentId ?? ''}`)).size !== scope.length) throw badRequest('name each place once');
  return scope;
}

/**
 * The scope a personal token is made with, as its person asked for it, by
 * path: each role one that manages no access (`delegable`), and one they
 * hold all of at its place now, by their instance role or a grant
 * (`holder`, as the vault answers them, with no credential's scope). One
 * that reaches nothing is refused: a token reaches what it names, and
 * nothing its person is given later.
 */
export async function personalScope(
  db: Queryable,
  ctx: Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'>,
  holder: Holdings,
  wanted: ScopeByPath,
  metadata: Record<string, unknown>,
): Promise<{ scope: CredentialScope; byPath: ScopeByPath }> {
  const known = await places(db);
  const scope = placedScope(wanted, known);
  if (scope.length === 0) throw badRequest('say what the token reaches: a role on a project or an environment, as --scope market/dev=viewer');
  const issued = scope.map(asGrant);
  const named = (grant: ServiceAccount['grants'][number]) => Object.keys(scopeByPath([asGrant(grant)], known)!)[0]!;
  const managing = scope.find(({ role }) => !delegable(role));
  if (managing !== undefined) {
    throw badRequest(`a personal token never manages access: name ${DELEGABLE_ROLES.join(', ')} on ${named(managing)}, not ${managing.role}`);
  }
  const beyond = scope.find(({ role, place }) => !ROLES[role].permissions.every((permission) => allows(holder, permission, place)));
  if (beyond !== undefined) {
    const path = named(beyond);
    throw new Refusal(
      forbidden(`a personal token reaches at most what you hold: not ${beyond.role} on ${path}`),
      denied(ctx, 'token.create', 'beyond_holder', { metadata: { ...metadata, path } }),
    );
  }
  return { scope: issued, byPath: scopeByPath(issued, known)! };
}

/**
 * What the bindings a new one replaces reached, together, by id: what it
 * reaches unless told (`issuedScope`). Undefined when it replaces none, or
 * one 0.4 made and the app has not sealed, which reached all the account
 * held. Two that reach a place with different roles are for the caller to
 * choose between.
 */
export function inheritedScope(replaced: readonly { scope: string | null }[]): CredentialScope | undefined {
  if (replaced.length === 0) return undefined;
  const scopes = replaced.map((row) => readScope(row.scope));
  if (scopes.some((scope) => scope === null)) return undefined;
  const byPlace = new Map<string, CredentialScope[number]>();
  for (const grant of scopes.flat() as CredentialScope[number][]) {
    const place = `${grant.projectId}/${grant.environmentId ?? ''}`;
    const before = byPlace.get(place);
    if (before !== undefined && before.role !== grant.role) {
      throw badRequest('the bindings it replaces reach one place with different roles: say what it reaches');
    }
    byPlace.set(place, grant);
  }
  return [...byPlace.values()];
}

function asGrant({ role, place }: ServiceAccount['grants'][number]): CredentialScope[number] {
  return { projectId: place.projectId, environmentId: place.environmentId ?? null, role };
}

/**
 * Seal the tokens and trust bindings 0.4 made, which carry no scope, with
 * what their account holds now: once a configuration, the isolate's or the
 * process's, before it checks its first credential (`SigninService.verify`),
 * so each keeps what it reached and nothing granted after reaches it. A row
 * 0.4 still makes while both run is sealed on its first use instead
 * (`sealCredentials`, from `verify` or an exchange). Returns how many rows
 * it sealed.
 */
export async function sealScopes(db: Database, chainKey: Buffer, vault: Vault): Promise<number> {
  const unsealed = await unsealedCredentials(db, new Date());
  let sealed = 0;
  for (const principal of new Set(unsealed.map((row) => row.principal))) {
    const access = await vault.access(principal);
    if (access.status !== 'active') continue;
    sealed += await sealCredentials(db, chainKey, access, unsealed.filter((candidate) => candidate.principal === principal));
  }
  return sealed;
}

/**
 * Seal these unsealed rows of one account with what it holds now, as
 * `access` answered, asked of the vault before: in one transaction, with a
 * `token.seal` entry naming those it sealed, so a row put back unsealed
 * later, and sealed again, shows in the log. Each update matches the row's
 * MAC as read, so two at once seal a row once. Returns how many it sealed.
 */
export async function sealCredentials(db: Database, chainKey: Buffer, access: Access, rows: readonly Unsealed[]): Promise<number> {
  const scope = storedScope(access.grants.map(({ projectId, environmentId, role }) => ({ projectId, environmentId, role })));
  return audited({ db, chainKey }, async (tx, log) => {
    const done = { tokens: [] as string[], bindings: [] as string[] };
    for (const row of rows) {
      const changed = row.kind === 'token'
        ? await updateAuth(tx, chainKey, credentials, { id: row.id, scope: null }, { scope })
        : await updateAuth(tx, chainKey, serviceBindings, { id: row.id, scope: null }, { scope });
      if (changed > 0) done[row.kind === 'token' ? 'tokens' : 'bindings'].push(row.id);
    }
    const count = done.tokens.length + done.bindings.length;
    if (count > 0) {
      log.push({
        actorType: 'system',
        actorId: 'app',
        action: 'token.seal',
        decision: 'allow',
        metadata: { principalType: 'service', principalId: memberOf(access.principal).id, ...done, scope: JSON.parse(scope) as unknown },
      });
    }
    return count;
  });
}
