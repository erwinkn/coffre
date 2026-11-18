import { isScope, managesService, runsInstance, type Permission, type Place, type RoleDefinition, type Scope, type ScopeGrant, type ServiceAccount } from '@coffre/core/access';
import { environments, grants, policy, principals, projects, roles } from '@coffre/db/schema';
import { sql, type SQL } from 'drizzle-orm';

import type { Asking, callerParts } from '../caller.ts';
import { part, type Seen, type Unsealed } from '../change.ts';
import type { Row, Wire } from '../rows.ts';
import { NOWHERE } from './asking.ts';

/**
 * Who sets up and manages a service account, as the rows a change reads
 * say (`setsUpServices`, `givesService`, `managesService`): the changes of
 * members and grants (`access.ts`) and of credentials (`signin.ts`) weigh
 * them the same way.
 */

/**
 * On a session: a credential with a scope holds nothing of the instance's
 * own, and what it did here (end another credential, link or unlink an
 * account, make a token) would outlive it or reach past it. Only a person
 * has a session: a service account's credentials always have a scope.
 */
export const onSession = (caller: Asking) => caller.holds.credentialScope == null;

/** Whether the caller runs the instance (`runsInstance`): an instance role with no row is none (`callerOf`). */
export const runs = (caller: Asking) => runsInstance(caller.holds);

/**
 * A service account: by its id, or as SQL that selects it, a binding's or a
 * session's member, which the read finds with the row that names it.
 */
export type ServiceIn = string | SQL | null;

/** `member` if it names a service account, or selects one, else null. */
export const serviceNamed = (member: ServiceIn) => (typeof member === 'string' ? (member.startsWith('token:') ? member : null) : member);

/** The projects a service account's grants are on, as SQL for `callerParts`: what the caller holds there says whether they manage it. */
export function projectsOf(member: ServiceIn) {
  const service = serviceNamed(member);
  return service === null ? NOWHERE : sql`(SELECT coalesce(g.project_id, e.project_id) FROM grants g LEFT JOIN environments e ON e.id = g.environment_id WHERE g.principal = ${service})`;
}

/**
 * What says who manages a service account (`managesService`): its row, its
 * grants, the places they are on and the roles they name, and the
 * instance's setting of where people set service accounts up. Nothing for
 * a member that is none.
 */
export function serviceParts(member: ServiceIn) {
  const service = serviceNamed(member);
  const of = (where: (id: string | SQL) => SQL) => (service === null ? sql`false` : where(service));
  return {
    account: part(principals, of((id) => sql`${principals.id} = ${id}`)),
    held: part(grants, of((id) => sql`${grants.principal} = ${id}`)),
    heldIn: part(projects, of((id) => sql`${projects.id} IN (SELECT g.project_id FROM grants g WHERE g.principal = ${id})`)),
    heldAt: part(environments, of((id) => sql`${environments.id} IN (SELECT g.environment_id FROM grants g WHERE g.principal = ${id})`)),
    // The roles its grants name: what the caller must hold of each is the role's row, and a role with no row is no role.
    heldAs: part(roles, of((id) => sql`NOT ${roles.instance} AND ${roles.id} IN (SELECT g.role FROM grants g WHERE g.principal = ${id})`)),
    // Every environment of the projects it holds something in, whatever its row says: the caller's read takes those that say they are protected, and one whose flag was edited behind the vault would leave it unseen.
    beside: part(environments, service === null ? sql`false` : sql`${environments.projectId} IN ${projectsOf(service)}`),
    setting: part(policy, service === null ? sql`false` : sql`${policy.onlyRow}`),
  };
}

export type ServiceSeen = Seen<ReturnType<typeof serviceParts>>;

/**
 * A service account as `managesService` weighs it, from the rows read: its
 * live grants, each on a place that is there (one on a deleted place
 * reaches nothing, and is left out, as 0.14 left it out), and who admitted
 * it last, as 0.14 said it (`status_changed_by`). Null for one that is not
 * an active service account, or with a grant on a place the read did not
 * find: a row missing makes it no one's to manage but whoever runs the
 * instance.
 */
export function serviceOf(seen: ServiceSeen, member: string, at: number): ServiceAccount | null {
  const row = seen.account.find((other) => other.id === member);
  if (row === undefined || row.status !== 'active') return null;
  const held: { role: string; place: Place }[] = [];
  for (const grant of seen.held) {
    if (grant.generation !== row.generation || (grant.expiresAt !== null && grant.expiresAt.getTime() <= at)) continue;
    if (grant.environmentId !== null) {
      const there = seen.heldAt.find((environment) => environment.id === grant.environmentId);
      if (there === undefined) return null;
      if (!there.slug.includes('~')) held.push({ role: grant.role, place: { projectId: there.projectId, environmentId: there.id, environmentSlug: there.slug } });
    } else {
      const there = seen.heldIn.find((project) => project.id === grant.projectId);
      if (there === undefined) return null;
      if (!there.slug.includes('~')) held.push({ role: grant.role, place: { projectId: there.id } });
    }
  }
  return { grants: held, admittedBy: row.statusChangedBy };
}

/** The instance's setting of where people set service accounts up, from its row: none without the row, or with one that does not read as a scope. */
export function settingOf(seen: Pick<ServiceSeen, 'setting'>): Scope | null {
  const [row] = seen.setting;
  if (row === undefined) return null;
  try {
    const setting: unknown = JSON.parse(row.serviceAccounts);
    return isScope(setting) ? setting : null;
  } catch {
    return null;
  }
}

/**
 * Whether the caller, on a session, manages the service account `member`:
 * whoever runs the instance; else a person who holds everything it holds,
 * where the instance's setting lets people set service accounts up, or who
 * admitted it while it holds nothing (`managesService`). `tampered` when
 * that would rest on a row written behind the vault: a grant of the
 * service's is one less it holds, and an environment of its projects may
 * be protected, where the caller holds less. Either would let them manage
 * it more easily. A row deleted for the decision is not found this way (see
 * `credentialEnd`).
 */
export function manages(caller: Asking, seen: ServiceSeen, unsealed: Unsealed<ReturnType<typeof serviceParts> & ReturnType<typeof callerParts>>, member: string, at: number): boolean | 'tampered' {
  if (runs(caller)) return true;
  // A credential with a scope manages no service, as 0.14.7 gave a non-person no setting (`serviceSettingFor`): a
  // service's token that holds `grant.manage` would make another's tokens, or a new one of its own past its revocation.
  if (!onSession(caller)) return false;
  if (unsealed.held + unsealed.places + unsealed.beside > 0) return 'tampered';
  return managesSealed(caller, seen, member, at);
}

/**
 * Whether the caller manages the service account `member` by the rows the
 * vault wrote alone, as `manages` weighs them: a row written behind it is
 * left out, which only lets them manage it more easily. So one who does not
 * by these rows does not at all, and is told no more; one who does is
 * refused `tampered` by the change while such a row is there.
 */
export function managesSealed(caller: Asking, seen: ServiceSeen, member: string, at: number): boolean {
  if (runs(caller)) return true;
  if (!onSession(caller)) return false;
  const account = serviceOf(seen, member, at);
  const setting = settingOf(seen);
  if (account === null || setting === null) return false;
  // What its grants' roles hold, from their rows, beside the caller's own.
  const { holds } = caller;
  const named = Object.fromEntries(seen.heldAs.filter((row) => !row.instance).map((row): [string, RoleDefinition] => [row.id, { name: row.name, description: row.description, permissions: row.permissions as Permission[], protected: row.protected as Permission[] }]));
  return managesService({ ...holds, policy: { ...holds.policy, roles: { ...named, ...holds.policy.roles } } }, setting, caller.principal, account);
}

/** The roles of a project's grants a read found, by id: a role with no row is no role. */
export const definitionsOf = (rows: readonly Row<typeof roles>[]) =>
  Object.fromEntries(rows.filter((row) => !row.instance).map((row): [string, RoleDefinition] => [row.id, { name: row.name, description: row.description, permissions: row.permissions as Permission[], protected: row.protected as Permission[] }]));

/** Where a fork inherits from, three deep, as a use reads it (use.ts). */
export const MAX_PARENTS = 3;

/**
 * What rides beside the read of a service's token or binding (R32,
 * `Operation.beside`): each environment of `projects` but personal
 * configs, which no service reads, that holds a sensitive value now, and
 * the projects whose Owners give those values: its own, for one of its
 * keys, a reference held there (whose source's project gave only its
 * making) and, for a fork, what it inherits from its parents. No decision
 * goes by it, only what the answer tells
 * (`withheldOf`). Read by the projects' and environments' keys, a few
 * rows: one per environment.
 */
export const sensitiveIn = (projects: SQL): SQL => sql`WITH RECURSIVE lineage (environment, project, at, depth) AS (
    SELECT e.id, e.project_id, e.id, 0 FROM environments e WHERE e.project_id IN ${projects} AND e.owner IS NULL AND strpos(e.slug, '~') = 0
    UNION ALL SELECT l.environment, l.project, e.parent_id, l.depth + 1 FROM lineage l JOIN environments e ON e.id = l.at WHERE e.parent_id IS NOT NULL AND l.depth < ${MAX_PARENTS}
  )
  SELECT jsonb_build_object('environment', l.environment, 'project', l.project, 'from', jsonb_agg(DISTINCT s.project_id)) AS row
  FROM lineage l JOIN secrets s ON s.project_id = l.project AND s.environment_id = l.at AND s.archived_at IS NULL LEFT JOIN secrets src ON src.id = s.source_id
  WHERE (s.source_id IS NULL AND s.nature = 'sensitive') OR src.nature = 'sensitive'
  GROUP BY l.environment, l.project`;

/**
 * The places of a service's scope, by path, whose sensitive values it
 * will not read (`withheld`, R32): those where what `sensitiveIn` found
 * holds one of a project of which it reads none, no Owner of it having
 * issued it (`ownsProject`). A project's, in any of its environments.
 * 0.14.7's `withheldIn`. What rode beside the read carries no MAC: a row
 * written behind the vault changes what the answer tells, never what the
 * credential reads.
 */
export function withheldOf(scope: readonly { grant: ScopeGrant; path: string }[], found: readonly Wire[] | undefined): string[] {
  const owned = new Set(scope.flatMap(({ grant }) => (grant.sensitive === true ? [grant.projectId] : [])));
  const held = (found ?? []).filter((row) => !(Array.isArray(row.from) && row.from.every((project) => owned.has(project as string))));
  return scope
    .filter(({ grant }) => held.some((row) => (grant.environmentId === null ? row.project === grant.projectId : row.environment === grant.environmentId)))
    .map(({ path }) => path)
    .sort();
}
