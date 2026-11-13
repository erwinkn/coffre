import { allows, EVERYWHERE, isCredentialScope, isInstanceRole, isScope, scopeWithReads, type CredentialScope, type Holdings, type Permission, type Policy, type RoleDefinition } from '@coffre/core/access';
import { addressWithin, checkConstraints, type BindingPolicy, type Constraints } from '@coffre/core/identity';
import { bindings, credentials, environments, grants, identities, policy, principals, roles } from '@coffre/db/schema';
import { sql, type SQL } from 'drizzle-orm';

import { part, type Seen } from './change.ts';
import type { Row } from './rows.ts';

/**
 * Who is asking (docs/design/0.16.md, "A use"): from a credential's rows,
 * each under the vault's MAC, to what its holder may do now. One function
 * of the rows, what the request showed and the time, for a use and for a
 * change alike.
 */

/** A caller's rows, as one read found them. A row whose MAC is not the vault's is not among them. */
export type CallerRows = {
  credential: readonly Row<typeof credentials>[];
  principal: readonly Row<typeof principals>[];
  identity: readonly Row<typeof identities>[];
  grants: readonly Row<typeof grants>[];
  roles: readonly Row<typeof roles>[];
  /** The environments the request is about: a grant on one names it alone, and a protected one says so in its row. */
  environments: readonly Row<typeof environments>[];
  /** The trust binding that issued the credential, for one a binding issued. */
  binding: readonly Row<typeof bindings>[];
  /** A workload's session's: the sessions it was narrowed from, and the instance's policy, which says whether every workload is frozen. */
  ancestors: readonly Row<typeof credentials>[];
  policy: readonly Row<typeof policy>[];
};

/** What a request shows beyond its token, which only the app sees. */
export type Shown = {
  /**
   * The thumbprint of the key that signed this request's proof (RFC 9449),
   * once the app has held the proof to the request: its signature, method,
   * URL, token and content. Null for a request with none.
   */
  proof: string | null;
  /** The address it came from. */
  ip: string | null;
};

/** What the deployment says of workloads (docs/design/workload-access.md, section 6.3): null, it takes none. */
export type Workloads = {
  /** No binding may list values its sessions are handed back. */
  noReads: boolean;
  /** A service account is a key-bound session or nothing: no service token, kept or exchanged. */
  useOnly: boolean;
} | null;

/**
 * Why a workload's session that stands does nothing now, as its SDK reads
 * it. None of them ends the session: an approval, a move back inside the
 * binding's sources or a lifted freeze restores service with no new proof,
 * which matters where the proof is an enrollment code, spent.
 */
export type Stop = 'pending' | 'no_reads' | 'source' | 'frozen';

/** A workload's session, past its token and key. */
export type Workload = {
  binding: Row<typeof bindings>;
  policy: BindingPolicy;
  /** A session `narrow` made from another, or one with limits: it uses values within them and is handed none. */
  narrowed: boolean;
  constraints: Constraints | null;
  /** What stops it, the first of them in the order 0.14 answered: null, it serves. */
  stop: Stop | null;
};

export type Caller = {
  /** `user:<email>` or `token:<name>`. */
  principal: string;
  credential: Row<typeof credentials>;
  /** What they hold, as `@coffre/core/access` decides on it, with the roles and the protected environments of the rows read. */
  holds: Holdings & { policy: Policy };
  /** For a workload's session; null for any other credential. */
  workload: Workload | null;
};

/** What a trust binding issued says so in `created_by`: `binding:<id>`, under the row's MAC. */
const ISSUED = 'binding:';
/** `narrow` goes four deep (docs/design/workload-access.md, section 8.4). */
const MAX_ANCESTORS = 4;

function parsed(json: string | null): unknown {
  if (json === null) return null;
  try {
    return JSON.parse(json);
  } catch {
    return undefined;
  }
}

/** A token's cap: one that does not read as a scope reaches nothing. */
function capOf(stored: string | null): CredentialScope {
  const cap = parsed(stored);
  return isCredentialScope(cap) ? cap : [];
}

/**
 * A workload's session past its own row and its member's: the key, the
 * binding's policy, the sessions it was narrowed from, and what stops it.
 * Null for one that does not stand.
 */
function sessionOf(rows: CallerRows, session: Row<typeof credentials>, binding: Row<typeof bindings>, shown: Shown, workloads: NonNullable<Workloads>, at: number): Workload | null {
  const live = (row: Row<typeof credentials>) => row.kind === 'workload' && row.revokedAt === null && row.expiresAt.getTime() > at && row.notAfter !== null && row.notAfter.getTime() > at;
  // The key before anything that tells one live session from another: a token without its key learns nothing more.
  if (!live(session) || session.jkt === null || shown.proof !== session.jkt) return null;
  const policy = parsed(binding.policy);
  if (typeof policy !== 'object' || policy === null || Array.isArray(policy)) return null;
  const says = policy as BindingPolicy;

  // A `narrow` child stands while every session above it does.
  const ids = session.ancestors === null ? [] : parsed(session.ancestors);
  if (!Array.isArray(ids) || ids.length > MAX_ANCESTORS) return null;
  const lineage = ids.map((id: unknown) => rows.ancestors.find((row) => row.id === id && row.principal === session.principal && live(row)));
  if (lineage.includes(undefined)) return null;
  let constraints: Constraints | null = null;
  try {
    if (session.constraints !== null) constraints = checkConstraints(JSON.parse(session.constraints));
  } catch {
    return null;
  }

  const [instance] = rows.policy;
  // Each freeze is a field of the row it stops. An instance whose policy row is gone cannot say it is not frozen.
  const frozen = instance?.workloadsFrozenAt !== null || rows.principal.some((row) => row.frozenAt !== null) || binding.frozenAt !== null || session.frozenAt !== null || lineage.some((row) => row!.frozenAt !== null);
  const stop = says.approve === true && session.approvedAt === null ? 'pending'
    : workloads.noReads && says.reads !== undefined ? 'no_reads'
    : says.sources !== undefined && (shown.ip === null || !addressWithin(shown.ip, says.sources)) ? 'source'
    : frozen ? 'frozen' : null;
  return { binding, policy: says, narrowed: ids.length > 0 || constraints !== null, constraints, stop };
}

/**
 * The caller, or null: no such credential, one expired or revoked, one of
 * a member removed since it was issued, of an account since unlinked, or
 * of a binding since removed; a workload's session without its key. One
 * answer for all of these, so that none says which.
 */
export function callerOf(rows: CallerRows, shown: Shown, workloads: Workloads, at: number): Caller | null {
  const [credential] = rows.credential;
  const [principal] = rows.principal;
  if (credential === undefined || principal === undefined) return null;
  if (credential.revokedAt !== null || credential.expiresAt.getTime() <= at) return null;
  // Only a workload's session is frozen and thawed, which stops it and keeps it (`Stop`). On any other credential a freeze has no lift, so it ends it.
  if (credential.frozenAt !== null && credential.kind !== 'workload') return null;
  // A removal moves the generation on: everything issued before it is dead, whatever its own row says.
  if (principal.id !== credential.principal || principal.status !== 'active' || principal.generation !== credential.generation) return null;
  // A browser's session is an account's, always; any credential that names an account goes with it.
  if (credential.identityId === null ? credential.kind === 'browser' : !rows.identity.some((identity) => identity.id === credential.identityId && identity.revokedAt === null)) return null;

  const service = principal.id.startsWith('token:');
  const scope = principal.scope === null ? EVERYWHERE : parsed(principal.scope);
  if (!isScope(scope)) return null;

  // What a trust binding issued, a CI run's token or a workload's session, stands while the binding does, in the generation it was bound in.
  const issued = credential.createdBy.startsWith(ISSUED);
  const binding = issued ? rows.binding.find((row) => row.id === credential.createdBy.slice(ISSUED.length) && row.revokedAt === null && row.principal === principal.id && row.generation === credential.generation) : undefined;
  // What the credential reaches at most: nothing past it. A session's carries no cap, and holds all its member does.
  let credentialScope: CredentialScope | null;
  let workload: Workload | null = null;
  switch (credential.kind) {
    case 'browser':
    case 'cli':
      if (issued) return null;
      credentialScope = null;
      break;
    case 'personal':
    case 'handle':
      if (issued) return null;
      credentialScope = capOf(credential.scope);
      break;
    case 'service':
      // A token a CI run exchanged its ID token for reaches what its binding does, a binding with no policy: one with a policy makes sessions.
      if (workloads?.useOnly === true || (issued && (binding === undefined || binding.policy !== null))) return null;
      credentialScope = capOf(binding === undefined ? credential.scope : binding.scope);
      break;
    case 'workload': {
      if (workloads === null || binding === undefined) return null;
      workload = sessionOf(rows, credential, binding, shown, workloads, at);
      if (workload === null) return null;
      // Its own scope, an enrollment code's, or else its binding's, with the binding's `reads` on the environments they list.
      // A binding is made with a grant of its own at each environment it lists, so its scope says each one's project.
      const cap = capOf(credential.scope ?? binding.scope);
      const listed = new Map(cap.flatMap((grant): [string, string][] => (grant.environmentId != null && grant.projectId !== null ? [[grant.environmentId, grant.projectId]] : [])));
      credentialScope = scopeWithReads(cap, workload.policy.reads, listed);
      break;
    }
    // An MCP connection's requests come with an access token, which has no row: not built yet.
    default:
      return null;
  }

  const projectOf = new Map(rows.environments.map((environment) => [environment.id, environment.projectId]));
  const definitions = (instance: boolean) =>
    Object.fromEntries(rows.roles.filter((role) => role.instance === instance).map((role): [string, RoleDefinition] => [role.id, { name: role.name, description: role.description, permissions: role.permissions as Permission[], protected: role.protected as Permission[] }]));
  return {
    principal: principal.id,
    credential,
    workload,
    holds: {
      role: !service && isInstanceRole(principal.role) ? principal.role : 'member',
      scope,
      // A grant on an environment names only it: its project is the environment's row's. One on a place this request is not about decides nothing here.
      grants: rows.grants
        .filter((grant) => grant.principal === principal.id && (grant.expiresAt === null || grant.expiresAt.getTime() > at))
        .map((grant) => ({ projectId: grant.projectId ?? projectOf.get(grant.environmentId!) ?? null, environmentId: grant.environmentId, role: grant.role })),
      credentialScope,
      // A role with no row is no role: the roles are the rows read, never the ones that ship.
      policy: { roles: definitions(false), instanceRoles: definitions(true) as Policy['instanceRoles'], protected: rows.environments.filter((environment) => environment.protected).map((environment) => environment.id), protectedIn: {} },
      service,
      kind: workload !== null ? 'workload' : service ? 'bearer' : 'person',
    },
  };
}

/** A UUID as the vault writes one, for a statement to tell before it casts: a row is read before its MAC is checked. */
export const ID = sql.raw('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}');

/** A place that is there: not archived, and not the tombstone a deletion leaves. */
export const live = (row: { slug: string; archivedAt: Date | null }) => row.archivedAt === null && !row.slug.includes('~');

/**
 * The caller's rows as a change reads them, by the token's hash: what a
 * use reads in its one statement (use.ts). Of their grants and roles, only
 * those that bear on the projects the change is about, given as SQL for a
 * set of ids (`NO_PROJECT` for a change of the instance's own): the entry
 * names every row read, and an Owner's hundred grants elsewhere decide
 * nothing here.
 */
export function callerParts(token: Buffer, projects: SQL) {
  const hash = sql`decode(${token.toString('hex')}, 'hex')`;
  const own = (column: string) => sql`(SELECT c.${sql.identifier(column)} FROM credentials c WHERE c.token_hash = ${hash})`;
  const here = sql`(g.project_id IN ${projects} OR g.environment_id IN (SELECT e.id FROM environments e WHERE e.project_id IN ${projects}))`;
  return {
    credential: part(credentials, sql`${credentials.tokenHash} = ${hash}`),
    principal: part(principals, sql`${principals.id} = ${own('principal')}`),
    identity: part(identities, sql`${identities.id} = ${own('identity_id')}`),
    grant: part(grants, sql`${grants.id} IN (SELECT g.id FROM grants g WHERE g.principal = ${own('principal')} AND ${here})`),
    // The roles those grants name, and the member's own in the instance: a role with no row is no role.
    role: part(roles, sql`(NOT ${roles.instance} AND ${roles.id} IN (SELECT g.role FROM grants g WHERE g.principal = ${own('principal')} AND ${here})) OR (${roles.instance} AND ${roles.id} = (SELECT p.role FROM principals p WHERE p.id = ${own('principal')}))`),
    // What a trust binding issued names it, and a narrowed session the sessions above it: only what is shaped like ids is cast.
    binding: part(bindings, sql`${bindings.id} = (SELECT CASE WHEN c.created_by ~ '^binding:${ID}$' THEN substr(c.created_by, 9)::uuid END FROM credentials c WHERE c.token_hash = ${hash})`),
    ancestor: part(credentials, sql`${credentials.id} = ANY(ARRAY(SELECT above.id::uuid FROM credentials c, jsonb_array_elements_text(CASE WHEN c.kind = 'workload' AND c.ancestors ~ '^[[]("${ID}"(,"${ID}")*)?[]]$' THEN c.ancestors::jsonb END) AS above(id) WHERE c.token_hash = ${hash}))`),
    policy: part(policy, sql`${own('kind')} = 'workload'`),
  };
}

/** The projects of a change that is about none: a member's role, the instance's policy. */
export const NO_PROJECT = sql`(SELECT NULL::uuid WHERE false)`;

/**
 * Who asks a change. What they hold is weighed with the rows of the
 * environments it is asked about, never without: a row says whether its
 * environment is protected, and which project a grant on it is in. `may`
 * asks about one environment, by its row. `holding` is for a decision
 * about a whole project: given every environment of it, since one left out
 * counts as unprotected.
 */
export type Asking = Omit<Caller, 'holds'> & {
  /** What they hold, among these environments. */
  holding(rows: readonly Row<typeof environments>[]): Holdings;
  /** Whether they hold `permission` in this environment. */
  may(permission: Permission, environment: Row<typeof environments>): boolean;
};

/**
 * The caller a change's read found, as `callerOf` decides. A handle is the
 * proxy's, for uses: it changes nothing, whatever its scope says.
 */
export function callerFrom(seen: Seen<ReturnType<typeof callerParts>>, shown: Shown, workloads: Workloads, at: number): Asking | null {
  const caller = callerOf({ credential: seen.credential, principal: seen.principal, identity: seen.identity, grants: seen.grant, roles: seen.role, environments: [], binding: seen.binding, ancestors: seen.ancestor, policy: seen.policy }, shown, workloads, at);
  if (caller === null || caller.credential.kind === 'handle') return null;
  const { holds, ...who } = caller;
  const holding = (rows: readonly Row<typeof environments>[]): Holdings => {
    const guarded = rows.filter((row) => row.protected);
    const within: Record<string, { environmentId: string; slug: string | null }[]> = {};
    for (const row of guarded) (within[row.projectId] ??= []).push({ environmentId: row.id, slug: row.slug });
    return {
      ...holds,
      // A grant on an environment names only it: its project is the row's.
      grants: holds.grants.map((grant) => (grant.projectId === null ? { ...grant, projectId: rows.find((row) => row.id === grant.environmentId)?.projectId ?? null } : grant)),
      policy: { ...holds.policy, protected: guarded.map((row) => row.id), protectedIn: within },
    };
  };
  return { ...who, holding, may: (permission, environment) => allows(holding([environment]), permission, { projectId: environment.projectId, environmentId: environment.id, environmentSlug: environment.slug }) };
}
