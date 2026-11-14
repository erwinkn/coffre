import { allows, EVERYWHERE, isCredentialScope, isInstanceRole, isScope, scopeWithReads, type CredentialScope, type Holdings, type Permission, type Policy, type RoleDefinition } from '@coffre/core/access';
import { addressWithin, checkConstraints, type BindingPolicy, type Constraints } from '@coffre/core/identity';
import { bindings, credentials, environments, grants, identities, policy, principals, roles } from '@coffre/db/schema';
import { parseScopes, type McpScope } from '@coffre/core/mcp';
import type { Called, SignedHead } from '@coffre/core/vault';
import { sql, type SQL } from 'drizzle-orm';

import { keep, part, readParts, type Denied, type Refusal, type Running, type Seen } from './change.ts';
import { checked, type Key, type Row, type Wire } from './rows.ts';
import { headText } from './signer.ts';
import type { Memory } from './use.ts';

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

/**
 * An MCP connection's access token, past its own row: the connection it is
 * under, which it stands with, the client's id and the scopes it holds,
 * those of its own row the connection still holds.
 */
export type Mcp = { connection: Row<typeof credentials>; client: string; scopes: McpScope[] };

export type Caller = {
  /** `user:<email>` or `token:<name>`. */
  principal: string;
  credential: Row<typeof credentials>;
  /** What they hold, as `@coffre/core/access` decides on it, with the roles and the protected environments of the rows read. */
  holds: Holdings & { policy: Policy };
  /** For a workload's session; null for any other credential. */
  workload: Workload | null;
  /** For an MCP connection's access token; null for any other credential. */
  mcp: Mcp | null;
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

/**
 * An MCP credential's client, as its row holds it (JSON: its id, host,
 * registration, redirect and scopes, as 0.14's connections were carried
 * over): its id, its redirect and its scopes, or undefined for one that
 * does not read as one.
 */
export function mcpClientOf(stored: string | null): { id: string; redirectUri: string; scopes: McpScope[] } | undefined {
  const client = parsed(stored);
  if (typeof client !== 'object' || client === null || Array.isArray(client)) return undefined;
  const { id, redirectUri, scopes } = client as Record<string, unknown>;
  if (typeof id !== 'string' || typeof redirectUri !== 'string' || typeof scopes !== 'string') return undefined;
  const read = parseScopes(scopes);
  return read.unknown.length > 0 ? undefined : { id, redirectUri, scopes: read.scopes };
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
  let mcp: Mcp | null = null;
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
    case 'mcp': {
      // An access token, an hour's, under the connection it was made for. The connection's own row holds its code, then
      // its refresh token: what the client redeems, never what it shows a request.
      if (issued) return null;
      const above = parsed(credential.ancestors);
      if (!Array.isArray(above) || above.length !== 1) return null;
      // It stands while its connection does: one ended, expired or of a member removed since ends every token under it, with no write of theirs.
      const connection = rows.ancestors.find((row) => row.id === above[0] && row.kind === 'mcp' && row.ancestors === null && row.challenge === null && row.principal === credential.principal
        && row.generation === credential.generation && row.revokedAt === null && row.frozenAt === null && row.expiresAt.getTime() > at);
      const own = mcpClientOf(credential.client);
      const held = connection && mcpClientOf(connection.client);
      if (own === undefined || held === undefined || own.id !== held.id) return null;
      mcp = { connection: connection!, client: own.id, scopes: own.scopes.filter((scope) => held.scopes.includes(scope)) };
      // All its person holds, as their session does: its scopes say what the client may ask, and the vault changes nothing on its word (`callerFrom`).
      credentialScope = null;
      break;
    }
    default:
      return null;
  }

  const projectOf = new Map(rows.environments.map((environment) => [environment.id, environment.projectId]));
  const definitions = (instance: boolean) =>
    Object.fromEntries(rows.roles.filter((role) => role.instance === instance).map((role): [string, RoleDefinition] => [role.id, { name: role.name, description: role.description, permissions: role.permissions as Permission[], protected: role.protected as Permission[] }]));
  const instanceRoles = definitions(true) as Policy['instanceRoles'];
  return {
    principal: principal.id,
    credential,
    workload,
    mcp,
    holds: {
      // A role with no row, or one whose row is not the vault's, is no role: they hold what a member does, and run nothing.
      role: !service && isInstanceRole(principal.role) && Object.hasOwn(instanceRoles, principal.role) ? principal.role : 'member',
      scope,
      // A grant on an environment names only it: its project is the environment's row's. One on a place this request is not about decides nothing here.
      grants: rows.grants
        // A removal moves the generation on: a grant made before it reaches nothing, though a writer hid it from the removal and put it back.
        .filter((grant) => grant.principal === principal.id && grant.generation === principal.generation && (grant.expiresAt === null || grant.expiresAt.getTime() > at))
        .map((grant) => ({ projectId: grant.projectId ?? projectOf.get(grant.environmentId!) ?? null, environmentId: grant.environmentId, role: grant.role })),
      credentialScope,
      // A role with no row is no role: the roles are the rows read, never the ones that ship.
      policy: { roles: definitions(false), instanceRoles, protected: rows.environments.filter((environment) => environment.protected).map((environment) => environment.id), protectedIn: {} },
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
 * set of ids: the entry names every row read, and an Owner's hundred
 * grants elsewhere decide nothing here. With them, the environments that
 * weigh on what they hold there: those the projects protect, and those a
 * grant of theirs is on. So no operation has to remember them, and one
 * protected or unprotected meanwhile starts the change over. `projects`
 * null is every project: all they hold, for `caller`, which decides no
 * change and writes no entry.
 */
export function callerParts(token: Buffer, projects: SQL | null) {
  const hash = sql`decode(${token.toString('hex')}, 'hex')`;
  const own = (column: string) => sql`(SELECT c.${sql.identifier(column)} FROM credentials c WHERE c.token_hash = ${hash})`;
  const here = projects === null ? sql`true` : sql`(g.project_id IN ${projects} OR g.environment_id IN (SELECT e.id FROM environments e WHERE e.project_id IN ${projects}))`;
  const within = projects === null ? sql`true` : sql`${environments.projectId} IN ${projects}`;
  return {
    credential: part(credentials, sql`${credentials.tokenHash} = ${hash}`),
    principal: part(principals, sql`${principals.id} = ${own('principal')}`),
    identity: part(identities, sql`${identities.id} = ${own('identity_id')}`),
    grant: part(grants, sql`${grants.id} IN (SELECT g.id FROM grants g WHERE g.principal = ${own('principal')} AND ${here})`),
    // The roles those grants name, and the member's own in the instance: a role with no row is no role.
    role: part(roles, sql`(NOT ${roles.instance} AND ${roles.id} IN (SELECT g.role FROM grants g WHERE g.principal = ${own('principal')} AND ${here})) OR (${roles.instance} AND ${roles.id} = (SELECT p.role FROM principals p WHERE p.id = ${own('principal')}))`),
    // A deleted environment protects nothing: its tombstone is left out.
    places: part(environments, sql`(${within} AND ${environments.protected} AND strpos(${environments.slug}, '~') = 0) OR ${environments.id} IN (SELECT g.environment_id FROM grants g WHERE g.principal = ${own('principal')} AND ${here})`),
    // What a trust binding issued names it, a narrowed session the sessions above it, and an MCP access token its connection: only what is shaped like ids is cast.
    binding: part(bindings, sql`${bindings.id} = (SELECT CASE WHEN c.created_by ~ '^binding:${ID}$' THEN substr(c.created_by, 9)::uuid END FROM credentials c WHERE c.token_hash = ${hash})`),
    ancestor: part(credentials, sql`${credentials.id} = ANY(ARRAY(SELECT above.id::uuid FROM credentials c, jsonb_array_elements_text(CASE WHEN c.kind IN ('workload', 'mcp') AND c.ancestors ~ '^[[]("${ID}"(,"${ID}")*)?[]]$' THEN c.ancestors::jsonb END) AS above(id) WHERE c.token_hash = ${hash}))`),
    policy: part(policy, sql`${own('kind')} = 'workload'`),
  };
}

/** Who asks a change: what they hold in the change's projects, whole, and `may` for one environment, by its row. */
export type Asking = Caller & { may(permission: Permission, environment: Row<typeof environments>): boolean };

/**
 * The caller a change's read found, as `callerOf` decides, holding what the
 * rows read say of the change's projects: each one's protected
 * environments, listed by project too, as a decision about a whole project
 * weighs them. A handle is the proxy's, for uses: it changes nothing,
 * whatever its scope says. Nor does an MCP connection: every change it
 * asks for waits for its person, who makes it on their own session
 * (docs/design/0.16.md, "MCP connections"), so the vault decides none on
 * its word, and weighs none.
 */
export function callerFrom(seen: Seen<ReturnType<typeof callerParts>>, shown: Shown, workloads: Workloads, at: number): Asking | null {
  const caller = standing(seen, shown, workloads, at);
  return caller?.mcp != null ? null : caller;
}

/** The caller as `callerFrom` has them, an MCP connection too: who a page's request is (`caller`). */
function standing(seen: Seen<ReturnType<typeof callerParts>>, shown: Shown, workloads: Workloads, at: number): Asking | null {
  const caller = callerOf({ credential: seen.credential, principal: seen.principal, identity: seen.identity, grants: seen.grant, roles: seen.role, environments: seen.places, binding: seen.binding, ancestors: seen.ancestor, policy: seen.policy }, shown, workloads, at);
  if (caller === null || caller.credential.kind === 'handle') return null;
  const protectedIn: Record<string, { environmentId: string; slug: string | null }[]> = {};
  // Archived, an environment still protects: it may be brought back. Only a deleted one's tombstone does not.
  for (const row of seen.places) if (row.protected && !row.slug.includes('~')) (protectedIn[row.projectId] ??= []).push({ environmentId: row.id, slug: row.slug });
  const holds = { ...caller.holds, policy: { ...caller.holds.policy, protectedIn } };
  return {
    ...caller,
    holds,
    // By the row itself too: an environment of a project the change did not name is as protected as it says.
    may: (permission, environment) =>
      allows(environment.protected ? { ...holds, policy: { ...holds.policy, protected: [...holds.policy.protected, environment.id] } } : holds, permission, { projectId: environment.projectId, environmentId: environment.id, environmentSlug: environment.slug }),
  };
}

/** A place's slug as the tables hold one: what a caller typed is logged only if it could be one. */
const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;

/**
 * What the log says of a change refused to a caller who stands (D236): who
 * asked, on which credential, what, and why not. `where` is the place as
 * the caller named it, each slug logged if it could be one and null
 * otherwise: the log takes no free text from a caller. `objects` are the
 * rows the read found of what was asked about, by which the entry is
 * found from their pages. Nothing for a caller who does not stand: an
 * unknown token is one answer, and no entry.
 */
export function refusedTo<S extends Seen<ReturnType<typeof callerParts>>>(
  action: string,
  shown: Shown & { request: string | null },
  workloads: Workloads,
  about: { where?: Record<string, string>; objects?(seen: S): string[] } = {},
) {
  return (seen: S, at: number, refusal: Refusal): Denied | null => {
    const caller = callerFrom(seen, shown, workloads, at);
    if (caller === null) return null;
    const where = Object.fromEntries(Object.entries(about.where ?? {}).map(([name, slug]) => [name, SLUG.test(slug) ? slug : null]));
    return {
      action,
      actor: caller.principal,
      credential: caller.credential.id,
      request: shown.request,
      ip: shown.ip,
      objects: [`principal:${caller.principal}`, `credential:${caller.credential.id}`, ...(about.objects?.(seen) ?? [])],
      detail: { ...where, refused: refusal.refused },
    };
  };
}

/** A credential's last use is moved on at most this often. */
const TOUCHED_MS = 5 * 60_000;

/**
 * When the credential was last used, and from where: its row's own
 * statement, since it shares one with nothing a change may lock. It only
 * says when, so it never costs the call: a row a change holds is skipped,
 * not waited for, a failure is dropped, and a later time is never put back.
 */
export async function touch(vault: Pick<Running, 'db'> & { memory: Memory }, credential: Row<typeof credentials>, ip: string | null, at: number): Promise<void> {
  const { touched } = vault.memory;
  if (Math.max(credential.lastUsedAt?.getTime() ?? -Infinity, touched.get(credential.id)?.at ?? -Infinity) + TOUCHED_MS > at) return;
  const when = sql`${new Date(at).toISOString()}::timestamptz`;
  const free = sql`SELECT id FROM credentials WHERE id = ${credential.id} AND (last_used_at IS NULL OR last_used_at < ${when}) FOR NO KEY UPDATE SKIP LOCKED`;
  await vault.db.execute(sql`UPDATE credentials SET last_used_at = ${when}, last_used_ip = ${ip} WHERE id IN (${free})`).then(() => keep(touched, credential.id, { at }, at - TOUCHED_MS), () => {});
}

/** The log's head as its row holds it, in the words its MAC covers (`headText`): what rides beside a caller's rows when a page asks. */
const HEAD = sql`
  SELECT jsonb_build_object('size', size, 'keptSize', kept_size, 'keptRoot', encode(kept_root, 'hex'), 'agingSize', aging_size, 'agingRoot', encode(aging_root, 'hex'),
    'agingFrom', aging_from, 'signedAt', CASE WHEN isfinite(signed_at) THEN round(extract(epoch FROM signed_at) * 1000)::bigint END, 'mac', encode(mac, 'hex')) AS row
  FROM log_head`;

/**
 * The head the vault signed, or null: no head yet, or a row whose MAC is
 * not the vault's, which vouches for nothing. A number too large to read
 * back whole fails the MAC like any other edit, and so does a date with no
 * number, `infinity`, read as null. The table's own columns give the row
 * its shape otherwise: none is null, and each is of its type.
 */
function headOf(keys: readonly Key[], wire: Wire | undefined): SignedHead | null {
  if (wire === undefined) return null;
  const { mac, ...head } = wire as Parameters<typeof headText>[0] & { mac: string };
  if (checked(keys, (key) => key.entries, headText(head), Buffer.from(mac, 'hex')) === undefined) return null;
  const { size, keptSize, keptRoot, agingSize, agingRoot, agingFrom, signedAt } = head;
  return { size, keptSize, keptRoot, agingSize, agingRoot, agingFrom, signedAt: new Date(signedAt).toISOString() };
}

/** A caller's rows as one read found them, and when: what `caller` remembers, under the token's hash. */
export type CallerRead = { at: number; seen: Seen<ReturnType<typeof callerParts>> };

/**
 * `caller` (docs/design/0.16.md, "Who a request is"): who a request's
 * credential is and all it holds, for the app to scope a page's queries
 * with. One read, of every project, remembered as a use's rows are and
 * decided on again at each call. It opens and changes nothing, and logs
 * nothing: a use and a change read their caller themselves.
 *
 * With `head`, the log's head rides in the same statement and comes back
 * with the answer once its MAC is held to the vault's keys: what the audit
 * page proves the entries it shows against, since the app holds no key and
 * the row is a writer's to edit. It is a head the vault signed, not
 * necessarily its last: a writer can put an older one back, and only the
 * signer, from its own copy, tells. Never from memory: the head moves at
 * each signing, and a remembered one would leave the newest entries past it.
 */
export async function caller(vault: Pick<Running, 'db' | 'keys' | 'now'> & { memory: Memory; workloads: Workloads }, shown: Shown & { token: Buffer; head?: boolean }): Promise<Called | Refusal> {
  const { memory } = vault;
  const key = shown.token.toString('hex');
  const now = vault.now();
  let found = memory.callers.get(key);
  let head: SignedHead | null | undefined;
  // Fresh only between its read and the memory's length after it: a clock set back makes nothing fresher.
  if (found !== undefined && !(now >= found.at && now < found.at + memory.seconds * 1000)) found = undefined;
  if (shown.head === true) {
    const read = await readParts(vault, callerParts(shown.token, null), { head: HEAD });
    found = { at: now, seen: read.seen };
    head = headOf(vault.keys, read.beside.head[0]);
  }
  found ??= { at: now, seen: (await readParts(vault, callerParts(shown.token, null))).seen };
  const at = vault.now();
  const asking = standing(found.seen, shown, vault.workloads, at);
  // A session that stands and is stopped is told why, as at a use; a narrowed one reaches no page.
  const refused = asking === null ? 'unauthenticated' : (asking.workload?.stop ?? (asking.workload?.narrowed === true ? 'narrowed' : null));
  if (asking === null || refused !== null) {
    // Not remembered: the next call reads again, and is given what has changed since.
    memory.callers.delete(key);
    return { refused: refused! };
  }
  // An access token's use is its connection's, which Connected apps lists: the token is gone within the hour.
  await touch(vault, asking.mcp?.connection ?? asking.credential, shown.ip, at);
  // Unless a newer read of the same is there already: a slow call does not put its older rows back over it.
  if (memory.seconds > 0 && !((memory.callers.get(key)?.at ?? -Infinity) > found.at)) keep(memory.callers, key, found, at - memory.seconds * 1000);
  const { id, kind, expiresAt } = asking.credential;
  const mcp = asking.mcp === null ? {} : { connection: asking.mcp.connection.id, scopes: asking.mcp.scopes };
  return { principal: asking.principal, credential: { id, kind, expiresAt: expiresAt.toISOString(), ...mcp }, holds: asking.holds, ...(head === undefined ? {} : { head }) };
}
