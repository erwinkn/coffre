import {
  DEFAULT_POLICY,
  definitionProblem,
  EVERY_ENVIRONMENT,
  EVERYWHERE,
  grantKind,
  INSTANCE_ROLES,
  isInstanceRole,
  isScope,
  ROLES,
  UNWRITTEN_FORK_MS,
  type InstanceRole,
  type Policy,
  type Role,
  type RoleDefinition,
  type Scope,
} from './access.ts';
import { accessRevision, type Access, type Grant, type Settings } from './vault.ts';

// What the vault answers about a principal, the policy and its settings,
// from the rows that hold them: the vault, once it has checked each row by
// its MAC, and the app, which holds no key of the vault's and checks none,
// for what it only shows (`GET /api/me`). One rule for both, so the two
// answers agree whenever the rows are the vault's.

/** A member: `user:<email>` or `token:<name>`. */
export const PRINCIPAL = /^(user|token):[^\s:][^\s]*$/;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A member's row, as `vault_members` holds it, its instance role and scope read (`storedRole` in @coffre/db/grants). */
export type MemberFacts = {
  status: 'active' | 'removed';
  role: InstanceRole;
  scope: Scope;
  generation: number;
  /** Milliseconds since the epoch. */
  statusChangedAt: number;
  statusChangedBy: string;
};

/** A grant, as `vault_grants` holds it, its environment's project filled in; times in milliseconds since the epoch. */
export type GrantFacts = {
  projectId: string | null;
  environmentId: string | null;
  role: string;
  expiresAt: number | null;
  grantedAt: number;
  grantedBy: string;
};

/**
 * What `access` answers about `principal`, from their row and their
 * grants, lapsed ones too, as of `at`; `tampered` when a row failed the
 * vault's check, which only the vault can tell.
 */
export function answerFrom(principal: string, row: MemberFacts | undefined, held: readonly GrantFacts[], at: number, tampered: boolean, policy: Policy): Access {
  const active = PRINCIPAL.test(principal) && !tampered && row?.status === 'active';
  const access: Access = {
    principal,
    status: tampered ? 'tampered' : !PRINCIPAL.test(principal) ? 'unknown' : (row?.status ?? 'unknown'),
    generation: row?.generation ?? 0,
    ...(active ? roleOf(principal, row) : { role: 'member', scope: EVERYWHERE }),
    grants: active ? held.filter((grant) => live(grant, at) && grantKind(grant) !== null).map(view) : [],
    since: row ? iso(row.statusChangedAt) : null,
    by: row?.statusChangedBy ?? null,
    policy,
  };
  return { ...access, revision: accessRevision(access) };
}

/** A member's instance role, as their row has it: service accounts are members, whatever a row says. */
export function roleOf(principal: string, row: Pick<MemberFacts, 'role' | 'scope'>): { role: InstanceRole; scope: Scope } {
  return principal.startsWith('user:') ? { role: row.role, scope: row.scope } : { role: 'member', scope: EVERYWHERE };
}

/** Whether a grant still holds at `at`. */
export function live(grant: { expiresAt: number | null }, at: number): boolean {
  return grant.expiresAt === null || grant.expiresAt > at;
}

/** A grant as `access` answers it. */
export function view(grant: GrantFacts): Grant {
  return {
    projectId: grant.projectId,
    environmentId: grant.environmentId,
    role: grant.role as Role,
    expiresAt: grant.expiresAt === null ? null : iso(grant.expiresAt),
    grantedAt: iso(grant.grantedAt),
    grantedBy: grant.grantedBy,
  };
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

// --- the policy -------------------------------------------------------------------

/**
 * What a `policy.change` entry keeps: the roles an Owner edited or made,
 * each whole, and the protected environments. A role as it ships is kept by
 * none, so a release that changes a default changes it where nobody edited it.
 */
export type PolicyEdits = { roles: Record<string, RoleDefinition>; instanceRoles: Partial<Record<InstanceRole, RoleDefinition>>; protected: ProtectedPlace[] };

/**
 * A protected environment, with its project's id, what a grant on the whole
 * project reaches of it, and when it was protected, by the vault's clock:
 * an id with no row ten minutes later is a fork that was never written.
 */
export type ProtectedPlace = { projectId: string; environmentId: string; at: number };

export const NO_EDITS: PolicyEdits = { roles: {}, instanceRoles: {}, protected: [] };

/** A role holding nothing, which every role but Owner is under the closed policy. */
const NOTHING_HELD = (definition: RoleDefinition): RoleDefinition => ({ ...definition, permissions: [], protected: [] });

/**
 * The policy when the log has some, but none the vault wrote within reach:
 * whoever inserted rows may have hidden an Owner's narrowing, so no role
 * holds anything, a service account's neither, but Owner, which holds
 * everything always and so may write the policy again.
 */
export const CLOSED_POLICY: Policy = {
  roles: Object.fromEntries(Object.entries(ROLES).map(([id, definition]) => [id, id === 'owner' ? definition : NOTHING_HELD(definition)])),
  instanceRoles: Object.fromEntries(Object.entries(INSTANCE_ROLES).map(([id, definition]) => [id, id === 'owner' ? definition : NOTHING_HELD(definition)])) as Policy['instanceRoles'],
  protected: [EVERY_ENVIRONMENT],
  protectedIn: {},
};

/** An environment a policy names, as the policy reads it. */
export type PolicyEnvironment = { slug: string; deleted: boolean };

/**
 * The policy the newest `policy.change` says, from its metadata, as of
 * `at`, with the rows of the environments it protects: none for no entry,
 * the roles as they ship; and closed for one whose edits do not hold.
 */
export function policyFrom(metadata: string | null, rows: ReadonlyMap<string, PolicyEnvironment>, at: number): { policy: Policy; edits: PolicyEdits; readable: boolean } {
  if (metadata === null) return { policy: DEFAULT_POLICY, edits: NO_EDITS, readable: true };
  let stored: unknown;
  try {
    stored = JSON.parse(metadata);
  } catch {}
  const edits = typeof stored === 'object' && stored !== null ? readEdits(stored as { policy?: unknown }) : null;
  if (edits === null) return { policy: CLOSED_POLICY, edits: NO_EDITS, readable: false };
  return { policy: livePolicy(rows, edits, at), edits, readable: true };
}

/** A policy entry's edits, checked as the vault wrote them, or null for any that does not hold. */
export function readEdits(stored: { policy?: unknown }): PolicyEdits | null {
  const edits = stored.policy as Partial<PolicyEdits> | undefined;
  if (typeof edits !== 'object' || edits === null) return null;
  const { roles, instanceRoles, protected: protectedIds } = edits;
  if (typeof roles !== 'object' || roles === null || typeof instanceRoles !== 'object' || instanceRoles === null || !Array.isArray(protectedIds)) return null;
  const defined = (table: object) => Object.values(table).every((definition) => definitionProblem(definition as RoleDefinition) === null);
  if (!defined(roles) || !defined(instanceRoles) || Object.keys(instanceRoles).some((role) => !isInstanceRole(role))) return null;
  if (protectedIds.some((place) => typeof place !== 'object' || place === null || !UUID.test((place as ProtectedPlace).projectId) || !UUID.test((place as ProtectedPlace).environmentId)
    || !Number.isSafeInteger((place as ProtectedPlace).at))) return null;
  return { roles: roles as Record<string, RoleDefinition>, instanceRoles: instanceRoles as PolicyEdits['instanceRoles'], protected: protectedIds as ProtectedPlace[] };
}

/**
 * The policy `edits` say as of `at`: the roles as they ship, each edited
 * one replaced and each made one added; and the protected environments, but
 * for those deleted since, the project around one's included: a deleted
 * prod protects nothing, and holds nobody back from giving a service
 * account a role on all of its project (`givesService`). A fork's id with
 * no row yet stays, protected before it is written, ten minutes: one with
 * none after that is a fork refused or abandoned, never written. Each
 * keeps its slug, which a scoped instance role's filters read. The edits
 * keep them all: no write is needed.
 */
export function livePolicy(rows: ReadonlyMap<string, PolicyEnvironment>, edits: PolicyEdits, at: number): Policy {
  const live = edits.protected.filter((place) => {
    const row = rows.get(place.environmentId);
    return row === undefined ? at - place.at < UNWRITTEN_FORK_MS : !row.deleted;
  });
  const slugOf = (place: ProtectedPlace) => rows.get(place.environmentId)?.slug ?? null;
  return {
    roles: { ...ROLES, ...edits.roles },
    instanceRoles: { ...INSTANCE_ROLES, ...edits.instanceRoles },
    protected: live.map((place) => place.environmentId),
    protectedIn: live.reduce<Record<string, { environmentId: string; slug: string | null }[]>>(
      (byProject, place) => ({ ...byProject, [place.projectId]: [...(byProject[place.projectId] ?? []), { environmentId: place.environmentId, slug: slugOf(place) }] }),
      {},
    ),
  };
}

// --- the settings -----------------------------------------------------------------

/** The settings before anyone changed them: people set up service accounts anywhere they hold access. */
export const DEFAULT_SETTINGS: Settings = { serviceAccounts: EVERYWHERE };

/** The settings when the log has some, but none the vault wrote within reach: people set up no service accounts. */
export const CLOSED_SETTINGS: Settings = { serviceAccounts: { projects: { only: [] }, environments: 'all' } };

/** The settings the newest `settings.change` says, from its metadata: none for no entry, the default; closed for one that does not hold. */
export function settingsFrom(metadata: string | null): Settings {
  if (metadata === null) return DEFAULT_SETTINGS;
  let stored: unknown;
  try {
    stored = JSON.parse(metadata);
  } catch {}
  const serviceAccounts = typeof stored === 'object' && stored !== null ? (stored as { serviceAccounts?: unknown }).serviceAccounts : undefined;
  return isScope(serviceAccounts) ? { serviceAccounts } : CLOSED_SETTINGS;
}
