import type { AccessValue } from '@coffre/client';
import type { Role } from '@coffre/core/access';

import type { GrantRow } from '../shared/models';

/** Read or write on one environment, and when it ends: an ISO instant, or null for never. */
export type EnvironmentAccess = { role: Extract<Role, 'viewer' | 'developer'>; expiresAt: string | null };

/**
 * What one project is set to in a principal's access editor: nothing, owner,
 * read or write everywhere, or read or write per environment. Every grant the
 * plan asks for carries its own expiry.
 *
 * `custom` is for grants that do not fit that shape -- an auditor grant, or
 * read everywhere plus write on one environment. The editor shows them and
 * leaves them alone unless another setting is picked.
 */
export type AccessPlan = {
  level: 'none' | Extract<Role, 'owner' | 'viewer' | 'developer'> | 'env' | 'custom';
  /** When the project-wide level ends. */
  expiresAt: string | null;
  /** Environments without an entry get no access. */
  environments: Record<string, EnvironmentAccess>;
};

export type HeldGrant = Pick<
  GrantRow,
  'id' | 'role' | 'roleName' | 'environmentSlug' | 'expiresAt'
>;

export type AccessChange =
  | { kind: 'create'; role: string; environmentSlug: string | null; expiresAt: string | null }
  | { kind: 'expiry'; grant: HeldGrant; expiresAt: string | null }
  | { kind: 'revoke'; grant: HeldGrant };

/** An environment's access in a plan; slugs like `constructor` are not inherited. */
export function environmentAccess(plan: AccessPlan, slug: string): EnvironmentAccess | null {
  return Object.hasOwn(plan.environments, slug) ? plan.environments[slug] : null;
}

/**
 * Read what a principal holds on a project back into the editor's terms.
 * `environments` are the ones the editor can set: live, and not archived.
 */
export function planFromGrants(
  grants: readonly HeldGrant[],
  environments: readonly string[],
): AccessPlan {
  if (grants.length === 0) return { level: 'none', expiresAt: null, environments: {} };

  const [only] = grants;
  if (
    grants.length === 1 &&
    only.environmentSlug === null &&
    (only.role === 'owner' || only.role === 'viewer' || only.role === 'developer')
  ) {
    return { level: only.role, expiresAt: only.expiresAt, environments: {} };
  }

  const perEnvironment: Record<string, EnvironmentAccess> = {};
  for (const grant of grants) {
    const slug = grant.environmentSlug;
    if (
      slug === null ||
      !environments.includes(slug) ||
      Object.hasOwn(perEnvironment, slug) ||
      (grant.role !== 'viewer' && grant.role !== 'developer')
    ) {
      return { level: 'custom', expiresAt: null, environments: {} };
    }
    perEnvironment[slug] = { role: grant.role, expiresAt: grant.expiresAt };
  }
  return { level: 'env', expiresAt: null, environments: perEnvironment };
}

/**
 * Switch a plan's level. Going from read or write everywhere to per
 * environment starts every environment at that level and expiry, so the
 * switch alone keeps the same reach.
 */
export function withLevel(
  plan: AccessPlan,
  level: AccessPlan['level'],
  environments: readonly string[],
): AccessPlan {
  if (
    level === 'env' &&
    (plan.level === 'viewer' || plan.level === 'developer') &&
    Object.keys(plan.environments).length === 0
  ) {
    const access = { role: plan.level, expiresAt: plan.expiresAt };
    return {
      ...plan,
      level,
      environments: Object.fromEntries(environments.map((slug) => [slug, access])),
    };
  }
  return { ...plan, level };
}

/** Set one environment's access, or take it away with `null`. */
export function withEnvironment(
  plan: AccessPlan,
  slug: string,
  access: EnvironmentAccess | null,
): AccessPlan {
  const environments = { ...plan.environments };
  if (access === null) delete environments[slug];
  else environments[slug] = access;
  return { ...plan, environments };
}

function grantsFor(
  plan: AccessPlan,
): { role: string; environmentSlug: string | null; expiresAt: string | null }[] {
  switch (plan.level) {
    case 'none':
    case 'custom':
      return [];
    case 'owner':
    case 'viewer':
    case 'developer':
      return [{ role: plan.level, environmentSlug: null, expiresAt: plan.expiresAt }];
    case 'env':
      return Object.entries(plan.environments).map(([environmentSlug, access]) => ({
        environmentSlug,
        ...access,
      }));
  }
}

/** The server and the date field spell the same instant differently. */
function sameExpiry(a: string | null, b: string | null): boolean {
  return a === b || (a !== null && b !== null && Date.parse(a) === Date.parse(b));
}

/**
 * The changes that take what is held to the plan: grants to create, grants
 * whose expiry moves, and grants to revoke, in that order. Asking for what is
 * already held yields nothing, so applying the same plan twice is a no-op.
 */
export function accessChanges(grants: readonly HeldGrant[], plan: AccessPlan): AccessChange[] {
  if (plan.level === 'custom') return [];

  const key = (grant: { role: string; environmentSlug: string | null }) =>
    `${grant.role}@${grant.environmentSlug ?? ''}`;
  const wanted = new Map(grantsFor(plan).map((grant) => [key(grant), grant]));
  const held = new Map(grants.map((grant) => [key(grant), grant]));

  const changes: AccessChange[] = [];
  for (const [id, grant] of wanted) {
    if (!held.has(id)) changes.push({ kind: 'create', ...grant });
  }
  for (const [id, grant] of held) {
    const want = wanted.get(id);
    if (want !== undefined && !sameExpiry(grant.expiresAt, want.expiresAt)) {
      changes.push({ kind: 'expiry', grant, expiresAt: want.expiresAt });
    }
  }
  for (const [id, grant] of held) {
    if (!wanted.has(id)) changes.push({ kind: 'revoke', grant });
  }
  return changes;
}

/**
 * The changes as the API's access patch for one project: each place it
 * touches, and the role to hold there until when, or `null` for none.
 *
 *   { "market": null, "market/dev": { "role": "developer", "until": "2026-12-31T23:59:59.000Z" } }
 *
 * A place holds one role, so where a level changes, the revoke of the old
 * role and the create of the new land on the same place, and the new role
 * wins: the server replaces one with the other, never passing through none.
 */
export function accessPatch(project: string, changes: readonly AccessChange[]): Record<string, AccessValue> {
  const place = (environmentSlug: string | null) =>
    environmentSlug === null ? project : `${project}/${environmentSlug}`;
  const holding = (role: string, expiresAt: string | null): AccessValue =>
    expiresAt === null ? (role as Role) : { role: role as Role, until: expiresAt };

  const patch: Record<string, AccessValue> = {};
  for (const change of changes) {
    if (change.kind === 'revoke') patch[place(change.grant.environmentSlug)] = null;
  }
  for (const change of changes) {
    if (change.kind === 'expiry') patch[place(change.grant.environmentSlug)] = holding(change.grant.role, change.expiresAt);
    if (change.kind === 'create') patch[place(change.environmentSlug)] = holding(change.role, change.expiresAt);
  }
  return patch;
}

/** A date field's value as the instant access ends: the close of that day, UTC. */
export function expiryFromDate(date: string): string | null {
  return date === '' ? null : new Date(`${date}T23:59:59Z`).toISOString();
}

/** A date field's value for an expiry. Expiries are shown as UTC dates everywhere. */
export function dateFromExpiry(expiresAt: string | null): string {
  return expiresAt === null ? '' : expiresAt.slice(0, 10);
}
