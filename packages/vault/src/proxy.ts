import { covers, DEFAULT_POLICY, holds, inScope, issuedGrant, ownsProject, scopeDefinition, type Columns, type Holdings, type Permission, type Place, type RoleDefinition } from '@coffre/core/access';
import { CREDENTIAL_NAME } from '@coffre/core/identity';
import type { ProxyItemView, ProxyView } from '@coffre/core/vault';

import { placeIn, refuses, type Reader } from './decide.ts';
import { sealed, type EnvironmentInput, type FrozenHoldings, type ProxyInput, type ProxyItem, type ReservedInput, type SealKeys, type SecretInput } from './inputs.ts';

/**
 * The pure part of the proxy's decisions (0.16, T186;
 * docs/design/proxy-ui.md, sections 2 and 8): what a save freezes of its
 * editor, whether each key of an item clears for them, and what the tab is
 * shown. vault.ts reads the sealed objects these weigh, and logs.
 */

/** The most fork parents a lookup walks, as values inherit (`MAX_PARENTS`). */
export const MAX_PARENTS = 3;

/** The most names one `proxy.code` reserves at once: far more than any deployment's code defines. */
export const MAX_RESERVED = 1000;

/** A key of an item as the save resolved it: where it is held (nearest first), and its value's nature and project, a reference's source's. */
export type ResolvedKey = { name: string; holder: EnvironmentInput; nature: SecretInput['nature']; projectId: string };

/**
 * What a save freezes of its editor (decision 5): their instance role, its
 * scope and what it holds, and each live grant with what its role holds,
 * each as the policy defines it now (`FrozenHoldings`). A use weighs the
 * item's keys for these wherever the item serves, a fork made later
 * included, intersected with what its editor holds then (PR C).
 */
export function frozenHoldings(reader: Reader): FrozenHoldings {
  const { live } = reader;
  const policy = live.policy ?? DEFAULT_POLICY;
  const role = Object.hasOwn(policy.instanceRoles, live.role) ? policy.instanceRoles[live.role] : undefined;
  return {
    role: live.role,
    scope: live.scope,
    instance: { normal: [...(role?.permissions ?? [])], protected: [...(role?.protected ?? [])] },
    grants: live.grants.map((grant) => issuedGrant(grant, policy)),
  };
}

/**
 * Whether what a save froze holds `permission` at `place`, as `allows`
 * decides for a holder whose roles are what they were then: the instance
 * role inside its scope, and each grant that covers the place. `holder`
 * says whether the place is protected now, as the policy has it. A fork
 * made after the save is decided by the grants that reach it:
 *
 *   saved by Lin, router on market/dev      market/dev-eu: nothing
 *   saved by Ada, router on market          market/dev-eu: read, use
 */
export function frozenAllows(frozen: FrozenHoldings, permission: Permission, place: Place, holder: Pick<Holdings, 'policy' | 'service'>): boolean {
  const asRole = (columns: Columns): RoleDefinition => ({ name: '', description: '', permissions: columns.normal, protected: columns.protected });
  if (inScope(frozen.scope, place) && holds(asRole(frozen.instance), permission, place, holder)) return true;
  return frozen.grants.some((grant) => covers(grant, place) && holds(scopeDefinition(grant), permission, place, holder));
}

/** Whether what a save froze owns `projectId` (`ownsProject`): who alone routes its sensitive values (R66). Owner is a fixed role. */
export function frozenOwns(frozen: FrozenHoldings, projectId: string): boolean {
  return (frozen.role === 'owner' && inScope(frozen.scope, { projectId })) || frozen.grants.some((grant) => grant.role === 'owner' && covers(grant, { projectId }));
}

/**
 * Why `reader` may not route `key`, or null (section 8): read it where it is
 * held (a fork's parent for an inherited key, R8; a reference's holder, R20),
 * and, for a sensitive value, own its project, the source's for a reference
 * (R66, as R32 has it for service tokens). A deleted or archived holder
 * routes nothing.
 */
export function routeRefusal(reader: Reader, key: ResolvedKey, chain: readonly EnvironmentInput[]): string | null {
  const places = new Map(chain.map((environment) => [environment.id, environment]));
  const { holder } = key;
  const code = refuses(reader, 'secret.read', placeIn({ projectId: holder.projectId, environmentId: holder.id }, places), holder.deleted || holder.archived || holder.projectArchived);
  if (code !== null) return `${key.name}: its editor does not read it in ${holder.slug} (${code})`;
  if (key.nature === 'sensitive' && !ownsProject(reader.live, key.projectId)) return `${key.name} is sensitive: an Owner of its project may route sensitive keys`;
  return null;
}

/** Whether an item's save cleared it for its place's sensitive values: its editor owned the project. */
export function routesSensitive(holdings: FrozenHoldings, projectId: string): boolean {
  return frozenOwns(holdings, projectId);
}

/** An environment's sealed object as the tab shows it: each item without its holdings. */
export function proxyView(
  environment: { id: string; projectId: string },
  read: { object: ProxyInput | null; seal: Buffer | null; state: ProxyView['state'] },
  reserved: { object: ReservedInput | null; state: ProxyView['state'] },
): ProxyView {
  const items: ProxyItemView[] = read.state !== 'ok' || read.object === null ? [] : Object.values(read.object.items).map((item) => ({
    definition: item.definition,
    keys: [...item.keys],
    savedBy: item.savedBy,
    savedAt: item.savedAt,
    routesSensitive: routesSensitive(item.holdings, environment.projectId),
  }));
  return {
    environmentId: environment.id,
    seal: read.seal?.toString('base64') ?? null,
    state: read.state,
    items,
    reserved: reserved.state === 'ok' ? [...(reserved.object?.names ?? [])] : [],
    reservedState: reserved.state,
  };
}

/** Why the names a deployment's code reserves are no list of names, or null. */
export function reservedProblem(names: unknown): string | null {
  if (!Array.isArray(names) || names.length > MAX_RESERVED || names.some((name) => typeof name !== 'string' || !CREDENTIAL_NAME.test(name))) {
    return `the names code reserves are a list of at most ${MAX_RESERVED} credential names`;
  }
  return null;
}

/**
 * One level of a fork chain as a lookup reads it: its environment's proxy
 * row, if any (`readObject`: a row whose index column is not its items' has
 * no seal), the row's seal, and the seal of the object's newest change
 * (`undefined`: none ever).
 */
export type ProxyLevel = { environmentId: string; row: ProxyInput | null; seal: Buffer | null; newest: Buffer | null | undefined };

/**
 * The item a route's name serves at a place (docs/design/proxy-ui.md,
 * section 2; decision 6): the levels nearest first, the place, then each
 * fork parent, each checked in turn, its seal the vault's and its newest
 * change's, through the first whose sealed index names the route; none past
 * it is weighed. A level with no object (no change ever, no row) passes the
 * lookup on; one whose row a writer put back, deleted or planted is
 * `stale`, one whose items or index fail the seal `tampered`, and the
 * lookup stops there, never falling back to a parent: a fork's own item a
 * writer deleted from its row, its index left, fails the seal over the row,
 * and the parent's never serves in its place. `seals` lists the checked
 * levels' seals, nearest first, which an answer carries (`OneVersion`).
 */
export function proxyLookup(keys: SealKeys, levels: readonly ProxyLevel[], name: string):
  | { served: true; item: ProxyItem; level: number; seals: (Buffer | null)[] }
  | { served: false; fault: 'tampered' | 'stale' | null; seals: (Buffer | null)[] } {
  const seals: (Buffer | null)[] = [];
  for (const [level, { environmentId, row, seal, newest }] of levels.entries()) {
    if (newest === undefined || newest === null) {
      // No change ever: no object, unless a row was planted. A change that left none: no proxy change does.
      if (row !== null || newest === null) return { served: false, fault: 'stale', seals };
      seals.push(null);
      continue;
    }
    if (row === null) return { served: false, fault: 'stale', seals };
    if (!sealed(keys, { kind: 'proxy', id: environmentId }, row, seal)) return { served: false, fault: 'tampered', seals };
    if (seal === null || !newest.equals(seal)) return { served: false, fault: 'stale', seals };
    seals.push(seal);
    if (Object.hasOwn(row.items, name)) return { served: true, item: row.items[name]!, level, seals };
  }
  return { served: false, fault: null, seals };
}
