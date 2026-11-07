import { covers, DEFAULT_POLICY, holds, inScope, issuedGrant, ownsProject, scopeDefinition, type Columns, type Holdings, type Permission, type Place, type RoleDefinition } from '@coffre/core/access';
import { CREDENTIAL_NAME } from '@coffre/core/identity';
import type { ProxyItemView, ProxyView } from '@coffre/core/vault';

import { placeIn, readerOf, refuses, type Reader } from './decide.ts';
import {
  indexBytes, itemDigest, parseIndex, sealed, sealedIndex,
  type CredentialInput, type EnvironmentInput, type FrozenHoldings, type PrincipalInput, type ProxyInput, type ProxyItem, type ReservedInput, type RolesInput, type SealKeys, type SecretInput,
} from './inputs.ts';

/**
 * The pure part of the proxy's decisions (0.16, T186;
 * docs/design/proxy-ui.md, sections 2 and 8): what a save freezes of its
 * editor, whether each key of an item clears for them, and what the tab is
 * shown. vault.ts reads the sealed objects these weigh, and logs.
 */

/** The most names one `proxy.code` reserves at once: far more than any deployment's code defines. */
export const MAX_RESERVED = 1000;

/** A key of an item as the save resolved it: where it is held (nearest first), which decides it (R71), and its value's nature, a reference's source's. */
export type ResolvedKey = { name: string; holder: EnvironmentInput; nature: SecretInput['nature'] };

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
 * and, for a sensitive value, own the project it is held in, a reference's
 * holder's as any key's there (R66, R71, as R32 has it for service tokens).
 * A deleted or archived holder routes nothing.
 */
export function routeRefusal(reader: Reader, key: ResolvedKey, chain: readonly EnvironmentInput[]): string | null {
  const places = new Map(chain.map((environment) => [environment.id, environment]));
  const { holder } = key;
  const code = refuses(reader, 'secret.read', placeIn({ projectId: holder.projectId, environmentId: holder.id }, places), holder.deleted || holder.archived || holder.projectArchived);
  if (code !== null) return `${key.name}: its editor does not read it in ${holder.slug} (${code})`;
  if (key.nature === 'sensitive' && !ownsProject(reader.live, holder.projectId)) return `${key.name} is sensitive: an Owner of its project may route sensitive keys`;
  return null;
}


/**
 * Why an item would not route now (decision 5), or null: each of its keys,
 * resolved where a use finds it, must clear both for what its save froze of
 * its editor and for that editor as they stand now, as a use decides them
 * (section 8), key by key (`editorRefusal`, the use's own rule). The tab marks such an item `route_not_cleared`, naming the
 * key, until someone who reads its keys saves it again. A key the place does
 * not hold is decided at each use, and marks nothing here.
 *
 *   Lin saved openai; she is demoted to Viewer   ->  { key: 'OPENAI_API_KEY', reason: 'OPENAI_API_KEY: its editor does not read it in dev (no_grant)' }
 */
export function notCleared(item: ProxyItem, editor: Reader, keys: ReadonlyMap<string, ResolvedKey>, chain: readonly EnvironmentInput[]): NonNullable<ProxyItemView['notCleared']> | null {
  for (const name of item.keys) {
    const key = keys.get(name);
    if (key === undefined) continue;
    const reason = editorRefusal(item.holdings, editor, key, chain);
    if (reason !== null) return { key: name, reason };
  }
  return null;
}

/** An environment's sealed object as the tab shows it: each item without its holdings, with its clearance mark (`notCleared`) where `marks` says. */
export function proxyView(
  environment: { id: string; projectId: string },
  read: { object: ProxyInput | null; seal: Buffer | null; state: ProxyView['state'] },
  reserved: { object: ReservedInput | null; state: ProxyView['state'] },
  marks: ReadonlyMap<string, ProxyItemView['notCleared']> | null = null,
): ProxyView {
  const items: ProxyItemView[] = read.state !== 'ok' || read.object === null ? [] : Object.values(read.object.items).map((item) => ({
    definition: item.definition,
    keys: [...item.keys],
    savedBy: item.savedBy,
    savedAt: item.savedAt,
    // Its save cleared it for its place's sensitive values: its editor owned the project.
    routesSensitive: frozenOwns(item.holdings, environment.projectId),
    ...(marks === null ? {} : { notCleared: marks.get(item.definition.name) ?? null }),
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

/**
 * One level of a fork chain as a route use's statement reads it (0058's `use_route`; docs/design/proxy-ui.md, section
 * 2): whether its environment has a proxy row, the route's item in it (or, for every item, the row's items whole), the
 * row's index (`digests`) and seal, and the seal of the object's newest change (`undefined`: none ever).
 */
export type RouteLevel = { environmentId: string; row: boolean; item: unknown; digests: Buffer | null; seal: Buffer | null; newest: Buffer | null | undefined };

/** A level's fault, or a route that no level serves (`fault` null): the use reads nothing of it. */
export type RouteFault = 'tampered' | 'stale' | null;

/**
 * The item a route's name serves, as a use reads it: each level nearest first, its index checked against its seal and
 * its seal against its object's newest change, through the first whose sealed index names the route, whose item must
 * hash to that entry (`proxyLookup`'s rules, on the route's item and the index alone, never every item). A level with no
 * object passes the lookup on; one whose row a writer put back, deleted or planted is `stale`; one whose index fails its
 * seal, whose sealed entry's item is missing or does not hash to it, or whose row holds an item its index lacks, is
 * `tampered`, and the lookup stops there, never serving a parent's in its place. `seals`, the checked levels', nearest
 * first, base64, `''` for a level with no object: what every round of one use must read again (`OneVersion`).
 *
 *   market/dev-eu, no row; market/dev's `openai` sealed        served at level 1, seals ['', <dev's>]
 *   market/dev-eu's `openai` deleted from its row, index left   tampered: never dev's
 */
export function routeLookup(keys: SealKeys, levels: readonly RouteLevel[], name: string):
  | { served: true; item: ProxyItem; digest: Buffer; level: number; seals: string[] }
  | { served: false; fault: RouteFault; seals: string[] } {
  const seals: string[] = [];
  for (const [level, { environmentId, row, item, digests, seal, newest }] of levels.entries()) {
    if (newest === undefined) {
      // No change ever: no object, unless a row was planted.
      if (row) return { served: false, fault: 'stale', seals };
      seals.push('');
      continue;
    }
    if (!row || newest === null) return { served: false, fault: 'stale', seals };
    const index = digests === null ? null : parseIndex(digests);
    if (index === null || !sealedIndex(keys, environmentId, index, seal)) return { served: false, fault: 'tampered', seals };
    if (!seal!.equals(newest)) return { served: false, fault: 'stale', seals };
    seals.push(seal!.toString('base64'));
    const entry = index.find(([named]) => named === name);
    if (entry === undefined) {
      // An item the sealed index does not name: planted.
      if (item !== null && item !== undefined) return { served: false, fault: 'tampered', seals };
      continue;
    }
    if (item === null || item === undefined || typeof item !== 'object' || Array.isArray(item)) return { served: false, fault: 'tampered', seals };
    const read = item as ProxyItem;
    if (!itemDigest(read).equals(entry[1])) return { served: false, fault: 'tampered', seals };
    return { served: true, item: read, digest: entry[1], level, seals };
  }
  return { served: false, fault: null, seals };
}

/**
 * Every item a place serves, as `proxyItem` with no name answers them (the plan's call; docs/design/proxy-ui.md,
 * section 6): each level's row whole, nearest first, checked as `proxyLookup` checks a level, and each name served by
 * the nearest level that holds it. One level that fails fails the whole answer (the plan answers 503): one forged item
 * among 256 is enough to send the app a value through it.
 */
export function proxyServing(keys: SealKeys, levels: readonly RouteLevel[]):
  | { ok: true; items: { name: string; level: number; item: ProxyItem; digest: Buffer }[]; seals: string[] }
  | { ok: false; fault: 'tampered' | 'stale'; seals: string[] } {
  const seals: string[] = [];
  const served = new Map<string, { name: string; level: number; item: ProxyItem; digest: Buffer }>();
  for (const [level, { environmentId, row, item, digests, seal, newest }] of levels.entries()) {
    if (newest === undefined) {
      if (row) return { ok: false, fault: 'stale', seals };
      seals.push('');
      continue;
    }
    if (!row || newest === null) return { ok: false, fault: 'stale', seals };
    const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
    if (!isRecord(item) || !Object.values(item).every(isRecord)) return { ok: false, fault: 'tampered', seals };
    const items = item as Record<string, ProxyItem>;
    // The row's index column must be its items' index, and the seal the vault's over it.
    if (digests === null || !indexBytes(items).equals(digests) || !sealed(keys, { kind: 'proxy', id: environmentId }, { kind: 'proxy', id: environmentId, items }, seal)) {
      return { ok: false, fault: 'tampered', seals };
    }
    if (!seal!.equals(newest)) return { ok: false, fault: 'stale', seals };
    seals.push(seal!.toString('base64'));
    for (const [name, one] of Object.entries(items)) if (!served.has(name)) served.set(name, { name, level, item: one, digest: itemDigest(one) });
  }
  return { ok: true, items: [...served.values()].sort((a, b) => (a.name < b.name ? -1 : 1)), seals };
}

/**
 * Why a route's editor may not route `key` at a use, or null (decision 5(b); formal/Routing.tla, ClearanceAtUse,
 * EditorStillHolds): both what their save froze (`frozenAllows`, `frozenOwns`, the place protected or not as the policy
 * is now) and what they hold now (`routeRefusal`, as the save weighed them) must read it where it is held, and, for a
 * sensitive value, own its project. So a role widened since the save widens nothing, and an editor demoted or removed
 * since routes nothing they no longer read:
 *
 *   Lin, router on market/dev when she saved, a Viewer now        route_not_cleared
 *   Lin saved as a Developer, an Owner now, the key sensitive since  route_not_cleared: her save froze no ownership
 */
export function editorRefusal(frozen: FrozenHoldings, now: Reader, key: ResolvedKey, chain: readonly EnvironmentInput[]): string | null {
  const current = routeRefusal(now, key, chain);
  if (current !== null) return current;
  const places = new Map(chain.map((environment) => [environment.id, environment]));
  const { holder } = key;
  const place = placeIn({ projectId: holder.projectId, environmentId: holder.id }, places);
  if (!frozenAllows(frozen, 'secret.read', place, { policy: now.live.policy, service: false })) return `${key.name}: what its editor held when they saved it does not read it in ${holder.slug}`;
  if (key.nature === 'sensitive' && !frozenOwns(frozen, holder.projectId)) return `${key.name} is sensitive, and its editor was no Owner of its project when they saved it`;
  return null;
}

/**
 * The second decision of a route use's key (decision 5(b)): for the item's editor, as their save froze them and as they
 * stand now (`editor`, their principal as the use read it, its seals checked; `roles`, the instance's), at the key as
 * the use read it (`view`: the key, a reference's source, the places it weighed). The same function decides it live
 * (use.ts) and replayed (log-replay.ts), on the same rows (R53). Null: allowed; else why not, naming the key.
 */
export function routeEditorRefusal(
  item: ProxyItem, editor: PrincipalInput | null, roles: RolesInput,
  view: { secret: { row: SecretInput | null }; source: { row: SecretInput | null } | null; environments: ReadonlyMap<string, { row: EnvironmentInput | null }> }, at: number, name: string,
): string | null {
  const credential: CredentialInput = { kind: 'credential', id: item.savedBy, principal: item.savedBy, caller: 'person', scope: null, expiresAt: null, revoked: false, generation: editor?.generation ?? 0 };
  const chain = [...view.environments.values()].flatMap((read) => (read.row === null ? [] : [read.row]));
  const secret = view.secret.row;
  const value = secret === null ? null : secret.source === null ? secret : view.source?.row ?? null;
  const holder = secret === null ? undefined : view.environments.get(secret.environmentId)?.row ?? undefined;
  if (secret === null || value === null || holder === undefined) return `${name}: not held where the route serves it`;
  const reader = readerOf(editor, credential, roles, chain, at);
  return editorRefusal(item.holdings, reader, { name, holder, nature: value.nature }, chain);
}
