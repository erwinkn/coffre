/**
 * Who sees which entries of the log: `GET /api/audit` (`listAudit`), its
 * filter built in JS and read in SQL, held to an independent model on
 * random worlds, logs and queries, on the engine the suite runs on.
 *
 * The rule, from the docs:
 *
 * - Whoever reads the whole log, `audit.read` by an instance role in both
 *   its columns whose scope is written `all`, on no credential, reads
 *   every entry (docs/design/instance-roles.md, "Reading the whole log";
 *   docs/design/roles.md, section 3).
 * - Anyone else reads the entries about the places they hold `audit.read`
 *   at, and nothing about no place (instance-roles.md). A personal config's
 *   log is its parent's (`can` in src/api/caller.ts).
 * - An entry about a reference or a fork names the place on its other side
 *   (`also`), and is in the logs of both: "An auditor of either project
 *   sees it" (docs/design/environments.md, "The log, in both projects").
 * - But a project's log leaves out each protected environment its reader's
 *   role leaves out (docs/design/roles.md, section 7), and an entry that
 *   names such a place on either side is left out with it (`auditWhere`,
 *   and roles.test.ts: "nor one that names prod besides"). A place is left
 *   out so only for a reader of its project: anyone else reads it or not
 *   as any place, by the rule above.
 * - A path filters to its place's log: the entries naming it on either
 *   side, and for a secret, the reads of several that list it, read there
 *   or through it as a holder (`readsByPlace` in the vault).
 *
 * Entries go into the real log through the app's writer, so the chain
 * stays valid; their places are rows of their own, which the log names by
 * id. Callers are built as the vault would answer for them (`callerFrom`):
 * people with instance roles, scopes and grants, a person's personal
 * token, and a service account's credential.
 */
import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';
import { randomUUID } from 'node:crypto';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';
import type { Access } from '@coffre/core/vault';

import { propertySettings } from '../../../scripts/property-settings.ts';
import {
  ROLES,
  grants as grantsIn, policy as policyOf, scope as scopeOf, world as worldOf,
  type Columns, type Environment, type Filter, type Grant, type InstanceRole, type Policy, type Scope, type World,
} from '../../../scripts/properties/domain.ts';
import { DETAIL_ACTIONS, listAudit, type AuditQuery } from '../src/api/audit.ts';
import { callerFrom, type Caller } from '../src/api/caller.ts';
import type { ApiContext } from '../src/api/context.ts';
import { ApiError } from '../src/api/errors.ts';
import { appendAudit, type AuditEntry } from '../src/db/audit.ts';
import { resetDatabase } from './api-fixture.ts';
import { emptyLog, openTestDatabase } from './db/engine.ts';
import { environments as storedEnvironments, projects as storedProjects, secrets as storedSecrets } from './db/tables.ts';

const settings = propertySettings(150, 10);
let database: Awaited<ReturnType<typeof openTestDatabase>>;
before(async () => {
  database = await openTestDatabase();
  // Whatever a file before this one left in a shared database: each case then clears only what it writes.
  await resetDatabase(database.owner);
});
after(async () => { await database.close(); });

/** One side of an entry: the place it is about, or the other side of a reference or a fork (`also`). */
type Side = { projectId: string | null; environmentId: string | null; secretId: string | null };
type Listed = { secretId: string; also?: { secretId: string } };
type Entry = { actor: string; action: string; decision: 'allow' | 'deny'; main: Side | null; also: Side | null; secrets: Listed[] | null };

/** Who asks: a person signed in, a person's personal token, or a service account's credential. */
type Who = {
  kind: 'person' | 'token' | 'service';
  principal: string;
  role: InstanceRole;
  scope: Scope;
  grants: Grant[];
  /** The credential's scope, each grant with the columns it kept when issued; null for a session. */
  credential: { grant: Grant; columns: Columns }[] | null;
};

type Query = { path: { project: string; environment?: string; key?: string } | null; actor: string | null; decision: 'allow' | 'deny' | null; detail: boolean; limit: number };

const NORMAL_ACTIONS = ['secret.read', 'secret.write', 'secret.reference', 'environment.create', 'access.change'] as const;
const PLACE_DETAILS = ['key.wrap', 'reference.create', 'mcp.read'] as const;
const INSTANCE_ACTIONS = ['sign_in', 'member.add', 'settings.change', 'token.create'] as const;
const ACTORS = ['user:ada@acme.example', 'user:bo@acme.example', 'token:ci', 'system:coffre-scheduler', 'system:ci'] as const;
const ASKED_ACTORS = ['user:ada@acme.example', 'user:ADA@acme.example', 'token:ci', 'coffre-scheduler', 'ci', 'bo@acme.example'] as const;
const DETAIL = new Set<string>(DETAIL_ACTIONS);
const NO_SECRET = '00000000-0000-4000-8000-00000000dead';

/** A personal config's own slug, as the app makes one (`dev-p-3f9c2a1b`), never shown: `dev@me` names it to its owner. */
const storedSlug = (environment: Environment, parentSlug: string | undefined) =>
  environment.owner === null ? environment.slug : `${parentSlug}-p-${environment.owner.slice('user:'.length, environment.owner.indexOf('@'))}`;

const instance = gs.composite((tc) => {
  const world = tc.draw(worldOf({ maxProjects: 2, maxEnvironments: 4, maxSecrets: 6 }));
  const environments = world.projects.flatMap((project) => project.environments);
  const drawn = tc.draw(policyOf(environments.map((environment) => environment.id)));
  // A role that reads the log but a protected environment's, as an Owner may make one: what leaves a place out of a project's log.
  const policy = { ...drawn, roles: { ...drawn.roles, 'log-reader': { permissions: ['audit.read'], protected: [] } } } as Policy;
  // Archived places are still places: their log is read as any other's.
  const archived = new Set([...world.projects.map((project) => project.id), ...environments.map((environment) => environment.id)]
    .filter(() => tc.draw(gs.integers({ minValue: 0, maxValue: 5 })) === 0));
  return { world, policy, archived };
});
type Instance = { world: World; policy: Policy; archived: Set<string> };

/** An entry about no place, a project, an environment, a secret, or several secrets read at one place; and maybe what is on its other side. */
function entry(world: World) {
  const environments = world.projects.flatMap((project) => project.environments);
  const secretIds = world.secrets.map((secret) => secret.id);
  const place = gs.composite((tc): Side => {
    const environment = tc.draw(gs.sampledFrom(environments));
    const held = world.secrets.filter((secret) => secret.environmentId === environment.id);
    const secret = held.length > 0 && tc.draw(gs.booleans()) ? tc.draw(gs.sampledFrom(held)).id : null;
    return { projectId: environment.projectId, environmentId: environment.id, secretId: secret };
  });
  return gs.composite((tc): Entry => {
    const actor = tc.draw(gs.sampledFrom(ACTORS));
    const decision = tc.draw(gs.sampledFrom(['allow', 'deny'] as const));
    const shape = tc.draw(gs.sampledFrom(['none', 'project', 'place', 'several'] as const));
    if (shape === 'none') return { actor, action: tc.draw(gs.sampledFrom(INSTANCE_ACTIONS)), decision, main: null, also: null, secrets: null };
    let main: Side;
    let secrets: Listed[] | null = null;
    let action: string = tc.draw(gs.sampledFrom([...NORMAL_ACTIONS, ...PLACE_DETAILS]));
    if (shape === 'project') {
      main = { projectId: tc.draw(gs.sampledFrom(world.projects)).id, environmentId: null, secretId: null };
    } else if (shape === 'place') {
      main = tc.draw(place);
    } else {
      // A read of several at one place: no secret of its own, each listed with its holder when read through a reference.
      main = { ...tc.draw(place), secretId: null };
      action = tc.draw(gs.sampledFrom(['secret.read', 'secret.read', 'secret.write']));
      const listed = gs.composite((inner): Listed => {
        // Now and then a version that names no secret there is, as a refused `bad_claim` lists it.
        const secretId = inner.draw(gs.sampledFrom([...secretIds, NO_SECRET]));
        const holder = inner.draw(gs.optional(gs.sampledFrom([...secretIds, NO_SECRET])));
        return holder === null ? { secretId } : { secretId, also: { secretId: holder } };
      });
      secrets = tc.draw(gs.arrays(listed, { minSize: 2, maxSize: 3 }));
    }
    // The other side: a reference's, anywhere; or a fork's, which names only the environment, in the same project.
    const kind = tc.draw(gs.sampledFrom(['none', 'reference', 'fork'] as const));
    let also: Side | null = null;
    if (kind === 'reference') also = tc.draw(place);
    if (kind === 'fork') {
      const siblings = environments.filter((environment) => environment.projectId === main.projectId);
      also = { projectId: null, environmentId: tc.draw(gs.sampledFrom(siblings)).id, secretId: null };
    }
    return { actor, action, decision, main, also, secrets };
  });
}

/** Who asks, in this instance. */
function who({ world, policy }: Instance) {
  // Grants that read the log, on top of what the world drew: most roles read none of it.
  const auditing = Object.fromEntries(Object.entries(policy.roles).filter(([, columns]) => columns.permissions.includes('audit.read')));
  const more = (held: readonly Grant[], roles: Record<string, Columns>) => gs.composite((tc) => {
    if (Object.keys(roles).length === 0 || tc.draw(gs.integers({ minValue: 0, maxValue: 3 })) === 0) return [...held];
    const extra = tc.draw(grantsIn(world.projects, roles, 3));
    const place = (grant: Grant) => `${grant.projectId}/${grant.environmentId ?? ''}`;
    return [...held.filter((grant) => !extra.some((other) => place(other) === place(grant))), ...extra];
  });
  const scoped = (held: readonly Grant[]) => gs.composite((tc) =>
    held.filter(() => tc.draw(gs.integers({ minValue: 0, maxValue: 3 })) > 0).map((grant) => ({ grant, columns: tc.draw(issued(policy, grant.role)) })));
  return gs.composite((tc): Who => {
    const kind = tc.draw(gs.sampledFrom(['person', 'person', 'token', 'service'] as const));
    if (kind === 'service') {
      const account = tc.draw(gs.sampledFrom(world.services));
      const grants = tc.draw(more(account.grants, auditing));
      // A service signs in only on a credential: a part of what its account holds, as its role was then or is now.
      return { kind, principal: account.principal, role: 'member', scope: { projects: 'all', environments: 'all' }, grants, credential: tc.draw(scoped(grants)) };
    }
    const person = tc.draw(gs.sampledFrom(world.people));
    const grants = tc.draw(more(person.grants, auditing));
    // A personal token names delegable roles alone, none that manages access.
    const credential = kind === 'person' ? null : tc.draw(scoped(tc.draw(more(tc.draw(grantsIn(world.projects, delegable(policy.roles))), delegable(auditing)))));
    // Now and then the instance's Auditor, whose scope may narrow nothing: who reads the whole log, or not, as its role is.
    const role = tc.draw(gs.integers({ minValue: 0, maxValue: 3 })) === 0 ? 'auditor' : person.role;
    const scope = role === person.role ? person.scope : tc.draw(gs.oneOf(gs.just<Scope>({ projects: 'all', environments: 'all' }), scopeOf(world.projects.map((project) => project.id))));
    return { kind, principal: person.principal, role, scope, grants, credential };
  });
}

/** What a credential's grant kept of its role: as the role is now, or as it shipped, before an Owner edited it. */
const issued = (policy: Policy, role: string) => gs.sampledFrom([policy.roles[role]!, ROLES[role] ?? policy.roles[role]!]);
const delegable = (roles: Record<string, Columns>) => Object.fromEntries(Object.entries(roles).filter(([, columns]) => !columns.permissions.includes('grant.manage')));

function query({ world }: Instance) {
  return gs.composite((tc): Query => {
    let path: Query['path'] = null;
    const depth = tc.draw(gs.integers({ minValue: 0, maxValue: 3 }));
    if (depth > 0) {
      // Mostly places there are, so that most queries read something.
      const project = tc.draw(gs.integers({ minValue: 0, maxValue: 7 })) === 0 ? null : tc.draw(gs.sampledFrom(world.projects));
      path = { project: project?.slug ?? 'gone' };
      if (depth > 1) {
        const environments = project?.environments ?? [];
        const roots = environments.filter((environment) => environment.owner === null).map((environment) => environment.slug);
        const named = environments.map((environment) => storedSlug(environment, environments.find((parent) => parent.id === environment.parentId)?.slug));
        path.environment = tc.draw(gs.sampledFrom([...named, ...named, ...roots.map((slug) => `${slug}@me`), 'nope']));
        const keys = world.secrets.filter((secret) => environments.some((environment) => environment.id === secret.environmentId)).map((secret) => secret.key);
        if (depth > 2) path.key = tc.draw(gs.sampledFrom([...keys, ...keys, 'MISSING']));
      }
    }
    return {
      path,
      actor: tc.draw(gs.optional(gs.sampledFrom(ASKED_ACTORS))),
      decision: tc.draw(gs.optional(gs.sampledFrom(['allow', 'deny'] as const))),
      detail: tc.draw(gs.booleans()),
      limit: tc.draw(gs.integers({ minValue: 1, maxValue: 6 })),
    };
  });
}

// The model.

function admits(filter: Filter, value: string | null): boolean {
  if (filter === 'all') return true;
  if (value === null) return false;
  return 'only' in filter ? filter.only.includes(value) : !filter.except.includes(value);
}

/**
 * Whether `asker` holds `audit.read` at a project or one of its
 * environments: by the instance role inside its scope (a project as a
 * whole only when the scope keeps all its environments), or a grant on the
 * project or that environment; for a person in a protected environment, by
 * the role's protected column; and within the credential's scope, if any.
 * A personal config's is its parent's.
 */
function readsAt({ world, policy }: Instance, asker: Who, projectId: string, environmentId: string | null): boolean {
  const environments = world.projects.flatMap((project) => project.environments);
  let at = environmentId === null ? null : environments.find((environment) => environment.id === environmentId)!;
  if (at?.owner != null) at = environments.find((environment) => environment.id === at!.parentId)!;
  const column = (columns: Columns) => (asker.kind !== 'service' && at !== null && policy.protected.includes(at.id) ? columns.protected : columns.permissions);
  const covers = (grant: Grant) => grant.projectId === projectId && (grant.environmentId === null || grant.environmentId === at?.id);
  if (asker.credential !== null && !asker.credential.some(({ grant, columns }) => covers(grant) && column(columns).includes('audit.read'))) return false;
  const inScope = admits(asker.scope.projects, projectId) && (at === null ? asker.scope.environments === 'all' : admits(asker.scope.environments, at.slug));
  if (asker.kind !== 'service' && inScope && column(policy.instanceRoles[asker.role]).includes('audit.read')) return true;
  return asker.grants.some((grant) => covers(grant) && column(policy.roles[grant.role]!).includes('audit.read'));
}

function readsWhole({ policy }: Instance, asker: Who): boolean {
  const role = policy.instanceRoles[asker.role];
  return asker.kind !== 'service' && asker.credential === null && asker.scope.projects === 'all' && asker.scope.environments === 'all'
    && role.permissions.includes('audit.read') && role.protected.includes('audit.read');
}

function sees(instance: Instance, asker: Who, entry: Entry): boolean {
  if (readsWhole(instance, asker)) return true;
  const environments = instance.world.projects.flatMap((project) => project.environments);
  const sides = [entry.main, entry.also].filter((side): side is Side => side !== null);
  const projectOf = (side: Side) => side.projectId ?? environments.find((environment) => environment.id === side.environmentId)!.projectId;
  const reads = (side: Side) => readsAt(instance, asker, projectOf(side), side.environmentId);
  // Left out: an environment of a project they read, whose log they do not.
  const leftOut = (side: Side) => side.environmentId !== null && readsAt(instance, asker, projectOf(side), null) && !reads(side);
  return sides.some(reads) && !sides.some(leftOut);
}

type Resolved = { projectId: string; environmentId?: string; secretId?: string };

/** A path's place, as the caller names it, or a 404. */
function resolve({ world }: Instance, asker: Who, path: NonNullable<Query['path']>): Resolved | 404 {
  const project = world.projects.find((each) => each.slug === path.project);
  if (project === undefined) return 404;
  if (path.environment === undefined) return { projectId: project.id };
  const parentSlug = (environment: Environment) => project.environments.find((parent) => parent.id === environment.parentId)?.slug;
  let environment: Environment | undefined;
  if (path.environment.endsWith('@me')) {
    const of = project.environments.find((each) => each.owner === null && each.slug === path.environment!.slice(0, -'@me'.length));
    environment = asker.kind === 'service' ? undefined : project.environments.find((each) => of !== undefined && each.parentId === of.id && each.owner === asker.principal);
  } else {
    environment = project.environments.find((each) => storedSlug(each, parentSlug(each)) === path.environment);
  }
  if (environment === undefined) return 404;
  if (path.key === undefined) return { projectId: project.id, environmentId: environment.id };
  const secret = world.secrets.find((each) => each.environmentId === environment.id && each.key === path.key);
  return secret === undefined ? 404 : { projectId: project.id, environmentId: environment.id, secretId: secret.id };
}

/** Whether an entry is in a place's log: naming it on either side, or for a secret, listing it in a read of several. */
function inPlace(entry: Entry, place: Resolved): boolean {
  const sides = [entry.main, entry.also].filter((side): side is Side => side !== null);
  if (!sides.some((side) => side.projectId === place.projectId)) return false;
  if (place.environmentId !== undefined && !sides.some((side) => side.environmentId === place.environmentId)) return false;
  if (place.secretId === undefined) return true;
  if (sides.some((side) => side.secretId === place.secretId)) return true;
  return entry.action === 'secret.read' && entry.main?.secretId === null
    && (entry.secrets ?? []).some((listed) => listed.secretId === place.secretId || listed.also?.secretId === place.secretId);
}

function byActor(entry: Entry, asked: string): boolean {
  const colon = asked.indexOf(':');
  if (/^(user|token):/.test(asked)) return entry.actor === (asked.startsWith('user:') ? `user:${asked.slice(colon + 1).toLowerCase()}` : asked);
  return [`user:${asked}`, `token:${asked}`, `system:${asked}`, asked].includes(entry.actor);
}

// The real thing.

async function store({ world, archived }: Instance, log: readonly Entry[]): Promise<number[]> {
  const { owner, runtime } = database;
  await emptyLog(owner);
  await owner.delete(storedSecrets);
  await owner.delete(storedEnvironments);
  await owner.delete(storedProjects);
  const at = (id: string) => (archived.has(id) ? new Date() : null);
  await owner.insert(storedProjects).values(world.projects.map((project) => ({ id: project.id, slug: project.slug, name: project.slug, archivedAt: at(project.id) })));
  const environments = world.projects.flatMap((project) => project.environments);
  await owner.insert(storedEnvironments).values(environments.map((environment) => {
    const slug = storedSlug(environment, environments.find((parent) => parent.id === environment.parentId)?.slug);
    return { id: environment.id, projectId: environment.projectId, slug, name: slug, parentId: environment.parentId, owner: environment.owner, archivedAt: at(environment.id) };
  }));
  if (world.secrets.length > 0) {
    await owner.insert(storedSecrets).values(world.secrets.map((secret) => ({
      id: secret.id,
      projectId: environments.find((environment) => environment.id === secret.environmentId)!.projectId,
      environmentId: secret.environmentId,
      key: secret.key,
      archivedAt: secret.archived ? new Date() : null,
    })));
  }
  if (log.length === 0) return [];
  const written: AuditEntry[] = log.map((item) => {
    const [prefix, id] = [item.actor.slice(0, item.actor.indexOf(':')), item.actor.slice(item.actor.indexOf(':') + 1)];
    const metadata: Record<string, unknown> = {};
    if (item.also !== null) metadata.also = item.also;
    if (item.secrets !== null) metadata.secrets = item.secrets;
    return {
      actorType: prefix === 'user' ? 'user' : prefix === 'token' ? 'service' : 'system',
      actorId: id,
      action: item.action,
      decision: item.decision,
      projectId: item.main?.projectId ?? null,
      environmentId: item.main?.environmentId ?? null,
      secretId: item.main?.secretId ?? null,
      metadata,
    };
  });
  const appended = await runtime.transaction((tx) => appendAudit(tx, CHAIN_KEY, written));
  return log.map((_, i) => Number(appended.seqStart) + i);
}

const CHAIN_KEY = Buffer.alloc(32, 41);

function callerOf({ policy, world }: Instance, asker: Who): Caller {
  const environments = world.projects.flatMap((project) => project.environments);
  const definition = (name: string, columns: Columns) => ({ name, description: '', permissions: [...columns.permissions], protected: [...columns.protected] });
  const protectedIn: Record<string, { environmentId: string; slug: string | null }[]> = {};
  for (const id of policy.protected) {
    const environment = environments.find((each) => each.id === id)!;
    (protectedIn[environment.projectId] ??= []).push({ environmentId: id, slug: storedSlug(environment, environments.find((parent) => parent.id === environment.parentId)?.slug) });
  }
  const access: Access = {
    principal: asker.principal,
    status: 'active',
    generation: 1,
    role: asker.role,
    scope: asker.scope,
    grants: asker.grants.map((grant) => ({ ...grant, expiresAt: null })) as Access['grants'],
    since: null,
    by: null,
    policy: {
      roles: Object.fromEntries(Object.entries(policy.roles).map(([name, columns]) => [name, definition(name, columns)])),
      instanceRoles: Object.fromEntries(Object.entries(policy.instanceRoles).map(([name, columns]) => [name, definition(name, columns)])) as never,
      protected: [...policy.protected],
      protectedIn,
    },
  };
  const colon = asker.principal.indexOf(':');
  const principal = { type: asker.kind === 'service' ? 'service' as const : 'user' as const, id: asker.principal.slice(colon + 1) };
  const credentialScope = asker.credential?.map(({ grant, columns }) => ({
    projectId: grant.projectId, environmentId: grant.environmentId, role: grant.role,
    permissions: { normal: [...columns.permissions], protected: [...columns.protected] },
  })) ?? null;
  return callerFrom(principal, access, null, credentialScope);
}

function contextOf(caller: Caller): ApiContext {
  const refuse = () => { throw new Error('listAudit asks the vault nothing'); };
  return {
    db: database.runtime, chainKey: CHAIN_KEY, vault: new Proxy({}, { get: refuse }) as never, waitUntil: refuse,
    signin: null, workloads: null, mcp: null, caller, requestId: randomUUID(), sourceIp: null, credentialId: null,
    provenance: null, via: null, personalToken: null, credentialExpiresAt: null, rotateAfterDays: null,
  };
}

/** Every page of a query, from the head back, each held to the model as it comes. */
async function pages(instance: Instance, asker: Who, q: Query, log: readonly Entry[], seqs: readonly number[]): Promise<void> {
  const ctx = contextOf(callerOf(instance, asker));
  const asked: Omit<AuditQuery, 'before'> = {
    ...(q.path === null ? {} : { path: q.path }),
    ...(q.actor === null ? {} : { actor: q.actor }),
    ...(q.decision === null ? {} : { decision: q.decision }),
    detail: q.detail,
    limit: q.limit,
  };
  const forbidden = !readsWhole(instance, asker) && !instance.world.projects.some((project) =>
    readsAt(instance, asker, project.id, null) || project.environments.some((environment) => readsAt(instance, asker, project.id, environment.id)));
  const place = q.path === null ? null : resolve(instance, asker, q.path);
  if (forbidden || place === 404) {
    await assert.rejects(listAudit(ctx, asked), (error: unknown) => error instanceof ApiError && error.status === (forbidden ? 403 : 404));
    return;
  }
  // Newest first: what the filters but `detail` match, and of those, the entries shown.
  const matching = log.map((item, i) => ({ item, seq: seqs[i]! }))
    .filter(({ item }) => sees(instance, asker, item) && (place === null || inPlace(item, place))
      && (q.actor === null || byActor(item, q.actor)) && (q.decision === null || item.decision === q.decision))
    .reverse();
  const shown = matching.filter(({ item }) => q.detail || !DETAIL.has(item.action));
  let before: number | undefined;
  let rest = shown;
  for (let n = 0; ; n++) {
    assert.ok(n <= shown.length, 'paging ends');
    const page = await listAudit(ctx, { ...asked, ...(before === undefined ? {} : { before }) });
    const expected = rest.slice(0, q.limit);
    assert.deepEqual(page.entries.map((each) => each.seq), expected.map(({ seq }) => seq), `page ${n} before ${before ?? 'the head'}`);
    assert.equal(page.more, expected.length === q.limit, `page ${n}: more`);
    for (const [i, shownEntry] of page.entries.entries()) {
      const { item } = expected[i]!;
      const project = instance.world.projects.find((each) => each.id === item.main?.projectId);
      assert.equal(shownEntry.project, project?.slug ?? null);
      assert.equal(shownEntry.action, item.action);
    }
    if (q.detail) assert.equal(page.hidden, undefined);
    else {
      // What the page left out: the detail entries in its stretch, from its oldest entry (the log's first on the last) up to where it started.
      const from = page.more ? page.entries.at(-1)!.seq : -Infinity;
      const counts = new Map<string, number>();
      for (const { item, seq } of matching) {
        if (DETAIL.has(item.action) && seq >= from && (before === undefined || seq < before)) counts.set(item.action, (counts.get(item.action) ?? 0) + 1);
      }
      const hidden = [...counts].map(([action, count]) => ({ action, count })).sort((a, b) => b.count - a.count || (a.action < b.action ? -1 : 1));
      assert.deepEqual(page.hidden, hidden, `page ${n}: hidden`);
    }
    rest = rest.slice(expected.length);
    if (!page.more) break;
    before = page.entries.at(-1)!.seq;
  }
  assert.deepEqual(rest, [], 'the last page leaves nothing out');
}

function describe(instance: Instance, asker: Who, q: Query): string {
  return JSON.stringify({ asker, query: q, protected: instance.policy.protected }, null, 1);
}

test(`the log a caller reads is the entries about the places they read, both sides of each, paged without gaps or repeats, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const drawn = tc.draw(instance);
  const log = tc.draw(gs.arrays(entry(drawn.world), { maxSize: 20 }));
  const seqs = await store(drawn, log);
  for (let n = tc.draw(gs.integers({ minValue: 1, maxValue: 4 })); n > 0; n--) {
    const asker = tc.draw(who(drawn));
    const q = tc.draw(query(drawn));
    tc.note(describe(drawn, asker, q));
    await pages(drawn, asker, q, log, seqs);
  }
}, settings));
