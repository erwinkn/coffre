// No value leaves coffre for someone the rules forbid it to (R8, R15, R16,
// R18, R20, R23, R24, R30, R32). A random world from the shared domain
// generators is built through the API: projects, environments, forks that
// inherit, `@me` overlays, keys of every nature, references, people with
// instance roles and grants, service accounts, an edited policy with
// protected environments, and personal tokens, service tokens and trust
// bindings issued by whoever the world says. Then a random list of changes,
// drawn up front so Hegel shrinks it, edits all of that. After the world and
// after each change, every session and credential reads every environment
// every way the API offers: a whole environment's reveal (`coffre run` and
// `export`), each key's (`coffre get`), the listing, which shows plain
// values, and a dry run, whose `unchanged` confirms a guess. Every value is
// a unique token, so a scan of each answer's body finds whatever it handed
// back, wherever it is in it, an error's message included.
//
// An independent model, written from the README and docs/design (roles.md,
// forking.md, personal-tokens.md, instance-roles.md), says what each one may
// receive: a plain value whoever lists where it is read, a secret whoever
// reads there, both also where an inherited value is held; a sensitive one
// no person on any credential, Owners included, and a service only on a
// credential an Owner of the value's project issued; an `@me` value its owner
// alone. A person's personal token holds its scope as issued, and its person
// as they are now; a service's credential its scope as issued, its account
// as it is now, and no more than its issuer held when issuing it.
//
// A change that makes a value reachable by someone who could not reach it
// before, rather than changing who holds what, is a value made live
// (roles.md, section 2): its actor must have typed it, or could reach it
// themselves, or, for an old version, hold at its place what it takes to
// bring back (write for a plain one, read for a secret, use for a sensitive
// one); and a sensitive value made reachable as anything else takes an
// Owner of its project (R30).
import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';
import { generateKeyPairSync, randomUUID, sign as signWith, type KeyObject } from 'node:crypto';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';
import { CoffreError, createClient, type CoffreClient } from '@coffre/client';
import { github, signin } from '@coffre/core/identity';
import { and, eq } from 'drizzle-orm';

import { propertySettings } from '../../../scripts/property-settings.ts';
import {
  columns as drawColumns,
  INSTANCE_ROLES,
  INSTANCE_ROLE_NAMES,
  NATURES,
  PEOPLE,
  PERMISSIONS,
  policy as drawPolicy,
  PROJECT_ONLY,
  ROLES,
  ROLE_NAMES,
  scope as drawScope,
  SERVICES,
  world as drawWorld,
  type Columns,
  type Filter,
  type InstanceRole,
  type Nature,
  type Permission,
  type Policy,
  type Scope,
  type World,
} from '../../../scripts/properties/domain.ts';
import { coffreRoute } from '../src/app.ts';
import { serveApi } from '../src/api/router.ts';
import { resolveConfig } from '../src/config.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { forgetKeys } from '../src/workloads/keys.ts';
import { processLimits } from '../src/workloads/limits.ts';
import type { WorkloadTransport } from '../src/workloads/transport.ts';
import { contextFor, openTestDatabase, resetDatabase, testVault, waitUntil, type FixtureDeps } from './api-fixture.ts';
import { environments as storedEnvironments, projects as storedProjects } from './db/tables.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'user:admin@acme.example';
const ISSUER = 'https://token.actions.githubusercontent.com';
const KEYS_URL = `${ISSUER}/.well-known/jwks`;
const KEY_NAMES = ['DATABASE_URL', 'STRIPE_KEY', 'API_TOKEN', 'REGION'] as const;
const CUSTOM_ROLES = ['release-manager', 'reader', 'on-call'] as const;
const READ: Permission = 'secret.read';
const USE: Permission = 'secret.use';
const WRITE: Permission = 'secret.write';
const settings = propertySettings(8, 10);

/** Who acts: the instance's first Owner, or a person of the world. */
const ACTORS = [ROOT, ...PEOPLE] as const;
/** Whose access a change edits: a person or a service account. */
const MEMBERS = [...PEOPLE, ...SERVICES] as const;
const OP_KINDS = [
  'write', 'write-personal', 'mark', 'refer', 'restore', 'archive', 'unarchive', 'fork', 'grant', 'revoke', 'setup',
  'instance-role', 'role-edit', 'protect', 'unprotect', 'personal-token', 'service-token', 'binding', 'remove', 'readd',
] as const;
type Op = {
  kind: typeof OP_KINDS[number];
  actor: number;
  member: number;
  env: number;
  source: number;
  key: typeof KEY_NAMES[number];
  nature: Nature;
  role: string;
  instanceRole: InstanceRole;
  scope: Scope;
  columns: Columns;
  /** A role edit's: the instance role of that name. A fork's: whether it inherits. A token's: its whole account, or one place. */
  flag: boolean;
  /** Which version a restore brings back, which place a token names: taken modulo what there is. */
  index: number;
  /** A grant's or a token's place: a project, or one environment. */
  onProject: boolean;
  /** A fixed scenario's own choice, by the world's ids, over the indices above. */
  target?: { env: string; key?: string; source?: { env: string; key: string } };
};
const operation = (projectIds: readonly string[]) => gs.record({
  kind: gs.sampledFrom(OP_KINDS),
  actor: gs.integers({ minValue: 0, maxValue: ACTORS.length - 1 }),
  member: gs.integers({ minValue: 0, maxValue: MEMBERS.length - 1 }),
  env: gs.integers({ minValue: 0, maxValue: 9 }),
  source: gs.integers({ minValue: 0, maxValue: 9 }),
  key: gs.sampledFrom(KEY_NAMES),
  nature: gs.sampledFrom(NATURES),
  role: gs.sampledFrom([...ROLE_NAMES, ...CUSTOM_ROLES]),
  instanceRole: gs.sampledFrom(INSTANCE_ROLE_NAMES),
  scope: drawScope(projectIds),
  columns: drawColumns,
  flag: gs.booleans(),
  index: gs.integers({ minValue: 0, maxValue: 5 }),
  onProject: gs.booleans(),
});

// The model's state.
type Env = { key: string; id: string; projectId: string; project: string; slug: string; parent: string | null; owner: string | null };
type Version = { text: string; nature: Nature };
type Row = { versions: Version[]; current: number | null; reference: { env: string; key: string } | null; archived: boolean };
type Person = { active: boolean; role: InstanceRole; scope: Scope; grants: Map<string, string> };
type Account = { active: boolean; grants: Map<string, string> };
type ScopePlace = { projectId: string; environmentId: string | null; columns: Columns };
type Credential = {
  label: string;
  kind: 'personal' | 'service' | 'binding';
  /** The person a personal token acts as, or the service account. */
  holder: string;
  issuer: string;
  scope: ScopePlace[];
  /** For a service's: what its issuer held at each environment when issuing it. */
  cap: (env: Env) => ReadonlySet<Permission>;
  /** For a service's: the projects whose sensitive values it reads, an Owner of which issued it. */
  sensitive: ReadonlySet<string>;
  live: boolean;
  /** Read once after it died: dead for good, it is not read again. */
  buried: boolean;
  token: string;
  repository: string;
};
/** Where a value is served: read at `env`, held at `holder` (itself, or the parent it inherits from), from `project`. */
type Serving = { env: Env; holder: Env; key: string; text: string; nature: Nature; project: string; version: number | null };
type Reader = { label: string; person: string | null; credential: Credential | null };

const STRICTNESS: Record<Nature, number> = { plain: 0, secret: 1, sensitive: 2 };
const placeKey = (projectId: string, environmentId: string | null) => `${projectId}/${environmentId ?? ''}`;
const inFilter = (filter: Filter, value: string) => filter === 'all' || ('only' in filter ? filter.only.includes(value) : !filter.except.includes(value));
/** A role's permissions at a place: its protected column in a protected environment, and its project-wide ones, which have one column, everywhere. */
const columnsOf = (columns: Columns | undefined, guarded: boolean): readonly Permission[] =>
  columns === undefined ? [] : guarded ? [...columns.protected, ...columns.permissions.filter((permission) => PROJECT_ONLY.includes(permission))] : columns.permissions;
const sameColumns = (a: Columns, b: Columns) => JSON.stringify([[...a.permissions].sort(), [...a.protected].sort()]) === JSON.stringify([[...b.permissions].sort(), [...b.protected].sort()]);

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let signer: { privateKey: KeyObject; jwk: Record<string, unknown> };
const transport: WorkloadTransport = { json: async (url) => (url.href === KEYS_URL ? { keys: [signer.jwk] } : { issuer: ISSUER, jwks_uri: KEYS_URL }) };

before(async () => {
  db = await openTestDatabase();
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  signer = { privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid: 'es-1', alg: 'ES256', use: 'sig' } };
});
after(async () => { await db.close(); });

/** What each reader received and was allowed, for a fixed scenario's own assertions. */
type Outcome = { received: Map<string, Set<string>>; texts: Map<string, string>; applied: number };

async function scenario(world: World, policy: Policy, ops: readonly Op[], note: (text: string) => void = () => {}): Promise<Outcome> {
  await resetDatabase(db.owner);
  forgetKeys();
  const vault = testVault([ROOT.slice('user:'.length)], { bulkLimit: { count: 1_000_000, windowMinutes: 1 } }, { kek: Buffer.alloc(32, 17) });
  const deps: FixtureDeps = { db: db.runtime, vault, chainKey: Buffer.alloc(32, 23) };
  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault,
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: processLimits({ perSource: 1_000_000, total: 1_000_000 }) } }),
    auditChainKey: deps.chainKey.toString('base64'),
  });
  const runtime: CoffreRuntime = createRuntime(config, deps.db, vault, transport, waitUntil);
  deps.signin = runtime.signin!;
  deps.workloads = runtime.workloads!;

  /** A person's session, as a page or `coffre login` holds it; `sink` keeps each answer's body. */
  const session = (principal: string, sink?: string[]): CoffreClient => createClient({
    url: ORIGIN,
    transport: async (request) => {
      const response = await serveApi(request, await contextFor(deps, principal.slice('user:'.length)));
      sink?.push(await response.clone().text());
      return response;
    },
  });
  const bearer = (token: string, sink?: string[]): CoffreClient => createClient({
    url: ORIGIN,
    headers: () => ({ authorization: `Bearer ${token}` }),
    transport: async (request) => {
      const response = (await coffreRoute(request, runtime, '203.0.113.7'))!;
      sink?.push(await response.clone().text());
      return response;
    },
  });

  // The model.
  const roles: Record<string, Columns> = { ...ROLES };
  const instanceRoles: Record<string, Columns> = { ...INSTANCE_ROLES };
  const guarded = new Set<string>();
  const projects: { key: string; id: string; slug: string }[] = [];
  const envs: Env[] = [];
  const rows = new Map<string, Map<string, Row>>();
  const removed = new Set<string>();
  const people = new Map<string, Person>([[ROOT, { active: true, role: 'owner', scope: { projects: 'all', environments: 'all' }, grants: new Map() }]]);
  const accounts = new Map<string, Account>();
  const credentials: Credential[] = [];
  /** What each person could ever reach, by their sessions and the credentials they hold or issued; and what they typed. */
  const everKnown = new Map<string, Set<string>>(ACTORS.map((actor) => [actor, new Set()]));
  const typed = new Map<string, Set<string>>(ACTORS.map((actor) => [actor, new Set()]));
  const texts = new Map<string, string>();
  let made = 0;
  const fresh = (where: string) => {
    const text = `vv${String(++made).padStart(4, '0')}vv`;
    texts.set(text, where);
    return text;
  };

  const envOf = (key: string) => envs.find((env) => env.key === key)!;
  const rowsOf = (env: Env) => rows.get(env.key) ?? rows.set(env.key, new Map()).get(env.key)!;
  const pathOf = (env: Env) => `${env.project}/${env.slug}`;
  const isGuarded = (env: Env): boolean => env.owner !== null ? isGuarded(envOf(env.parent!)) : guarded.has(env.key);

  function personAt(person: Person, env: Env, policy = { roles, instanceRoles }, protection = isGuarded(env)): Set<Permission> {
    const held = new Set<Permission>();
    if (!person.active) return held;
    if (inFilter(person.scope.projects, env.projectId) && inFilter(person.scope.environments, env.slug)) {
      for (const permission of columnsOf(policy.instanceRoles[person.role], protection)) held.add(permission);
    }
    for (const at of [placeKey(env.projectId, null), placeKey(env.projectId, env.id)]) {
      const role = person.grants.get(at);
      for (const permission of columnsOf(role === undefined ? undefined : policy.roles[role], protection)) held.add(permission);
    }
    return held;
  }
  function accountAt(account: Account, env: Env): Set<Permission> {
    const held = new Set<Permission>();
    if (!account.active) return held;
    for (const at of [placeKey(env.projectId, null), placeKey(env.projectId, env.id)]) {
      const role = account.grants.get(at);
      for (const permission of columnsOf(role === undefined ? undefined : roles[role], false)) held.add(permission);
    }
    return held;
  }
  const scopeAt = (credential: Credential, env: Env, protection: boolean) => new Set(credential.scope
    .filter((place) => place.projectId === env.projectId && (place.environmentId === null || place.environmentId === env.id))
    .flatMap((place) => columnsOf(place.columns, protection)));
  const meet = (...sets: ReadonlySet<Permission>[]) => new Set([...sets[0]!].filter((permission) => sets.every((set) => set.has(permission))));

  /** What a reader holds at an environment that is no personal config. */
  function holds(reader: Reader, env: Env): Set<Permission> {
    if (reader.credential === null) return personAt(people.get(reader.person!)!, env);
    const { credential } = reader;
    if (!credential.live) return new Set();
    if (credential.kind === 'personal') {
      const person = people.get(credential.holder)!;
      return meet(personAt(person, env), scopeAt(credential, env, isGuarded(env)));
    }
    return meet(accountAt(accounts.get(credential.holder)!, env), scopeAt(credential, env, false), credential.cap(env));
  }
  /** Whether a reader reaches a personal config's own values: its owner, while they read or use what it is a config of. */
  function ownsOverlay(reader: Reader, env: Env): boolean {
    const person = reader.credential === null ? reader.person : reader.credential.kind === 'personal' ? reader.credential.holder : null;
    if (person !== env.owner) return false;
    const held = holds(reader, envOf(env.parent!));
    return held.has(READ) || held.has(USE);
  }

  function keysAt(env: Env): Set<string> {
    const own = new Set(rowsOf(env).keys());
    if (env.parent !== null) for (const key of keysAt(envOf(env.parent))) own.add(key);
    return own;
  }
  /** What a key resolves to where it is read: its own value, its reference's source's, or what its parent passes down. */
  function resolve(env: Env, key: string): Omit<Serving, 'env' | 'key'> | null {
    const row = rowsOf(env).get(key);
    if (row !== undefined && !row.archived) {
      if (row.reference !== null) {
        const sourceEnv = envOf(row.reference.env);
        const source = rowsOf(sourceEnv).get(row.reference.key);
        if (source === undefined || source.archived || source.current === null) return null;
        return { holder: env, ...source.versions[source.current]!, project: sourceEnv.projectId, version: null };
      }
      return { holder: env, ...row.versions[row.current!]!, project: env.projectId, version: row.current! + 1 };
    }
    if (env.parent === null || removed.has(`${env.key}/${key}`)) return null;
    return resolve(envOf(env.parent), key);
  }
  function servings(): Serving[] {
    const live = envs.flatMap((env) => [...keysAt(env)].flatMap((key) => {
      const resolved = resolve(env, key);
      return resolved === null ? [] : [{ env, key, ...resolved }];
    }));
    // An archived key is still listed, with its plain value, which its listers saw already; but for a fork's override
    // reset to its parent's, which lists the parent's instead.
    const archived = envs.flatMap((env) => [...rowsOf(env)].flatMap(([key, row]): Serving[] => {
      if (!row.archived || (env.parent !== null && keysAt(envOf(env.parent)).has(key))) return [];
      const unarchived = { ...row, archived: false };
      rowsOf(env).set(key, unarchived);
      const resolved = resolve(env, key);
      rowsOf(env).set(key, row);
      return resolved?.nature === 'plain' ? [{ env, key, ...resolved }] : [];
    }));
    return [...live, ...archived];
  }
  /**
   * Whether a reader may be handed a value as it is served: plain to whoever
   * lists (reads or uses) where it is read and where it is held, a secret to
   * whoever reads both, a sensitive one only to a service, on a credential
   * an Owner of the value's project issued; a personal config's own values
   * to its owner alone.
   */
  function receives(reader: Reader, serving: Serving): boolean {
    if (serving.nature === 'sensitive' && (reader.credential === null || reader.credential.kind === 'personal' || !reader.credential.sensitive.has(serving.project))) return false;
    const enough = (held: ReadonlySet<Permission>) => held.has(READ) || (serving.nature === 'plain' && held.has(USE));
    if (serving.env.owner !== null) {
      if (!ownsOverlay(reader, serving.env)) return false;
      return serving.holder === serving.env || enough(holds(reader, serving.holder));
    }
    return enough(holds(reader, serving.env)) && (serving.holder === serving.env || enough(holds(reader, serving.holder)));
  }
  const allowed = (reader: Reader, all = servings()) => new Set(all.filter((serving) => receives(reader, serving)).map((serving) => serving.text));

  const sessionReader = (person: string): Reader => ({ label: `session of ${person}`, person, credential: null });
  const credentialReader = (credential: Credential): Reader => ({ label: credential.label, person: null, credential });
  const readers = (): Reader[] => [...ACTORS.map(sessionReader), ...credentials.map(credentialReader)];
  /** Everything each person can reach now, on their sessions and on the credentials they hold or issued, is theirs for good. */
  function learn() {
    const all = servings();
    for (const actor of ACTORS) for (const text of allowed(sessionReader(actor), all)) everKnown.get(actor)!.add(text);
    for (const credential of credentials) {
      const reach = allowed(credentialReader(credential), all);
      for (const person of new Set([credential.issuer, credential.kind === 'personal' ? credential.holder : credential.issuer])) {
        for (const text of reach) everKnown.get(person)!.add(text);
      }
    }
  }

  /** Whether a person owns a project: an Owner of the whole of it, by an unscoped-enough instance role or a grant. */
  function ownsProject(principal: string, projectId: string): boolean {
    const person = people.get(principal)!;
    if (!person.active) return false;
    return (person.role === 'owner' && inFilter(person.scope.projects, projectId) && person.scope.environments === 'all')
      || person.grants.get(placeKey(projectId, null)) === 'owner';
  }

  // Calls: refusals are expected; a server error is not.
  async function attempt<T>(call: () => Promise<T>): Promise<T | null> {
    try {
      return await call();
    } catch (error) {
      if (error instanceof CoffreError && error.status < 500) return null;
      throw error;
    }
  }
  const clientOf = (actor: string) => session(actor);
  const root = clientOf(ROOT);

  async function realEnv(projectId: string, filter: { slug?: string; owner?: string; parentId?: string }) {
    const where = [eq(storedEnvironments.projectId, projectId)];
    if (filter.slug !== undefined) where.push(eq(storedEnvironments.slug, filter.slug));
    if (filter.owner !== undefined) where.push(eq(storedEnvironments.owner, filter.owner));
    if (filter.parentId !== undefined) where.push(eq(storedEnvironments.parentId, filter.parentId));
    const [row] = await db.owner.select({ id: storedEnvironments.id, slug: storedEnvironments.slug }).from(storedEnvironments).where(and(...where));
    return row!;
  }

  /** A person's personal config of `base`: made at their first write there. */
  async function overlayOf(person: string, base: Env, key = `${base.key}@${person}`): Promise<Env> {
    const existing = envs.find((env) => env.owner === person && env.parent === base.key);
    if (existing !== undefined) return existing;
    const row = await realEnv(base.projectId, { owner: person, parentId: base.id });
    const env: Env = { key, id: row.id, projectId: base.projectId, project: base.project, slug: row.slug, parent: base.key, owner: person };
    envs.push(env);
    return env;
  }
  /** The path a person writes a value at: a personal config's by `@me`, any other by its slug. */
  const writePath = (env: Env) => env.owner === null ? pathOf(env) : `${env.project}/${envOf(env.parent!).slug}@me`;

  // Value changes, applied to the model once the API took them.
  function rowAt(env: Env, key: string): Row {
    const existing = rowsOf(env).get(key);
    if (existing !== undefined) return existing;
    const row: Row = { versions: [], current: null, reference: null, archived: false };
    rowsOf(env).set(key, row);
    return row;
  }
  function written(env: Env, key: string, version: Version) {
    const row = rowAt(env, key);
    row.versions.push(version);
    row.current = row.versions.length - 1;
    row.reference = null;
    row.archived = false;
    removed.delete(`${env.key}/${key}`);
  }
  async function write(actor: string, env: Env, key: string, nature: Nature): Promise<boolean> {
    const text = fresh(`${env.key}/${key} as ${nature} by ${actor}`);
    const done = await attempt(() => clientOf(actor).secrets.set(writePath(env), { [key]: { value: text, sensitivity: nature } }));
    if (done === null) return false;
    typed.get(actor)!.add(text);
    written(env, key, { text, nature });
    return true;
  }
  async function refer(actor: string, env: Env, key: string, source: Env, sourceKey: string): Promise<boolean> {
    const done = await attempt(() => clientOf(actor).secrets.set(pathOf(env), { [key]: { ref: `${pathOf(source)}/${sourceKey}` } }));
    if (done === null) return false;
    const row = rowAt(env, key);
    row.current = null;
    row.reference = { env: source.key, key: sourceKey };
    row.archived = false;
    removed.delete(`${env.key}/${key}`);
    return true;
  }

  // Credentials.
  const ALL = new Set<Permission>(PERMISSIONS);
  const pathOfPlace = (projectId: string, environmentId: string | null) => {
    const project = projects.find((each) => each.id === projectId)!;
    return environmentId === null ? project.slug : `${project.slug}/${envs.find((env) => env.id === environmentId)!.slug}`;
  };
  type Place = { projectId: string; environmentId: string | null; role: string };
  async function issuePersonal(person: string, places: readonly Place[]): Promise<boolean> {
    if (places.length === 0) return false;
    const scope = Object.fromEntries(places.map((place) => [pathOfPlace(place.projectId, place.environmentId), place.role]));
    const issued = await attempt(() => clientOf(person).tokens.issue(person, { label: 'property', expiresInMinutes: 60, scope }));
    if (issued === null) return false;
    credentials.push({
      label: `personal token ${credentials.length} of ${person} for ${JSON.stringify(scope)}`,
      kind: 'personal', holder: person, issuer: person,
      scope: places.map((place) => ({ projectId: place.projectId, environmentId: place.environmentId, columns: roles[place.role] ?? { permissions: [], protected: [] } })),
      cap: () => ALL, sensitive: new Set(), live: true, buried: false, token: issued.token, repository: '',
    });
    return true;
  }
  const claimsFor = (repository: string) => ({
    repository_owner_id: '9919', repository_id: repository, workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main', ref: 'refs/heads/main', event_name: 'push',
  });
  async function issueService(issuer: string, account: string, places: readonly Place[] | null, kind: 'service' | 'binding'): Promise<boolean> {
    const scope = places === null ? undefined : Object.fromEntries(places.map((place) => [pathOfPlace(place.projectId, place.environmentId), place.role]));
    const repository = String(50_000 + credentials.length);
    let token = '';
    if (kind === 'service') {
      const issued = await attempt(() => clientOf(issuer).tokens.issue(account, { expiresInDays: 30, ...(scope === undefined ? {} : { scope }) }));
      if (issued === null) return false;
      token = issued.token;
    } else {
      const bound = await attempt(() => clientOf(issuer).bindings.create(account, { profile: 'github', claims: claimsFor(repository), ...(scope === undefined ? {} : { scope }) }));
      if (bound === null) return false;
    }
    // What it reaches: the places it names, or all its account holds now, each as its role is now.
    const held = places ?? [...accounts.get(account)!.grants].map(([at, role]) => {
      const [projectId, environmentId] = at.split('/') as [string, string];
      return { projectId, environmentId: environmentId === '' ? null : environmentId, role };
    });
    // No more than its issuer held when issuing it: where each environment was, as it was; anywhere made later, by the roles and grants they had.
    const issuerThen = { ...people.get(issuer)!, grants: new Map(people.get(issuer)!.grants) };
    const policyThen = { roles: { ...roles }, instanceRoles: { ...instanceRoles } };
    const atIssue = new Map(envs.filter((env) => env.owner === null).map((env) => [env.key, personAt(issuerThen, env)]));
    credentials.push({
      label: `${kind === 'service' ? 'service token' : 'binding'} ${credentials.length} of ${account} by ${issuer}${scope === undefined ? '' : ` for ${JSON.stringify(scope)}`}`,
      kind, holder: account, issuer,
      scope: held.map((place) => ({ projectId: place.projectId, environmentId: place.environmentId, columns: roles[place.role] ?? { permissions: [], protected: [] } })),
      // Who managed access there could give it anything (README, "Roles": an Admin reaches values through a service account).
      cap: (env) => {
        const held = atIssue.get(env.key) ?? personAt(issuerThen, env, policyThen, false);
        return held.has('grant.manage') ? ALL : held;
      },
      // R32: a service reads a project's sensitive values only on a credential an Owner of that project issued.
      sensitive: new Set(held.filter((place) => ownsProject(issuer, place.projectId)).map((place) => place.projectId)),
      live: true, buried: false, token, repository,
    });
    return true;
  }
  /** A CI run's ID token for a binding's repository, as GitHub would sign it for this instance. */
  function idToken(repository: string): string {
    const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const input = `${part({ alg: 'ES256', kid: 'es-1', typ: 'JWT' })}.${part({ iss: ISSUER, aud: ORIGIN, sub: `repo:acme/r${repository}:ref:refs/heads/main`, iat: now - 5, exp: now + 295, jti: randomUUID(), run_id: '7001', ...claimsFor(repository) })}`;
    return `${input}.${signWith('sha256', Buffer.from(input), { key: signer.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
  }
  async function exchanged(credential: Credential): Promise<string | null> {
    const response = (await coffreRoute(new Request(`${ORIGIN}/api/auth/oidc`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: credential.holder, token: idToken(credential.repository) }),
    }), runtime, '203.0.113.7'))!;
    if (response.status >= 500) throw new Error(`the exchange failed: ${response.status} ${await response.text()}`);
    return response.status === 200 ? ((await response.json()) as { token: string }).token : null;
  }

  // Access changes, applied to the model once the API took them.
  const apiScope = (scope: Scope) => {
    const slugs = (ids: string[]) => ids.flatMap((id) => projects.filter((project) => project.key === id).map((project) => project.slug));
    const filter = (value: Filter) => value === 'all' ? value : 'only' in value ? { only: slugs(value.only) } : { except: slugs(value.except) };
    return { projects: filter(scope.projects), environments: scope.environments };
  };
  const realScope = (scope: Scope): Scope => {
    const ids = (keys: string[]) => keys.flatMap((key) => projects.filter((project) => project.key === key).map((project) => project.id));
    const filter = (value: Filter): Filter => value === 'all' ? value : 'only' in value ? { only: ids(value.only) } : { except: ids(value.except) };
    return { projects: filter(scope.projects), environments: scope.environments };
  };
  const grantsOf = (member: string) => (member.startsWith('user:') ? people.get(member)! : accounts.get(member)!).grants;
  async function grant(actor: string, member: string, projectId: string, environmentId: string | null, role: string | null): Promise<boolean> {
    const done = await attempt(() => clientOf(actor).access.set(member, { [pathOfPlace(projectId, environmentId)]: role }));
    if (done === null) return false;
    const account = member.startsWith('user:') ? people.get(member)! : accounts.get(member)!;
    if (!account.active) Object.assign(account, { active: true, grants: new Map() });
    if (role === null) grantsOf(member).delete(placeKey(projectId, environmentId));
    else grantsOf(member).set(placeKey(projectId, environmentId), role);
    return true;
  }
  const definition = (name: string, columns: Columns) => ({ name, description: '', permissions: [...columns.permissions], protected: [...columns.protected] });

  // The world, as its people would build it, the first five environments of it.
  for (const project of world.projects) {
    await root.projects.create(project.slug);
    const [row] = await db.owner.select({ id: storedProjects.id }).from(storedProjects).where(eq(storedProjects.slug, project.slug));
    projects.push({ key: project.id, id: row!.id, slug: project.slug });
  }
  const worldEnvs = world.projects.flatMap((project) => project.environments).slice(0, 5);
  for (const environment of worldEnvs) {
    if (environment.owner !== null) continue;
    const project = projects.find((each) => each.key === environment.projectId)!;
    const parent = environment.parentId === null ? null : envs.find((env) => env.key === environment.parentId);
    if (parent === undefined) continue;
    const done = await attempt(() => root.environments.create(`${project.slug}/${environment.slug}`, parent === null ? {} : { from: parent.slug, inherit: true }));
    if (done === null) continue;
    const row = await realEnv(project.id, { slug: environment.slug });
    envs.push({ key: environment.id, id: row.id, projectId: project.id, project: project.slug, slug: environment.slug, parent: parent?.key ?? null, owner: null });
  }
  for (const [name, wanted] of Object.entries(policy.roles)) {
    if (name === 'owner' || (ROLES[name] !== undefined && sameColumns(wanted, ROLES[name]))) continue;
    if (await attempt(() => root.roles.set(name, definition(name, wanted))) !== null) roles[name] = wanted;
  }
  for (const name of ['auditor', 'developer', 'admin'] as const) {
    const wanted = policy.instanceRoles[name];
    if (sameColumns(wanted, INSTANCE_ROLES[name])) continue;
    if (await attempt(() => root.roles.set(name, definition(name, wanted), { instance: true })) !== null) instanceRoles[name] = wanted;
  }
  for (const env of envs.filter((each) => policy.protected.includes(each.key))) {
    if (await attempt(() => root.environments.protect(pathOf(env))) !== null) guarded.add(env.key);
  }
  const placeOfWorld = (projectKey: string, environmentKey: string | null) => {
    const project = projects.find((each) => each.key === projectKey)!;
    if (environmentKey === null) return { projectId: project.id, environmentId: null };
    const env = envs.find((each) => each.key === environmentKey && each.owner === null);
    return env === undefined ? null : { projectId: project.id, environmentId: env.id };
  };
  for (const person of world.people) {
    const asked = person.role === 'member' ? {} : { role: person.role, scope: apiScope(person.scope) };
    const made = await attempt(() => root.members.add(person.principal, asked));
    if (made === null) await root.members.add(person.principal);
    people.set(person.principal, made === null || person.role === 'member'
      ? { active: true, role: 'member', scope: { projects: 'all', environments: 'all' }, grants: new Map() }
      : { active: true, role: person.role, scope: realScope(person.scope), grants: new Map() });
    for (const each of person.grants) {
      const place = placeOfWorld(each.projectId, each.environmentId);
      if (place !== null) await grant(ROOT, person.principal, place.projectId, place.environmentId, each.role);
    }
  }
  for (const service of world.services) {
    await root.members.add(service.principal);
    accounts.set(service.principal, { active: true, grants: new Map() });
    for (const each of service.grants) {
      const place = placeOfWorld(each.projectId, each.environmentId);
      if (place !== null) await grant(ROOT, service.principal, place.projectId, place.environmentId, each.role);
    }
  }
  const worldEnv = (id: string) => worldEnvs.find((environment) => environment.id === id);
  for (const secret of world.secrets) {
    const environment = worldEnv(secret.environmentId);
    if (environment === undefined) continue;
    if (environment.owner !== null) {
      // A personal config's values are its owner's to write, at `@me`, which makes it.
      const base = envs.find((env) => env.key === environment.parentId && env.owner === null);
      if (base === undefined) continue;
      const text = fresh(`${environment.id}/${secret.key} as ${secret.nature} by ${environment.owner}`);
      if (await attempt(() => clientOf(environment.owner!).secrets.set(`${pathOf(base)}@me`, { [secret.key]: { value: text, sensitivity: secret.nature } })) === null) continue;
      typed.get(environment.owner)!.add(text);
      written(await overlayOf(environment.owner, base, environment.id), secret.key, { text, nature: secret.nature });
      continue;
    }
    const env = envs.find((each) => each.key === environment.id);
    if (env === undefined) continue;
    if (secret.reference === null) {
      await write(ROOT, env, secret.key, secret.nature);
      continue;
    }
    const source = world.secrets.find((each) => each.id === secret.reference)!;
    const sourceEnv = envs.find((each) => each.key === source.environmentId);
    if (sourceEnv !== undefined && rowsOf(sourceEnv).get(source.key)?.current != null) await refer(ROOT, env, secret.key, sourceEnv, source.key);
  }
  for (const secret of world.secrets.filter((each) => each.archived)) {
    const env = envs.find((each) => each.key === secret.environmentId);
    const row = env === undefined ? undefined : rowsOf(env).get(secret.key);
    if (row === undefined || row.archived) continue;
    if (await attempt(() => clientOf(env!.owner ?? ROOT).secrets.set(writePath(env!), { [secret.key]: null })) !== null) row.archived = true;
  }
  for (const dismissal of world.dismissals) {
    const env = envs.find((each) => each.key === dismissal.environmentId && each.owner === null);
    if (env === undefined) continue;
    if (await attempt(() => root.environments.dismiss(pathOf(env), { [dismissal.key]: true })) !== null) removed.add(`${env.key}/${dismissal.key}`);
  }
  const placesOf = (scope: readonly { projectId: string; environmentId: string | null; role: string }[]): Place[] =>
    scope.flatMap((each) => {
      const place = placeOfWorld(each.projectId, each.environmentId);
      return place === null ? [] : [{ ...place, role: each.role }];
    });
  for (const credential of world.credentials) {
    if (credential.kind === 'personal') await issuePersonal(credential.issuer, placesOf(credential.scope));
    else await issueService(credential.issuer, credential.account, credential.scope.length === 0 ? null : placesOf(credential.scope), credential.kind);
  }

  // What every session and credential reads, against what the model allows it.
  const received = new Map<string, Set<string>>();
  let applied = 0;
  const describe = (text: string, all: Serving[]) => `${text} (${texts.get(text)}), served ${JSON.stringify(all.filter((serving) => serving.text === text).map((serving) => `${pathOf(serving.env)}/${serving.key} as ${serving.nature}${serving.holder === serving.env ? '' : ` from ${pathOf(serving.holder)}`}`))}`;
  async function readEverything(reader: Reader, client: CoffreClient, quiet: CoffreClient, got: Set<string>) {
    for (const env of envs) {
      const owner = reader.credential === null ? reader.person : reader.credential.kind === 'personal' ? reader.credential.holder : null;
      const paths = env.owner === null ? [pathOf(env)] : [pathOf(env), ...(owner === env.owner ? [writePath(env)] : [])];
      for (const path of paths) {
        const bulk = await attempt(() => client.secrets.reveal(path));
        await attempt(() => client.secrets.list(path));
        const guesses: Record<string, string> = {};
        for (const key of keysAt(env)) {
          if (bulk === null || !(key in bulk.values)) await attempt(() => client.secrets.reveal(`${path}/${key}`));
          const resolved = resolve(env, key);
          if (resolved !== null) guesses[key] = resolved.text;
        }
        // A dry run that says a guess is unchanged has told its reader the value.
        if (Object.keys(guesses).length === 0) continue;
        const compared = await attempt(() => quiet.secrets.dryRun(path, guesses));
        for (const [key, verdict] of Object.entries(compared?.keys ?? {})) if (verdict === 'unchanged') got.add(guesses[key]!);
      }
    }
  }
  async function consistent() {
    for (const env of envs.filter((each) => each.owner === null)) {
      const listed = await root.secrets.list(pathOf(env));
      const actual = Object.fromEntries(listed.keys.filter((key) => !key.archived && key.sensitivity !== null).map((key) => [key.key, `${key.sensitivity} v${key.version}`]).sort());
      const expected = Object.fromEntries([...keysAt(env)].flatMap((key) => {
        const resolved = resolve(env, key);
        return resolved === null ? [] : [[key, `${resolved.nature} v${resolved.version}`]];
      }).sort());
      assert.deepEqual(actual, expected, `the model holds ${pathOf(env)} as the API lists it`);
    }
  }
  async function check() {
    await consistent();
    const all = servings();
    for (const reader of readers()) {
      if (reader.credential?.buried === true) continue;
      const sink: string[] = [];
      const got = new Set<string>();
      if (reader.credential === null) {
        await readEverything(reader, session(reader.person!, sink), session(reader.person!), got);
      } else {
        const token = reader.credential.kind === 'binding' ? await exchanged(reader.credential) : reader.credential.token;
        if (token !== null) await readEverything(reader, bearer(token, sink), bearer(token), got);
      }
      for (const body of sink) for (const [text] of body.matchAll(/vv\d{4}vv/g)) got.add(text);
      const may = allowed(reader, all);
      const leaked = [...got].filter((text) => !may.has(text));
      assert.deepEqual(leaked.map((text) => describe(text, all)), [], `${reader.label} received only what the rules give it`);
      // And at least what they give it: every value held where it is read, but a sensitive one, which only a use hands on.
      const owed = all.filter((serving) => serving.env === serving.holder && serving.nature !== 'sensitive' && receives(reader, serving) && !got.has(serving.text));
      assert.deepEqual(owed.map((serving) => describe(serving.text, all)), [], `${reader.label} received all the rules give it`);
      const total = received.get(reader.label) ?? received.set(reader.label, new Set()).get(reader.label)!;
      for (const text of got) total.add(text);
      if (reader.credential !== null && !reader.credential.live) reader.credential.buried = true;
    }
    learn();
  }
  try {
    await check();
  } catch (error) {
    throw new Error(`after building the world: ${(error as Error).message}`, { cause: error });
  }

  // The changes.
  let forks = 0;
  const pick = <T>(list: readonly T[], n: number): T | undefined => list[n % Math.max(list.length, 1)];
  const shared = () => envs.filter((env) => env.owner === null);
  /** Whether the actor may act on this environment's keys: anyone on a shared one, its owner alone on a personal config. */
  const mine = (env: Env, actor: string) => env.owner === null || env.owner === actor;
  /** The keys of their own the actor may act on, which `test` takes. */
  const keyed = (actor: string, test: (row: Row) => boolean) => envs.filter((env) => mine(env, actor))
    .flatMap((env) => [...rowsOf(env)].filter(([, row]) => test(row)).map(([key, row]) => ({ env, key, row })));
  const envFor = (op: Op, list: readonly Env[]) => op.target === undefined ? pick(list, op.env) : list.find((env) => env.key === op.target!.env);
  const keyFor = (op: Op) => op.target?.key ?? op.key;
  const keyedFor = <T extends { env: Env; key: string }>(op: Op, list: readonly T[]) =>
    op.target === undefined ? pick(list, op.env) : list.find((at) => at.env.key === op.target!.env && at.key === op.target!.key);
  async function apply(op: Op, actor: string): Promise<'value' | 'access' | null> {
    switch (op.kind) {
      case 'write': {
        const env = envFor(op, envs);
        if (env === undefined) return null;
        if (!mine(env, actor)) {
          // Another person's personal config, by its own slug: never theirs to write.
          const done = await attempt(() => clientOf(actor).secrets.set(pathOf(env), { [keyFor(op)]: { value: fresh('a write into another\'s personal config'), sensitivity: op.nature } }));
          assert.equal(done, null, `${actor} wrote into ${env.owner}'s personal config ${pathOf(env)}`);
          return null;
        }
        return (await write(actor, env, keyFor(op), op.nature)) ? 'value' : null;
      }
      case 'write-personal': {
        const base = envFor(op, shared());
        if (base === undefined) return null;
        const key = keyFor(op);
        const text = fresh(`${base.key}@${actor}/${key} as ${op.nature} by ${actor}`);
        if (await attempt(() => clientOf(actor).secrets.set(`${pathOf(base)}@me`, { [key]: { value: text, sensitivity: op.nature } })) === null) return null;
        typed.get(actor)!.add(text);
        written(await overlayOf(actor, base), key, { text, nature: op.nature });
        return 'value';
      }
      case 'mark': {
        const at = keyedFor(op, keyed(actor, (row) => !row.archived && row.current !== null && row.versions[row.current]!.nature !== op.nature));
        if (at === undefined) return null;
        const { env, key, row } = at;
        const version = row.versions[row.current!]!;
        const done = await attempt(() => clientOf(actor).secrets.set(writePath(env), { [key]: { sensitivity: op.nature } })) !== null;
        // Looser only a sensitive value made a secret, by an Owner of its project (R30); stricter, by the instance's Owner
        // always. Whatever else a mark takes, it is not checked here: refused or not, the reads after hold it to the rules.
        const looser = STRICTNESS[op.nature] < STRICTNESS[version.nature];
        if (looser && !(version.nature === 'sensitive' && op.nature === 'secret' && ownsProject(actor, env.projectId))) assert.equal(done, false, `${actor} made ${pathOf(env)}/${key} ${op.nature} from ${version.nature}`);
        if (actor === ROOT && env.owner === null && !looser) assert.equal(done, true, `the instance's Owner could not make ${pathOf(env)}/${key} ${op.nature}`);
        if (!done) return null;
        row.versions.push({ text: version.text, nature: op.nature });
        row.current = row.versions.length - 1;
        return 'value';
      }
      case 'refer': {
        const env = envFor(op, shared());
        const sources = shared().filter((each) => each !== env).flatMap((each) => [...rowsOf(each)]
          .filter(([, row]) => !row.archived && row.current !== null)
          .map(([key]) => ({ env: each, key })));
        const named = op.target?.source;
        const source = named === undefined ? pick(sources, op.source) : sources.find((each) => each.env.key === named.env && each.key === named.key);
        if (env === undefined || source === undefined) return null;
        return (await refer(actor, env, keyFor(op), source.env, source.key)) ? 'value' : null;
      }
      case 'restore': {
        const at = keyedFor(op, keyed(actor, (row) => !row.archived && row.versions.length > 0));
        if (at === undefined) return null;
        const { env, key, row } = at;
        const version = op.index % row.versions.length + 1;
        const target = row.versions[version - 1]!;
        // It comes back no looser than it was, nor than that very value was made since, in place (R24); an Owner's loosening
        // is the current value's alone (R30); and sensitive while the key is, or its newest version (credential-proxy.md).
        const now = resolve(env, key)?.nature;
        const since = row.versions.findLast((later) => later.text === target.text)!.nature;
        const held = STRICTNESS[since] > STRICTNESS[target.nature] ? since : target.nature;
        const nature = now === 'sensitive' || row.versions.at(-1)!.nature === 'sensitive' ? 'sensitive' : held;
        const done = await attempt(() => clientOf(actor).secrets.restore(`${writePath(env)}/${key}`, version)) !== null;
        // A restore writes, and brings back an old value as it is held: refused to whoever cannot read it so (R24), plain
        // taking write alone, as does the current version, which makes no value live; never refused the instance's Owner.
        if (env.owner === null) {
          const holding = holds(sessionReader(actor), env);
          const makesLive = row.current !== version - 1 && held !== 'plain';
          if (!holding.has(WRITE) || (makesLive && !holding.has(held === 'secret' ? READ : USE))) assert.equal(done, false, `${actor} restored ${pathOf(env)}/${key} v${version}, held ${held}, holding ${[...holding].join(', ')}`);
          if (actor === ROOT) assert.equal(done, true, `the instance's Owner could not restore ${pathOf(env)}/${key} v${version}`);
        }
        if (!done) return null;
        written(env, key, { text: target.text, nature });
        return 'value';
      }
      case 'archive':
      case 'unarchive': {
        const archiving = op.kind === 'archive';
        const at = keyedFor(op, keyed(actor, (row) => row.archived !== archiving));
        if (at === undefined) return null;
        const { env, key, row } = at;
        const done = await attempt(async () => {
          if (archiving) await clientOf(actor).secrets.set(writePath(env), { [key]: null });
          else await clientOf(actor).secrets.update(`${writePath(env)}/${key}`, { archived: false });
          return true;
        });
        if (done === null) return null;
        row.archived = archiving;
        if (!archiving) removed.delete(`${env.key}/${key}`);
        return 'value';
      }
      case 'fork': {
        const source = envFor(op, shared());
        if (source === undefined || envs.length >= 8) return null;
        const slug = `f${++forks}`;
        const done = await attempt(() => clientOf(actor).environments.create(`${source.project}/${slug}`, op.flag ? { from: source.slug, inherit: true } : { from: source.slug }));
        if (done === null) return null;
        const row = await realEnv(source.projectId, { slug });
        const env: Env = { key: `op-${slug}`, id: row.id, projectId: source.projectId, project: source.project, slug, parent: op.flag ? source.key : null, owner: null };
        // A copy holds each value its source resolves to, as it is there; a fork of a protected environment is protected.
        const copies = op.flag ? [] : [...keysAt(source)].flatMap((key) => {
          const resolved = resolve(source, key);
          return resolved === null ? [] : [{ key, text: resolved.text, nature: resolved.nature }];
        });
        if (isGuarded(source)) guarded.add(env.key);
        envs.push(env);
        for (const copy of copies) written(env, copy.key, { text: copy.text, nature: copy.nature });
        return 'value';
      }
      case 'grant':
      case 'revoke':
      case 'setup': {
        const member = op.kind === 'setup' ? SERVICES[op.member % SERVICES.length]! : MEMBERS[op.member]!;
        const env = envFor(op, shared());
        if (env === undefined) return null;
        const role = op.kind === 'revoke' ? null : op.role;
        return (await grant(op.kind === 'setup' ? actor : ROOT, member, env.projectId, op.onProject ? null : env.id, role)) ? 'access' : null;
      }
      case 'instance-role': {
        const person = PEOPLE[op.member % PEOPLE.length]!;
        if (await attempt(() => root.members.add(person, { role: op.instanceRole, scope: apiScope(op.scope) })) === null) return null;
        const held = people.get(person)!;
        if (!held.active) Object.assign(held, { active: true, grants: new Map() });
        Object.assign(held, { role: op.instanceRole, scope: realScope(op.scope) });
        return 'access';
      }
      case 'role-edit': {
        const instance = op.flag;
        const name = instance ? (['auditor', 'developer', 'admin'] as const)[op.index % 3]! : op.role;
        if (name === 'owner') return null;
        if (await attempt(() => root.roles.set(name, definition(name, op.columns), { instance })) === null) return null;
        (instance ? instanceRoles : roles)[name] = op.columns;
        return 'access';
      }
      case 'protect':
      case 'unprotect': {
        const env = envFor(op, shared());
        if (env === undefined) return null;
        const on = op.kind === 'protect';
        if (await attempt(() => clientOf(actor).environments.protect(pathOf(env), on)) === null) return null;
        if (on) guarded.add(env.key);
        else guarded.delete(env.key);
        return 'access';
      }
      case 'personal-token': {
        const env = envFor(op, shared());
        if (env === undefined) return null;
        return (await issuePersonal(actor, [{ projectId: env.projectId, environmentId: op.onProject ? null : env.id, role: op.role }])) ? 'access' : null;
      }
      case 'service-token':
      case 'binding': {
        const account = SERVICES[op.member % SERVICES.length]!;
        const held = [...accounts.get(account)!.grants];
        const one = pick(held, op.index);
        const places = op.flag || one === undefined ? null : [{ projectId: one[0].split('/')[0]!, environmentId: one[0].split('/')[1] || null, role: one[1] }];
        return (await issueService(actor, account, places, op.kind === 'service-token' ? 'service' : 'binding')) ? 'access' : null;
      }
      case 'remove': {
        const member = MEMBERS[op.member]!;
        if (await attempt(() => root.members.remove(member)) === null) return null;
        const held = member.startsWith('user:') ? people.get(member)! : accounts.get(member)!;
        Object.assign(held, { active: false, grants: new Map(), role: 'member', scope: { projects: 'all', environments: 'all' } });
        // Removal ends every credential that acts as them, for good (personal-tokens.md).
        for (const credential of credentials) if (credential.holder === member) credential.live = false;
        return 'access';
      }
      case 'readd': {
        const member = MEMBERS[op.member]!;
        const held = member.startsWith('user:') ? people.get(member)! : accounts.get(member)!;
        if (held.active) return null;
        if (await attempt(() => root.members.add(member)) === null) return null;
        Object.assign(held, { active: true, grants: new Map() });
        return 'access';
      }
    }
  }

  /**
   * Why a value newly reachable by someone, after the actor changed values
   * rather than access, is one they may make live; null when it is.
   */
  function unjustified(actor: string, text: string, before: readonly Serving[], dormant: readonly Serving[]): string | null {
    if (typed.get(actor)!.has(text)) return null;
    const was = before.filter((serving) => serving.text === text);
    // A sensitive value made reachable as anything looser: an Owner of its project's alone (R30).
    if (was.length > 0 && was.every((serving) => serving.nature === 'sensitive') && servings().some((serving) => serving.text === text && serving.nature !== 'sensitive')) {
      return was.some((serving) => ownsProject(actor, serving.project)) ? null : 'a sensitive value loosened by someone who owns none of its projects';
    }
    if (everKnown.get(actor)!.has(text)) return null;
    const me = sessionReader(actor);
    const has = (env: Env, permission: Permission) => env.owner !== null ? ownsOverlay(me, env) : holds(me, env).has(permission);
    const takes = (nature: Nature): Permission[] => nature === 'plain' ? [READ, USE] : nature === 'secret' ? [READ] : [USE];
    // Served now: reading it as it is served, using it where it is sensitive (R24).
    if (was.some((serving) => takes(serving.nature).some((permission) => has(serving.env, permission) && has(serving.holder, permission)))) return null;
    // An old version, or an archived key's: what it takes to bring back, unless its value is served stricter now.
    for (const old of dormant.filter((each) => each.text === text)) {
      if (was.some((serving) => STRICTNESS[serving.nature] > STRICTNESS[old.nature])) continue;
      if (has(old.env, old.nature === 'plain' ? WRITE : old.nature === 'secret' ? READ : USE)) return null;
    }
    return `made reachable by ${actor}, who could not reach it`;
  }
  const dormantNow = (): Serving[] => envs.flatMap((env) => [...rowsOf(env)].flatMap(([key, row]) => row.versions
    .filter((_, i) => row.archived || row.current !== i)
    .map((version, i) => ({ env, holder: env, key, ...version, project: env.projectId, version: i + 1 }))));

  for (const [index, op] of ops.entries()) {
    const actor = ACTORS[op.actor]!;
    try {
      learn();
      const before = servings();
      const dormant = dormantNow();
      const reach = new Map(readers().map((reader) => [reader.label, allowed(reader, before)]));
      const kind = await apply(op, actor);
      note(`operation ${index}: ${op.kind} by ${actor}: ${kind ?? 'refused or skipped'}`);
      if (kind !== null) applied++;
      if (kind === 'value') {
        const all = servings();
        for (const reader of readers()) {
          for (const text of allowed(reader, all)) {
            if (reach.get(reader.label)?.has(text) ?? true) continue;
            const why = unjustified(actor, text, before, dormant);
            assert.equal(why, null, `${reader.label} newly reaches ${describe(text, all)}: ${why}`);
          }
        }
      }
      await check();
    } catch (error) {
      throw new Error(`after operation ${index}, ${JSON.stringify(op)}: ${(error as Error).message}`, { cause: error });
    }
  }
  return { received, texts, applied };
}

/** A world, its policy and the changes after it, all drawn up front so Hegel shrinks them. */
function drawn(tc: hegel.TestCase) {
  const world = tc.draw(drawWorld({ maxProjects: 2, maxEnvironments: 3, maxSecrets: 8 }));
  const policy = tc.draw(drawPolicy(world.projects.flatMap((project) => project.environments.filter((env) => env.owner === null).map((env) => env.id))));
  const ops = tc.draw(gs.arrays(operation(world.projects.map((project) => project.id)), { maxSize: 6 }));
  return { world, policy, ops };
}

test(`no value reaches a person or a credential the rules forbid it to, by any read, after any change, seed ${settings.seed}`, async () => {
  // What the cases did, together: a run whose changes are all refused, or that hands nobody anything, proves nothing.
  const did = { ops: 0, applied: 0, received: 0 };
  await hegel.testAsync(async (tc) => {
    const { world, policy, ops } = drawn(tc);
    tc.note(`world: ${JSON.stringify(world)}`);
    tc.note(`policy: ${JSON.stringify(policy)}`);
    tc.note(`operations: ${JSON.stringify(ops)}`);
    const outcome = await scenario(world, policy, ops, (text) => tc.note(text));
    did.ops += ops.length;
    did.applied += outcome.applied;
    did.received += [...outcome.received.values()].reduce((n, got) => n + got.size, 0);
  }, settings);
  assert.ok(did.applied * 5 >= did.ops && did.received > 0, `the cases did too little to show anything: ${JSON.stringify(did)}`);
});

const [ADA, BO, CY] = PEOPLE;
const [CI, DEPLOY] = SERVICES;
/** A change with nothing chosen yet. */
const CHANGE: Op = {
  kind: 'write', actor: 0, member: 0, env: 0, source: 0, key: 'DATABASE_URL', nature: 'secret', role: 'viewer', instanceRole: 'member',
  scope: { projects: 'all', environments: 'all' }, columns: { permissions: [], protected: [] }, flag: false, index: 0, onProject: false,
};
const actorOf = (principal: string) => ACTORS.indexOf(principal as typeof ACTORS[number]);
const memberOf = (principal: string) => MEMBERS.indexOf(principal as typeof MEMBERS[number]);
const nobody = (principal: string) => ({ principal, role: 'member' as const, scope: { projects: 'all' as const, environments: 'all' as const }, grants: [] });
const asShipped = (protectedIds: string[] = []): Policy => ({ roles: { ...ROLES }, instanceRoles: { ...INSTANCE_ROLES }, protected: protectedIds });
/** The value first written at `<environment id>/<key>`. */
const valueOf = (outcome: Outcome, at: string) => [...outcome.texts].find(([, where]) => where.startsWith(`${at} `))![0];

test('a fixed world: who receives each nature of value, on each credential, and an Owner of the project loosening a sensitive one', async () => {
  const env = (id: string, projectId: string, slug: string, parentId: string | null = null, owner: string | null = null) => ({ id, projectId, slug, parentId, owner });
  const secret = (id: string, environmentId: string, key: string, nature: Nature, reference: string | null = null) => ({ id, environmentId, key, nature, reference, archived: false });
  const world: World = {
    projects: [
      { id: 'market', slug: 'market', environments: [env('dev', 'market', 'dev'), env('prod', 'market', 'prod'), env('dev-eu', 'market', 'staging', 'dev'), env('dev@ada', 'market', 'dev@ada', 'dev', ADA)] },
      { id: 'billing', slug: 'billing', environments: [env('billing-dev', 'billing', 'dev')] },
    ],
    secrets: [
      secret('s1', 'dev', 'DATABASE_URL', 'secret'),
      secret('s2', 'dev', 'STRIPE_KEY', 'sensitive'),
      secret('s3', 'dev', 'REGION', 'plain'),
      secret('s4', 'prod', 'API_TOKEN', 'secret'),
      secret('s5', 'dev-eu', 'API_TOKEN', 'secret', 's4'),
      secret('s6', 'dev@ada', 'DATABASE_URL', 'secret'),
      secret('s7', 'dev@ada', 'STRIPE_KEY', 'sensitive'),
      secret('s8', 'billing-dev', 'STRIPE_KEY', 'sensitive', 's2'),
    ],
    dismissals: [],
    people: [
      { ...nobody(ADA), grants: [{ projectId: 'market', environmentId: null, role: 'developer' }] },
      { ...nobody(BO), grants: [{ projectId: 'market', environmentId: 'dev', role: 'contributor' }] },
      { ...nobody(CY), grants: [{ projectId: 'market', environmentId: null, role: 'owner' }] },
    ],
    services: [
      { principal: CI, grants: [{ projectId: 'market', environmentId: 'dev', role: 'viewer' }, { projectId: 'market', environmentId: 'dev-eu', role: 'viewer' }] },
      { principal: DEPLOY, grants: [{ projectId: 'billing', environmentId: 'billing-dev', role: 'viewer' }] },
    ],
    credentials: [
      { kind: 'service', account: CI, issuer: CY, scope: [] },
      { kind: 'service', account: CI, issuer: ADA, scope: [{ projectId: 'market', environmentId: 'dev', role: 'viewer' }] },
      { kind: 'binding', account: DEPLOY, issuer: ROOT, scope: [], provider: 'github', subject: 'repo:acme/app:ref:refs/heads/main' },
      { kind: 'personal', issuer: ADA, scope: [{ projectId: 'market', environmentId: 'dev', role: 'viewer' }] },
    ],
  };
  const outcome = await scenario(world, asShipped(['prod']), [
    // Only an Owner of market makes its sensitive value a secret, in place (R30).
    { ...CHANGE, kind: 'mark', actor: actorOf(BO), nature: 'secret', target: { env: 'dev', key: 'STRIPE_KEY' } },
    { ...CHANGE, kind: 'mark', actor: actorOf(CY), nature: 'secret', target: { env: 'dev', key: 'STRIPE_KEY' } },
  ]);
  const [database, stripe, region, token, mine, mySensitive] = ['dev/DATABASE_URL', 'dev/STRIPE_KEY', 'dev/REGION', 'prod/API_TOKEN', 'dev@ada/DATABASE_URL', 'dev@ada/STRIPE_KEY'].map((at) => valueOf(outcome, at));
  const got = (label: string) => [database, stripe, region, token, mine, mySensitive].filter((text) => outcome.received.get(label)?.has(text!));
  // People: an Owner, of the instance or of market, reads no sensitive value nor anyone's `@me`; a Contributor only plain ones;
  // a reference in staging lends prod's value, protected, to staging's readers (R20). Once loosened, dev's readers read STRIPE_KEY.
  assert.deepEqual(got(`session of ${ROOT}`), [database, stripe, region, token]);
  assert.deepEqual(got(`session of ${CY}`), [database, stripe, region, token]);
  assert.deepEqual(got(`session of ${ADA}`), [database, stripe, region, token, mine]);
  assert.deepEqual(got(`session of ${BO}`), [region]);
  // Credentials: the service token an Owner of market issued reads its sensitive value, and prod's through staging; the
  // Developer's reads dev's secret, and its sensitive value only once loosened; ROOT's binding for billing lends nothing of market's sensitive one; Ada's personal token
  // reads dev and her own `@me` values.
  const label = (prefix: string) => [...outcome.received.keys()].find((each) => each.startsWith(prefix))!;
  assert.deepEqual(got(label(`service token 0 of ${CI} by ${CY}`)), [database, stripe, region, token]);
  assert.deepEqual(got(label(`service token 1 of ${CI} by ${ADA}`)), [database, stripe, region]);
  assert.deepEqual(got(label(`binding 2 of ${DEPLOY}`)), [stripe]);
  assert.deepEqual(got(label(`personal token 3 of ${ADA}`)), [database, stripe, region, mine]);
});

test('a value made a secret in place stays one: a writer who never read it brings back no plain version of it, even over a value of their own', async () => {
  const world: World = {
    projects: [{ id: 'market', slug: 'market', environments: [{ id: 'dev', projectId: 'market', slug: 'dev', parentId: null, owner: null }] }],
    secrets: [{ id: 's1', environmentId: 'dev', key: 'REGION', nature: 'plain', reference: null, archived: false }],
    dismissals: [],
    people: [nobody(ADA), nobody(BO), nobody(CY)],
    services: [nobody(CI), nobody(DEPLOY)],
    credentials: [],
  };
  await scenario(world, asShipped(), [
    { ...CHANGE, kind: 'mark', nature: 'secret', target: { env: 'dev', key: 'REGION' } },
    { ...CHANGE, kind: 'grant', member: memberOf(BO), role: 'contributor', target: { env: 'dev' } },
    { ...CHANGE, kind: 'restore', actor: actorOf(BO), index: 0, target: { env: 'dev', key: 'REGION' } },
    // Their own value written over it first, so that the secret is no longer the newest version.
    { ...CHANGE, kind: 'write', actor: actorOf(BO), target: { env: 'dev', key: 'REGION' } },
    { ...CHANGE, kind: 'restore', actor: actorOf(BO), index: 0, target: { env: 'dev', key: 'REGION' } },
  ]);
});

test("a value's old version comes back no looser than it was, nor than it was made since: sensitive past an Owner's loosening, and after a mark", async () => {
  const world: World = {
    projects: [{ id: 'market', slug: 'market', environments: [{ id: 'dev', projectId: 'market', slug: 'dev', parentId: null, owner: null }] }],
    secrets: [
      { id: 's1', environmentId: 'dev', key: 'TOKEN', nature: 'sensitive', reference: null, archived: false },
      { id: 's2', environmentId: 'dev', key: 'HOOK', nature: 'secret', reference: null, archived: false },
    ],
    dismissals: [],
    people: [nobody(ADA), nobody(BO), nobody(CY)],
    services: [{ principal: CI, grants: [{ projectId: 'market', environmentId: 'dev', role: 'viewer' }] }, nobody(DEPLOY)],
    credentials: [{ kind: 'service', account: CI, issuer: ROOT, scope: [{ projectId: 'market', environmentId: 'dev', role: 'viewer' }] }],
  };
  await scenario(world, asShipped(), [
    { ...CHANGE, kind: 'mark', actor: actorOf(ROOT), nature: 'secret', target: { env: 'dev', key: 'TOKEN' } },
    { ...CHANGE, kind: 'write', actor: actorOf(ROOT), target: { env: 'dev', key: 'TOKEN' } },
    { ...CHANGE, kind: 'restore', actor: actorOf(ROOT), index: 0, target: { env: 'dev', key: 'TOKEN' } },
    { ...CHANGE, kind: 'mark', actor: actorOf(ROOT), nature: 'sensitive', target: { env: 'dev', key: 'HOOK' } },
    { ...CHANGE, kind: 'write', actor: actorOf(ROOT), target: { env: 'dev', key: 'HOOK' } },
    { ...CHANGE, kind: 'restore', actor: actorOf(ROOT), index: 0, target: { env: 'dev', key: 'HOOK' } },
  ]);
});

test('a writer who reads no secret restores its current version, which makes no value live, and no old one', async () => {
  const world: World = {
    projects: [{ id: 'market', slug: 'market', environments: [{ id: 'dev', projectId: 'market', slug: 'dev', parentId: null, owner: null }] }],
    secrets: [{ id: 's1', environmentId: 'dev', key: 'PROBE', nature: 'secret', reference: null, archived: false }],
    dismissals: [],
    people: [nobody(ADA), { ...nobody(BO), grants: [{ projectId: 'market', environmentId: 'dev', role: 'contributor' }] }, nobody(CY)],
    services: [nobody(CI), nobody(DEPLOY)],
    credentials: [],
  };
  await scenario(world, asShipped(), [
    { ...CHANGE, kind: 'restore', actor: actorOf(BO), index: 0, target: { env: 'dev', key: 'PROBE' } },
    { ...CHANGE, kind: 'write', actor: actorOf(ROOT), target: { env: 'dev', key: 'PROBE' } },
    { ...CHANGE, kind: 'restore', actor: actorOf(BO), index: 0, target: { env: 'dev', key: 'PROBE' } },
  ]);
});
