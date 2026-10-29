import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';
import { eq, inArray, sql } from 'drizzle-orm';

import { propertySettings } from '../../../scripts/property-settings.ts';
import { MAX_PARENTS, world } from '../../../scripts/properties/domain.ts';
import { openTestDatabase, resetDatabase, testVault, type TestVault } from './api-fixture.ts';
import { dismissedKeys, environments, projects, secretReferences, secrets, secretVersions } from './db/tables.ts';
import type { ApiContext } from '../src/api/context.ts';
import { inheritedRows, resolveKeys } from '../src/api/inheritance.ts';
import { missingKeys } from '../src/api/missing.ts';
import { readableValues } from '../src/api/references.ts';
import { dismissalsAcross, liveKeysIn, places, type ResolvedPath } from '../src/db/queries.ts';

/**
 * Forks resolve their keys three ways (docs/design/forking.md): by name
 * alone, from every environment's live keys and dismissals at once
 * (`resolveKeys`: missing keys, the project list's counts); row by row up
 * the chain (`inheritedRows`: a fork's list); and as a read opens values
 * (`readableValues`: run, export, get). Random worlds of forks, personal
 * configs, archived keys, references and removals, written as rows, hold
 * all three to one rule: a key is settled by the nearest environment of
 * the chain that holds it live or removed it. Worlds written around the
 * app add what it never makes: a parent archived or deleted under a live
 * fork, a chain that loops or runs past `MAX_PARENTS`, and a live key with
 * neither a value nor a reference.
 */

const ROOT = 'admin@acme.example';
const KEYS = ['DATABASE_URL', 'STRIPE_KEY', 'API_TOKEN', 'REGION'] as const;
const settings = propertySettings(120, 10);

type Env = { id: string; projectId: string; project: string; slug: string; parentId: string | null; owner: string | null; archived: boolean; deleted: boolean };
type Row = { id: string; environmentId: string; key: string; folder: string | null; archived: boolean; kind: 'value' | 'reference' | 'hollow'; source: string | null; ended: boolean };
type Removal = { environmentId: string; key: string; restored: boolean };
type Scene = { projects: { id: string; slug: string }[]; envs: Env[]; rows: Row[]; removals: Removal[] };
/** What changes a world around the app: one environment archived or deleted, made to name another parent, or given a key with no value. */
type Distortion = { kind: 'archive' | 'delete' | 'reparent' | 'hollow'; at: number; to: number; key: string };

const distortion = gs.record({
  kind: gs.sampledFrom(['archive', 'delete', 'reparent', 'hollow'] as const),
  at: gs.integers({ minValue: 0, maxValue: 63 }),
  to: gs.integers({ minValue: 0, maxValue: 63 }),
  key: gs.sampledFrom(KEYS),
});

let database: Awaited<ReturnType<typeof openTestDatabase>>;
let vault: TestVault;
let cases = 0;
/** Whether the vault has logged anything about this case's places. */
let sealed = false;
before(async () => {
  database = await openTestDatabase();
  await resetDatabase(database.owner);
  vault = testVault([ROOT], {}, { kek: Buffer.alloc(32, 31) });
});
after(async () => { await database.close(); });

/**
 * Empty what a case writes. Once the vault has sealed references, its log
 * names the case's places, and its members are bound to that log: then
 * everything goes, the vault's members too, and it starts afresh.
 */
async function clear(): Promise<void> {
  const db = database.owner;
  if (sealed) {
    sealed = false;
    return resetDatabase(db);
  }
  await db.delete(dismissedKeys);
  await db.update(secrets).set({ currentVersionId: null });
  await db.delete(secretVersions);
  await db.delete(secrets);
  await db.delete(environments);
  await db.delete(projects);
}

/**
 * A case's world, from the domain's: ids readable and fresh for each case,
 * then archived and deleted places as the app leaves them (a fork goes
 * before its parent), and the distortions to make around the app, if any.
 */
function sceneOf(tc: hegel.TestCase): { scene: Scene; distortions: Distortion[] } {
  const drawn = tc.draw(world({ maxProjects: 2, maxEnvironments: 6, maxSecrets: 12 }));
  const drawnIds = [...drawn.projects.map((project) => project.id), ...drawn.projects.flatMap((project) => project.environments.map((environment) => environment.id)), ...drawn.secrets.map((secret) => secret.id)];
  const run = (++cases).toString(16).padStart(8, '0');
  let n = 0;
  const ids = new Map(drawnIds.map((id) => [id, `${run}-0000-4000-8000-${(++n).toString(16).padStart(12, '0')}`]));
  const scene: Scene = { projects: drawn.projects.map((project) => ({ id: ids.get(project.id)!, slug: project.slug })), envs: [], rows: [], removals: [] };
  for (const project of drawn.projects) {
    for (const environment of project.environments) {
      const parent = scene.envs.find((each) => each.id === ids.get(environment.parentId ?? ''));
      const id = ids.get(environment.id)!;
      // An Owner's place state: live mostly, archived, or deleted, never more alive than its parent.
      const state = Math.max(tc.draw(gs.sampledFrom([0, 0, 0, 0, 0, 0, 1, 2])), parent === undefined ? 0 : parent.deleted ? 2 : parent.archived ? 1 : 0);
      scene.envs.push({
        id, projectId: ids.get(project.id)!, project: project.slug,
        slug: environment.slug,
        parentId: parent?.id ?? null, owner: environment.owner, archived: state >= 1, deleted: state === 2,
      });
    }
  }
  for (const secret of drawn.secrets) {
    const reference = secret.reference === null ? null : ids.get(secret.reference)!;
    scene.rows.push({
      id: ids.get(secret.id)!, environmentId: ids.get(secret.environmentId)!, key: secret.key,
      folder: tc.draw(gs.sampledFrom([null, 'database', 'payments'])), archived: secret.archived,
      kind: reference === null ? 'value' : 'reference', source: reference,
      ended: reference !== null && tc.draw(gs.integers({ minValue: 0, maxValue: 3 })) === 0,
    });
  }
  for (const dismissal of drawn.dismissals) {
    scene.removals.push({ environmentId: ids.get(dismissal.environmentId)!, key: dismissal.key, restored: tc.draw(gs.integers({ minValue: 0, maxValue: 4 })) === 0 });
  }
  const distortions = tc.draw(gs.oneOf(gs.just([] as Distortion[]), gs.arrays(distortion, { minSize: 1, maxSize: 3 })));
  return { scene, distortions };
}

/** Apply distortions to the model, as `write` applies them to the rows afterwards. */
function distort(scene: Scene, distortions: readonly Distortion[]): void {
  for (const change of distortions) {
    const env = scene.envs[change.at % scene.envs.length]!;
    if (change.kind === 'archive') env.archived = true;
    if (change.kind === 'delete') env.deleted = true;
    if (change.kind === 'reparent') {
      // A personal config keeps its parent: its owner is unique there.
      const others = scene.envs.filter((each) => each.projectId === env.projectId && each.id !== env.id);
      if (env.owner === null && others.length > 0) env.parentId = others[change.to % others.length]!.id;
    }
    if (change.kind === 'hollow' && !scene.rows.some((row) => row.environmentId === env.id && row.key === change.key)) {
      scene.rows.push({ id: `${env.id.slice(0, 24)}${(scene.rows.length + 0x800).toString(16).padStart(12, '0')}`, environmentId: env.id, key: change.key, folder: null, archived: false, kind: 'hollow', source: null, ended: false });
    }
  }
}

const tombstoned = (env: Env) => (env.deleted ? `${env.slug}~deleted-2026-10-24` : env.slug);

/**
 * Write the world: rows as the app leaves them, every key live and every
 * place standing while the vault seals the references (and breaks the
 * ended ones), then what archives, deletes and rewires them.
 */
async function write(scene: Scene, app: Scene): Promise<void> {
  const db = database.owner;
  // The vault open first: under 0.15's log, cut over before these rows, which stay the app's around it (0.14's).
  await vault.about();
  await db.insert(projects).values(scene.projects.map((project) => ({ id: project.id, slug: project.slug, name: project.slug })));
  await db.insert(environments).values(app.envs.map((env) => ({ id: env.id, projectId: env.projectId, slug: env.slug, name: env.slug, parentId: env.parentId, owner: env.owner })));
  const rows = scene.rows;
  if (rows.length > 0) {
    const projectOf = new Map(scene.envs.map((env) => [env.id, env.projectId]));
    await db.insert(secrets).values(rows.map((row) => ({ id: row.id, projectId: projectOf.get(row.environmentId)!, environmentId: row.environmentId, key: row.key, folder: row.folder })));
  }
  const values = rows.filter((row) => row.kind === 'value');
  if (values.length > 0) {
    // A plain value, as the app stores one: its envelope is never opened here.
    await db.insert(secretVersions).values(values.map((row, i) => ({
      id: `${row.id.slice(0, 24)}${(0x1000 + i).toString(16).padStart(12, '0')}`, secretId: row.id, version: 1, envelopeVersion: 1, ciphertext: Buffer.alloc(8), iv: Buffer.alloc(12), authTag: Buffer.alloc(16),
      wrappedDek: Buffer.alloc(40), kekProvider: 'local', kekId: 'test-kek-1', kekVersion: '1', createdBy: `user:${ROOT}`, plaintext: row.key.toLowerCase(),
    })));
    await db.update(secrets)
      .set({ currentVersionId: sql`(SELECT ${secretVersions.id} FROM ${secretVersions} WHERE ${secretVersions.secretId} = ${secrets.id})`, currentVersion: 1 })
      .where(inArray(secrets.id, values.map((row) => row.id)));
  }
  if (scene.removals.length > 0) {
    await db.insert(dismissedKeys).values(scene.removals.map((removal) => ({
      environmentId: removal.environmentId, key: removal.key, dismissedBy: `user:${ROOT}`,
      restoredAt: removal.restored ? new Date() : null, restoredBy: removal.restored ? `user:${ROOT}` : null,
    })));
  }
  const references = rows.filter((row) => row.kind === 'reference');
  if (references.length > 0) {
    const envOf = new Map(scene.envs.map((env) => [env.id, env]));
    const items = references.map((row) => {
      const holder = envOf.get(row.environmentId)!;
      return { id: row.id, holder: { projectId: holder.projectId, environmentId: holder.id, secretId: row.id, path: `${holder.project}/${holder.slug}/${row.key}` }, source: { secretId: row.source! } };
    });
    sealed = true;
    const made = await vault.reference({ principal: `user:${ROOT}`, items });
    if (!made.ok) throw new Error(`the vault refused a reference: ${JSON.stringify(made.refusal)}`);
    await db.insert(secretReferences).values(references.map((row, i) => {
      const source = rows.find((each) => each.id === row.source)!;
      return {
        id: row.id, projectId: items[i]!.holder.projectId, environmentId: row.environmentId, secretId: row.id,
        sourceProjectId: envOf.get(source.environmentId)!.projectId, sourceEnvironmentId: source.environmentId, sourceSecretId: source.id,
        createdSeq: BigInt(made.seqs[i]!), createdBy: `user:${ROOT}`,
      };
    }));
    const ended = references.flatMap((row, i) => (row.ended ? [{ reference: row.id, seq: made.seqs[i]! }] : []));
    if (ended.length > 0) {
      const broken = await vault.endReferences({ principal: `user:${ROOT}`, reason: 'broken', items: ended });
      if (!broken.ok) throw new Error(`the vault refused to break a reference: ${JSON.stringify(broken.refusal)}`);
    }
  }
  const archived = rows.filter((row) => row.archived);
  if (archived.length > 0) await db.update(secrets).set({ archivedAt: new Date() }).where(inArray(secrets.id, archived.map((row) => row.id)));
  for (const env of scene.envs) {
    const was = app.envs.find((each) => each.id === env.id)!;
    if (env.archived || env.deleted || env.parentId !== was.parentId) {
      await db.update(environments).set({ archivedAt: env.archived ? new Date() : null, slug: tombstoned(env), parentId: env.parentId }).where(eq(environments.id, env.id));
    }
  }
}

/** A fork's chain, nearest parent first, or `loops` for one that names a place twice or more than `MAX_PARENTS` (forking.md, section 1). */
function chainOf(scene: Scene, env: Env): Env[] | 'loops' {
  const parents: Env[] = [];
  for (let at = env.parentId; at !== null;) {
    if (at === env.id || parents.some((parent) => parent.id === at) || parents.length === MAX_PARENTS) return 'loops';
    const parent = scene.envs.find((each) => each.id === at)!;
    parents.push(parent);
    at = parent.parentId;
  }
  return parents;
}

/**
 * Settle each key down `layers`, nearest first: the first that holds it
 * live settles it there, the first that removed it settles it as absent.
 * A layer's own row beats its own removal ("a live row of the fork's own
 * beats its dismissal").
 */
function settle(scene: Scene, layers: readonly Env[]): Map<string, Row> {
  const held = new Map<string, Row>();
  const settled = new Set<string>();
  for (const layer of layers) {
    for (const row of scene.rows) {
      if (row.environmentId !== layer.id || row.archived || settled.has(row.key)) continue;
      held.set(row.key, row);
      settled.add(row.key);
    }
    for (const removal of scene.removals) if (removal.environmentId === layer.id && !removal.restored) settled.add(removal.key);
  }
  return held;
}

/**
 * What a read of `env` opens and refuses: the keys its chain settles, up
 * to the first parent archived or deleted, where it refuses saying so; or
 * nothing, for a chain that loops (forking.md, "The parent is archived or
 * deleted", and section 1).
 */
function readOf(scene: Scene, env: Env): { held: Map<string, Row>; refusal: string | null } {
  const here = `${env.project}/${env.slug}`;
  const chain = chainOf(scene, env);
  if (chain === 'loops') return { held: new Map(), refusal: `${here}'s parents loop or run past ${MAX_PARENTS}: it was made around coffre` };
  const gone = chain.findIndex((parent) => parent.archived || parent.deleted);
  const layers = [env, ...(gone === -1 ? chain : chain.slice(0, gone))];
  const stop = gone === -1 ? null : chain[gone]!;
  return {
    held: settle(scene, layers),
    refusal: stop === null ? null : `${here} inherits from ${env.project}/${tombstoned(stop)}, which is ${stop.deleted ? 'deleted' : 'archived'}`,
  };
}

/**
 * The keys `resolveKeys` gives an environment: its chain among the
 * standing environments, archived ones included, followed no further than
 * `MAX_PARENTS` (inheritance.ts: a loop is followed that far, and a read of
 * it refuses), each key settled as a read settles it.
 */
function keysOf(scene: Scene, env: Env): Map<string, Row> {
  const layers = [env];
  for (let at = env.parentId; at !== null && layers.length <= MAX_PARENTS;) {
    const parent = scene.envs.find((each) => each.id === at)!;
    if (parent.deleted) break;
    layers.push(parent);
    at = parent.parentId;
  }
  return settle(scene, layers);
}

/** Whether a reference reads: not broken, and its source a live key of a standing place. */
function opens(scene: Scene, row: Row): boolean {
  if (row.kind !== 'reference') return row.kind === 'value';
  const source = scene.rows.find((each) => each.id === row.source)!;
  const place = scene.envs.find((each) => each.id === source.environmentId)!;
  return !row.ended && !source.archived && !place.archived && !place.deleted;
}

/** Whether a read of `env` settles every key without refusing: its chain is the app's, every parent live. */
const clean = (scene: Scene, env: Env) => !env.archived && !env.deleted && readOf(scene, env).refusal === null;

const pathOf = (scene: Scene, env: Env): ResolvedPath => ({
  project: { id: env.projectId, slug: env.project, name: env.project, archivedAt: null },
  environment: {
    id: env.id, slug: env.slug, name: env.slug, archivedAt: null, parentId: env.parentId,
    parentSlug: scene.envs.find((each) => each.id === env.parentId)?.slug ?? null, owner: env.owner,
  },
  secret: null,
});

const where = (held: ReadonlyMap<string, { environmentId: string }>) => Object.fromEntries([...held].map(([key, row]) => [key, row.environmentId]).sort());

async function check(scene: Scene): Promise<void> {
  const db = database.runtime;
  const standing = (await places(db)).flatMap((project) => project.environments);
  const ids = standing.map((env) => env.id);
  const [live, removed] = await Promise.all([liveKeysIn(db, ids), dismissalsAcross(db, ids)]);
  const resolved = resolveKeys(standing, live, removed);
  assert.deepEqual(new Set(standing.map((env) => env.id)), new Set(scene.envs.filter((env) => !env.deleted).map((env) => env.id)), 'the standing environments are the undeleted ones');

  for (const env of scene.envs.filter((each) => !each.deleted)) {
    const named = `${env.project}/${env.slug}`;
    // The keys by name, as the missing keys and the counts see them.
    const expected = keysOf(scene, env);
    assert.deepEqual(where(resolved.get(env.id)!), where(expected), `resolveKeys of ${named}`);
    assert.deepEqual(Object.fromEntries([...resolved.get(env.id)!].map(([key, held]) => [key, held.folder])), Object.fromEntries([...expected].map(([key, row]) => [key, row.folder])), `the folders resolveKeys files ${named}'s keys in`);
    if (env.archived) continue;

    // The read, as run, export and get open it.
    const read = readOf(scene, env);
    const opened = await readableValues(db, pathOf(scene, env), { projectId: env.projectId, environmentId: env.id });
    const got = new Map<string, { environmentId: string; opens: boolean }>();
    for (const item of opened.items) {
      assert.equal(got.has(item.key), false, `${named} reads ${item.key} once`);
      got.set(item.key, { environmentId: item.parent?.environmentId ?? env.id, opens: true });
      if (item.parent !== undefined) {
        assert.equal(item.through, env.id, `an inherited ${item.key} is read through ${named}`);
        assert.equal(item.parent.slug, scene.envs.find((each) => each.id === item.parent!.environmentId)!.slug);
      }
    }
    for (const unread of [...opened.unreadable, ...opened.hollow]) {
      if (unread.key === undefined) continue;
      assert.equal(got.has(unread.key), false, `${named} settles ${unread.key} once`);
      got.set(unread.key, { environmentId: unread.parent?.environmentId ?? env.id, opens: false });
    }
    assert.deepEqual(
      Object.fromEntries([...got].sort()),
      Object.fromEntries([...read.held].map(([key, row]) => [key, { environmentId: row.environmentId, opens: opens(scene, row) }]).sort()),
      `what a read of ${named} opens, and where each key is held`,
    );
    assert.deepEqual(opened.unreadable.filter((unread) => unread.key === undefined).map((unread) => unread.reason), read.refusal === null ? [] : [read.refusal], `why a read of ${named} refuses whole`);

    // The list's rows, as a fork's page shows what it inherits.
    const rows = await inheritedRows(db, env.id);
    const chain = chainOf(scene, env);
    if (chain === 'loops') {
      assert.equal(rows, null, `inheritedRows refuses ${named}'s chain`);
      continue;
    }
    assert.notEqual(rows, null);
    if (read.refusal !== null) continue;
    assert.deepEqual(rows!.parents.map((parent) => parent.id), chain.map((parent) => parent.id), `${named}'s parents, nearest first`);
    const own = scene.rows.filter((row) => row.environmentId === env.id && !row.archived);
    const listed = new Map(own.map((row) => [row.key, row.environmentId]));
    for (const [key, held] of rows!.held) if (!listed.has(key) && !rows!.removed.has(key)) listed.set(key, held.from.id);
    assert.deepEqual(Object.fromEntries([...listed].sort()), where(read.held), `${named}'s own keys and those inheritedRows passes down`);
    // Clean, the three agree: by name, row by row, and as read.
    assert.deepEqual(where(resolved.get(env.id)!), where(read.held), `resolveKeys and the read of ${named}`);
  }

  // Missing keys: what this environment lacks that a live sibling resolves to, its own forks and personal configs aside.
  // A project whose every live environment reads clean: one that refuses resolves to nothing a read would agree with.
  const settled = (env: Env) => scene.envs.every((other) => other.projectId !== env.projectId || other.archived || other.deleted || clean(scene, other));
  for (const env of scene.envs.filter((each) => !each.archived && !each.deleted && settled(each))) {
    const siblings = scene.envs.filter((other) => other.projectId === env.projectId && other.id !== env.id && !other.archived && !other.deleted && other.owner === null && !below(scene, env, other));
    const has = new Set([...readOf(scene, env).held.keys(), ...scene.rows.filter((row) => row.environmentId === env.id).map((row) => row.key)]);
    const found = new Map<string, { in: string[]; folders: Set<string | null> }>();
    for (const other of siblings) {
      for (const [key, row] of readOf(scene, other).held) {
        if (has.has(key)) continue;
        const entry = found.get(key) ?? { in: [], folders: new Set() };
        entry.in.push(other.slug);
        entry.folders.add(row.folder);
        found.set(key, entry);
      }
    }
    const dismissed = new Set(scene.removals.filter((removal) => removal.environmentId === env.id && !removal.restored).map((removal) => removal.key));
    const expected = [...found].sort(([a], [b]) => (a < b ? -1 : 1)).map(([key, entry]) => ({ key, in: entry.in.sort(), folder: entry.folders.size === 1 ? [...entry.folders][0]! : null }));
    const got = await missingKeys({ db } as ApiContext, pathOf(scene, env));
    assert.deepEqual(got.missing, expected.filter((entry) => !dismissed.has(entry.key)), `the keys ${env.project}/${env.slug} is missing`);
    assert.deepEqual(got.dismissed.map((entry) => entry.key), expected.filter((entry) => dismissed.has(entry.key)).map((entry) => entry.key), `the missing keys ${env.project}/${env.slug} dismissed`);
  }
}

/** Whether `other` is below `env`: a fork of it, or of one of its forks. */
function below(scene: Scene, env: Env, other: Env): boolean {
  const seen = new Set<string>();
  for (let at = other.parentId; at !== null && !seen.has(at); at = scene.envs.find((each) => each.id === at)?.parentId ?? null) {
    if (at === env.id) return true;
    seen.add(at);
  }
  return false;
}

test(`a fork's keys are the same by name, row by row and as read, each from the nearest environment that holds or removed it, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const { scene, distortions } = sceneOf(tc);
  const app = structuredClone(scene);
  distort(scene, distortions);
  tc.note(`world: ${JSON.stringify(scene)}`);
  tc.note(`distortions: ${JSON.stringify(distortions)}`);
  await clear();
  await write(scene, app);
  await check(scene);
}, settings));
