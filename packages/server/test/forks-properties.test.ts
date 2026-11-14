// A fork's keys are worked out twice: by the app, from every environment's
// key names and dismissals at once (`resolveKeys` in routes/keys.ts: the
// list and the missing keys), and by the vault as a use opens values. Random
// worlds of forks, a personal config, overrides, resets, references and
// dismissals, some restored, written as the vault's rows, hold both to one
// rule (docs/design/0.16.md): a key is settled by the nearest environment of
// the chain that holds it live, or dismissed it. And an environment misses
// what its project's other live environments hold, apart from its own
// forks and the personal configs, unless it holds or inherits it, or once
// held it.
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { credential, emptyDatabase, environment, principal, project, role, rows, secret, user, value, write } from '@coffre/vault/testing';

import { propertySettings } from '../../../scripts/property-settings.ts';
import { openApp } from './app-fixture.ts';

const app = await openApp();
const { world } = app;
after(() => app.close());

const settings = propertySettings(60, 10);
const KEYS = ['A', 'B', 'C', 'D'] as const;
const SLUGS = ['e0', 'e1', 'e2', 'e3', 'e4'] as const;
const root = user('root');

/** What an environment holds of a key: nothing, a value, one archived (a reset, in a fork), or a reference to billing's key of that name. */
type Held = 'none' | 'value' | 'archived' | 'reference';
/** What it says of a key's dismissal: none, dismissed, or dismissed and restored since. */
type Dismissal = 'none' | 'dismissed' | 'restored';
type Env = { slug: string; parent: number | null; personal: boolean; held: Record<string, Held>; dismissals: Record<string, Dismissal> };

const held = gs.sampledFrom(['none', 'none', 'value', 'archived', 'reference'] as const);
const ownHeld = gs.sampledFrom(['none', 'none', 'value', 'archived'] as const);
const dismissal = gs.sampledFrom(['none', 'dismissed', 'dismissed', 'restored'] as const);

/** Up to five environments, each a root or a fork of an earlier one, two parents at most (`depth` counts the environment itself), and maybe root's personal config of one. */
function sceneOf(tc: hegel.TestCase): Env[] {
  const count = tc.draw(gs.integers({ minValue: 1, maxValue: SLUGS.length }));
  const envs: Env[] = [];
  const depth = (at: number | null): number => (at === null ? 0 : 1 + depth(envs[at]!.parent));
  // A personal config holds values only, no reference.
  const keyed = (personal = false) => ({
    held: Object.fromEntries(KEYS.map((key) => [key, tc.draw(personal ? ownHeld : held)])),
    dismissals: Object.fromEntries(KEYS.map((key) => [key, tc.draw(dismissal)])),
  });
  for (let i = 0; i < count; i++) {
    // A fork of the one just made, most often: chains three deep are where a parent's dismissal counts.
    const parent = i === 0 ? null : tc.draw(gs.sampledFrom([null, i - 1, i - 1, ...envs.keys()]));
    envs.push({ slug: SLUGS[i]!, parent: parent !== null && depth(parent) > 2 ? null : parent, personal: false, ...keyed() });
  }
  const mine = tc.draw(gs.sampledFrom([null, ...envs.keys()]));
  if (mine !== null && depth(mine) <= 2) envs.push({ slug: `${envs[mine]!.slug}-root`, parent: mine, personal: true, ...keyed(true) });
  return envs;
}

/** The chain a use reads: the environment, then its parents, nearest first. */
const chainOf = (envs: readonly Env[], env: Env): Env[] => [env, ...(env.parent === null ? [] : chainOf(envs, envs[env.parent]!))];

/** What a use of the environment is given, by key: the nearest environment that holds the key live or dismissed it settles it. */
function resolved(envs: readonly Env[], env: Env): Map<string, string> {
  const found = new Map<string, string>();
  for (const key of KEYS) {
    for (const layer of chainOf(envs, env)) {
      const holding = layer.held[key];
      if (holding === 'value') found.set(key, `${layer.slug}-${key}`);
      if (holding === 'reference') found.set(key, `billing-${key}`);
      if (holding === 'value' || holding === 'reference') break;
      // An environment's own dismissal is of what it inherits: at the chain's root, it removes nothing.
      if (layer.dismissals[key] === 'dismissed' && layer.parent !== null) break;
    }
  }
  return found;
}

/** What a fork lists as removed: a key it dismissed and holds no live value or reference of, of which a parent has a row. */
function removedOf(envs: readonly Env[], env: Env): string[] {
  const parents = chainOf(envs, env).slice(1);
  const live = (holding: Held | undefined) => holding === 'value' || holding === 'reference';
  return KEYS.filter((key) => env.dismissals[key] === 'dismissed' && !live(env.held[key]) && parents.some((parent) => parent.held[key] !== 'none'));
}

/** What the environment misses, each key with where it is held, and which of those it dismissed itself. */
function missingOf(envs: readonly Env[], env: Env): { missing: [string, string[]][]; dismissed: [string, string[]][] } {
  const below = (other: Env): boolean => other.parent !== null && (envs[other.parent] === env || below(envs[other.parent]!));
  const has = new Set([...KEYS.filter((key) => env.held[key] !== 'none'), ...resolved(envs, env).keys()]);
  const lacking = new Map<string, string[]>();
  for (const other of envs) {
    if (other === env || other.personal || below(other)) continue;
    for (const key of resolved(envs, other).keys()) if (!has.has(key)) lacking.set(key, [...(lacking.get(key) ?? []), other.slug]);
  }
  const sorted = [...lacking].map(([key, where]): [string, string[]] => [key, where.sort()]).sort(([a], [b]) => (a < b ? -1 : 1));
  return { missing: sorted.filter(([key]) => env.dismissals[key] !== 'dismissed'), dismissed: sorted.filter(([key]) => env.dismissals[key] === 'dismissed') };
}

async function written(envs: readonly Env[]): Promise<void> {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const [market, billing] = [project('market'), project('billing')];
  const source = environment(billing, 'prod');
  const sources = Object.fromEntries(KEYS.map((key) => [key, value(world, secret(source, key), `billing-${key}`)]));
  const made: ReturnType<typeof environment>[] = [];
  for (const env of envs) {
    made.push(environment(market, env.personal ? `${env.slug.slice(0, 2)}-p-0a0b0c0d` : env.slug, { parentId: env.parent === null ? null : made[env.parent]!.id, owner: env.personal ? root : null }));
  }
  const keys = envs.flatMap((env, i) => KEYS.flatMap((key) => {
    const place = made[i]!;
    switch (env.held[key]) {
      case 'value': return [value(world, secret(place, key), `${env.slug}-${key}`)];
      case 'archived': return [value(world, secret(place, key, { archivedAt: new Date(0) }), `${env.slug}-${key}-archived`)];
      case 'reference': return [secret(place, key, { sourceId: sources[key]!.id })];
      default: return [];
    }
  }));
  const dismissals = envs.flatMap((env, i) => KEYS.flatMap((key) => {
    const said = env.dismissals[key];
    if (said === 'none') return [];
    const at = new Date(0);
    return [{ environmentId: made[i]!.id, key, dismissedAt: at, dismissedBy: root, restoredAt: said === 'restored' ? at : null, restoredBy: said === 'restored' ? root : null }];
  }));
  await write(world,
    ...rows('projects', market, billing), ...rows('environments', source, ...made),
    ...rows('secrets', ...Object.values(sources), ...keys), ...rows('dismissedKeys', ...dismissals),
    ...rows('roles', role(true, 'owner', ['secret.read', 'secret.use', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage', 'audit.read']), role(true, 'member', [])),
    ...rows('principals', principal(root, { role: 'owner' })), ...rows('credentials', credential('root-cli', root)));
}

const call = async (method: string, path: string, body?: unknown) => {
  const got = await app.request(`/api${path}`, { method, headers: { authorization: 'Bearer root-cli' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const answer = (await got.json()) as Record<string, unknown>;
  assert.equal(got.status, 200, `${method} ${path}: ${JSON.stringify(answer)}`);
  return answer;
};

async function check(envs: readonly Env[]): Promise<void> {
  for (const env of envs) {
    const path = env.personal ? `market/${envs[env.parent!]!.slug}@me` : `market/${env.slug}`;
    const expected = resolved(envs, env);
    const read = (await call('POST', '/reveals', { path })).values as Record<string, string>;
    assert.deepEqual(new Map(Object.entries(read).sort()), new Map([...expected].sort()), `${path}: a use`);
    // The list shows a removal too, apart, while a parent has a row of the key: to be restored.
    const listed = (await call('GET', `/secrets/${path}`)).keys as { key: string; archived: boolean; parent: { state: string } | null }[];
    const removal = (key: { parent: { state: string } | null }) => key.parent?.state === 'removed';
    assert.deepEqual(listed.filter((key) => !key.archived && !removal(key)).map((key) => key.key).sort(), [...expected.keys()].sort(), `${path}: the list`);
    assert.deepEqual(listed.filter(removal).map((key) => key.key).sort(), removedOf(envs, env), `${path}: the list's removals`);
    const { missing, dismissed } = (await call('GET', `/projects/${path}/missing`)) as { missing: { key: string; in: string[] }[]; dismissed: { key: string; in: string[] }[] };
    const said = (entries: { key: string; in: string[] }[]) => entries.map((entry): [string, string[]] => [entry.key, entry.in]);
    assert.deepEqual({ missing: said(missing), dismissed: said(dismissed) }, missingOf(envs, env), `${path}: the missing keys`);
  }
}

test(`a fork's keys are the same listed, missed and used: each from the nearest environment that holds it live or dismissed it, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const envs = sceneOf(tc);
  tc.note(`world: ${JSON.stringify(envs)}`);
  await written(envs);
  await check(envs);
}, settings));
