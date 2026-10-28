import assert from 'node:assert/strict';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { EVERYWHERE, type CallerKind, type InstanceRole } from '@coffre/core/access';
import type { Purpose } from '@coffre/core/vault';

import { refreshMs, USE_AHEAD_MS, USE_DEADLINE_MS, type BulkRows } from '../src/bulk.ts';
import { decideUse, useEnvironments, type UseCode, type UseRequest, type UseView } from '../src/decide.ts';
import { limitOp, objectKey, POLICY_REF, ROLES_REF, sealOf, type Input, type Nature, type Op, type Ref } from '../src/inputs.ts';
import { emptyReplay, readUse, replay } from '../src/log-replay.ts';
import { propertySettings } from '../../../scripts/property-settings.ts';
import { SEAL_KEYS, World } from './world.ts';

// The 0.15 plan's PR 3 properties, on random logs over a small instance:
//
// 1. A use decided on the rows equals the replay's decision whenever the rows
//    are the replay's (R53: the log records requests, and every input is sealed).
// 2. Rows that are not the replay's change a decision only to `stale` or
//    `tampered`, and any such row among the inputs a use weighs makes it one.
// 3. The bulk cap: over requests decided in number order whose times run up to
//    the deadline out of order, no rolling window releases more than `count`
//    distinct keys (HotPathOneClock's BulkCapHolds).

const settings = propertySettings(200);

const PROJECTS = ['00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000b'];
const ENVIRONMENTS = [0, 1, 2, 3, 4, 5].map((n) => `00000000-0000-4000-8000-0000000000e${n}`);
const KEYS = [0, 1, 2, 3, 4, 5, 6, 7].map((n) => `00000000-0000-4000-8001-0000000000a${n}`);
const CREDENTIALS = [0, 1, 2, 3, 4].map((n) => `00000000-0000-4000-8002-0000000000c${n}`);
const PRINCIPALS = ['user:ada@acme.example', 'user:bo@acme.example', 'token:ci', 'token:deploy'];
const ROLE_NAMES = ['viewer', 'contributor', 'developer', 'maintainer', 'owner', 'auditor', 'custom'];
const PURPOSES: Purpose[] = ['reveal', 'run', 'compare', 'copy', 'use', 'expose'];
const NATURES: Nature[] = ['plain', 'secret', 'sensitive'];
const WRAPPED = { kekProvider: 'local', kekId: 'k1', kekVersion: '1', bytes: 'AAAA' };
/** A plain value's digest, in the shape `plainDigest` makes (base64 of 32 bytes). */
const PLAIN_DIGEST = 'X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=';

const pick = <T>(tc: hegel.TestCase, items: readonly T[]): T => tc.draw(gs.sampledFrom(items));
const maybe = <T>(tc: hegel.TestCase, items: readonly T[]): T | null => (tc.draw(gs.booleans()) ? pick(tc, items) : null);

/** One change, drawn over the instance: applied if it does something, as the change path would log it. */
function drawChange(tc: hegel.TestCase): [Ref, Op] {
  const place = () => {
    const projectId = pick(tc, PROJECTS);
    return { projectId, environmentId: maybe(tc, ENVIRONMENTS), environmentSlug: null };
  };
  const role = (): InstanceRole => pick(tc, ['member', 'member', 'developer', 'owner', 'auditor'] as const);
  switch (tc.draw(gs.integers({ minValue: 0, maxValue: 13 }))) {
    case 0: return [{ kind: 'principal', id: pick(tc, PRINCIPALS) }, { op: 'member.add', role: role(), scope: EVERYWHERE }];
    case 1: return [{ kind: 'principal', id: pick(tc, PRINCIPALS) }, { op: tc.draw(gs.booleans()) ? 'member.remove' : 'member.restore', role: role(), scope: EVERYWHERE } as Op];
    case 2: case 3: return [{ kind: 'principal', id: pick(tc, PRINCIPALS) }, { op: 'access.grant', grant: { ...place(), role: pick(tc, ROLE_NAMES), expiresAt: maybe(tc, [500, 5_000, 50_000]) } }];
    case 4: return [{ kind: 'principal', id: pick(tc, PRINCIPALS) }, { op: 'access.revoke', place: place() }];
    case 5: {
      const principal = pick(tc, PRINCIPALS);
      const caller: CallerKind = principal.startsWith('user:') ? 'person' : pick(tc, ['bearer', 'workload'] as const);
      const scope = caller === 'workload' || tc.draw(gs.booleans())
        ? [{ projectId: pick(tc, PROJECTS), environmentId: maybe(tc, ENVIRONMENTS), role: pick(tc, ROLE_NAMES), ...(tc.draw(gs.booleans()) ? { sensitive: true } : {}),
          ...(caller === 'workload' ? { reads: tc.draw(gs.booleans()) ? '*' as const : [pick(tc, KEYS)] } : {}) }]
        : null;
      return [{ kind: 'credential', id: pick(tc, CREDENTIALS) }, { op: 'credential.issue', principal, caller, scope, expiresAt: maybe(tc, [2_000, 20_000]) }];
    }
    case 6: return [{ kind: 'credential', id: pick(tc, CREDENTIALS) }, { op: 'credential.revoke' }];
    case 7: case 8: {
      const environment = pick(tc, ENVIRONMENTS);
      const reference = tc.draw(gs.integers({ minValue: 0, maxValue: 4 })) === 0;
      const nature = pick(tc, NATURES);
      // As `secretObject` makes them: a plain value with its text's digest and no key, a reference with neither.
      const plain = !reference && nature === 'plain';
      return [{ kind: 'secret', id: pick(tc, KEYS) }, {
        op: 'secret.write', projectId: PROJECTS[ENVIRONMENTS.indexOf(environment) % 2]!, environmentId: environment, version: `v${tc.draw(gs.integers({ minValue: 0, maxValue: 99 }))}`,
        nature, key: reference || plain ? null : WRAPPED, digest: plain ? PLAIN_DIGEST : null, source: reference ? pick(tc, KEYS) : null, reference: reference ? 'r' : null,
      }];
    }
    case 9: return [{ kind: 'secret', id: pick(tc, KEYS) }, { op: 'secret.delete' }];
    case 10: {
      const id = pick(tc, ENVIRONMENTS);
      const n = ENVIRONMENTS.indexOf(id);
      // Even ones are top-level; odd ones forks of the one before, or a personal config.
      const parentId = n % 2 === 1 ? ENVIRONMENTS[n - 1]! : null;
      return [{ kind: 'environment', id }, {
        op: 'environment.create', projectId: PROJECTS[n % 2]!, slug: pick(tc, ['dev', 'prod', 'fork']),
        owner: parentId !== null && tc.draw(gs.booleans()) ? pick(tc, PRINCIPALS.slice(0, 2)) : null, parentId, protected: tc.draw(gs.booleans()),
      }];
    }
    case 11: {
      const ops: Op[] = [{ op: 'environment.delete' }, { op: 'environment.protect', protected: tc.draw(gs.booleans()) }, { op: 'environment.rename', slug: pick(tc, ['dev', 'prod', 'staging']) },
        { op: 'environment.archive', archived: tc.draw(gs.booleans()) }];
      return [{ kind: 'environment', id: pick(tc, ENVIRONMENTS) }, pick(tc, ops)];
    }
    case 12: return [ROLES_REF, {
      op: 'role.define', table: 'roles', role: pick(tc, ROLE_NAMES.filter((name) => name !== 'owner')),
      definition: tc.draw(gs.booleans()) ? null : { name: 'Edited', description: '', permissions: ['secret.read', 'secret.use'], protected: tc.draw(gs.booleans()) ? ['secret.use'] : [] },
    }];
    default: return [POLICY_REF, limitOp({ count: tc.draw(gs.integers({ minValue: 1, maxValue: 4 })), windowMs: pick(tc, [1_000, 10_000, 60_000]) })];
  }
}

function drawRequest(tc: hegel.TestCase, at: number): UseRequest {
  return {
    credential: pick(tc, CREDENTIALS), secretId: pick(tc, KEYS), place: maybe(tc, ENVIRONMENTS),
    purpose: pick(tc, PURPOSES), keepsSensitive: tc.draw(gs.booleans()), at,
  };
}

/**
 * An instance: every environment, member, credential and key made first, then a random run of
 * changes and uses, each use's live answer kept.
 */
function drawWorld(tc: hegel.TestCase): { world: World; at: number; decided: Map<UseCode | null, number> } {
  const world = new World();
  const decided = new Map<UseCode | null, number>();
  world.change(POLICY_REF, limitOp({ count: tc.draw(gs.integers({ minValue: 1, maxValue: 6 })), windowMs: 60_000 }));
  ENVIRONMENTS.forEach((id, n) => world.change({ kind: 'environment', id }, {
    op: 'environment.create', projectId: PROJECTS[n % 2]!, slug: pick(tc, ['dev', 'prod']), protected: tc.draw(gs.booleans()),
    // Odd ones a fork of the one before, or Ada's personal config of it.
    parentId: n % 2 === 1 ? ENVIRONMENTS[n - 1]! : null, owner: n % 2 === 1 && tc.draw(gs.booleans()) ? PRINCIPALS[0]! : null,
  }));
  for (const principal of PRINCIPALS) {
    world.change({ kind: 'principal', id: principal }, { op: 'member.add', role: pick(tc, ['member', 'member', 'developer', 'owner'] as const), scope: EVERYWHERE });
    world.change({ kind: 'principal', id: principal }, { op: 'access.grant', grant: { projectId: pick(tc, PROJECTS), environmentId: maybe(tc, ENVIRONMENTS), environmentSlug: null, role: pick(tc, ROLE_NAMES), expiresAt: null } });
  }
  CREDENTIALS.forEach((id, n) => {
    const principal = PRINCIPALS[n % PRINCIPALS.length]!;
    const caller: CallerKind = principal.startsWith('user:') ? 'person' : n === 4 ? 'workload' : 'bearer';
    const scope = caller === 'workload' ? [{ projectId: PROJECTS[0]!, environmentId: null, role: 'viewer', reads: [KEYS[0]!] }] : null;
    world.change({ kind: 'credential', id }, { op: 'credential.issue', principal, caller, scope, expiresAt: null });
  });
  KEYS.forEach((id, n) => {
    const environmentId = ENVIRONMENTS[n % ENVIRONMENTS.length]!;
    const reference = n === KEYS.length - 1;
    const nature = pick(tc, NATURES);
    const plain = !reference && nature === 'plain';
    world.change({ kind: 'secret', id }, {
      op: 'secret.write', projectId: PROJECTS[(n % ENVIRONMENTS.length) % 2]!, environmentId, version: 'v0', nature,
      key: reference || plain ? null : WRAPPED, digest: plain ? PLAIN_DIGEST : null, source: reference ? KEYS[0]! : null, reference: reference ? 'r' : null,
    });
  });
  let at = 0;
  const steps = tc.draw(gs.integers({ minValue: 10, maxValue: 60 }));
  for (let i = 0; i < steps; i += 1) {
    at += tc.draw(gs.integers({ minValue: 0, maxValue: 500 }));
    if (tc.draw(gs.integers({ minValue: 0, maxValue: 2 })) === 0) {
      const [ref, op] = drawChange(tc);
      world.change(ref, op, at);
    } else {
      const code = world.use(drawRequest(tc, at));
      decided.set(code, (decided.get(code) ?? 0) + 1);
    }
  }
  return { world, at, decided };
}

/** The changes a run makes allow a share of its uses, and refuse others for many reasons: the properties are about something. */
const seen = new Map<UseCode | null, number>();
test.after(() => {
  assert.ok((seen.get(null) ?? 0) > 0, `some uses allowed: ${JSON.stringify([...seen])}`);
  assert.ok([...seen.keys()].filter((code) => code !== null).length >= 6, `refused for several reasons: ${JSON.stringify([...seen])}`);
});

test(`a use decided on the rows is the replay's decision when the rows are the replay's, seed ${settings.seed}`, () => hegel.test((tc) => {
  const { world, decided } = drawWorld(tc);
  for (const [code, n] of decided) seen.set(code, (seen.get(code) ?? 0) + n);
  const live = world.log.flatMap((entry) => (entry.kind === 'use' ? [entry.request] : []));
  const fresh = new World();
  const liveCodes: (UseCode | null)[] = [];
  // Live again, from the log's changes, so that each use is decided on the rows as they stood.
  for (const entry of world.log) {
    if (entry.kind === 'change') fresh.change(entry.ref, entry.op, entry.at);
    else liveCodes.push(fresh.use(entry.request));
  }
  const replayed: (UseCode | null)[] = [];
  const result = replay(SEAL_KEYS, world.log, (_, code) => replayed.push(code));
  assert.deepEqual(result.faults, []);
  assert.equal(replayed.length, live.length);
  assert.deepEqual(replayed, liveCodes);
  // The rows, the newest seals and the cap's rows the replay ends with are the tables'.
  assert.deepEqual(new Map([...result.rows].map(([k, v]) => [k, v.row])), new Map([...world.rows].map(([k, v]) => [k, v.row])));
  assert.deepEqual(result.newest, world.newest);
  // BulkReplayAgrees: the cap's rows are the replay's, every request the cap admitted counted, `stale` ones included.
  assert.deepEqual(result.bulk, world.bulk);
  assert.deepEqual(result.limit, world.limit);
}, settings));

type Perturbation = 'rollback' | 'edit' | 'delete' | 'unlogged' | 'foreign' | 'reseal';

test(`rows that are not the replay's change a decision only to stale or tampered, and always when the decision weighs one; bulk rows only the cap's, seed ${settings.seed}`, () => hegel.test((tc) => {
  const { world, at } = drawWorld(tc);
  const replayed = replay(SEAL_KEYS, world.log, undefined, emptyReplay());
  const rows = new Map(world.rows);
  // Any object the instance could hold, put back, edited, deleted, written with no change, or sealed by another key.
  const refs: Ref[] = [
    ...PRINCIPALS.map((id) => ({ kind: 'principal' as const, id })), ...CREDENTIALS.map((id) => ({ kind: 'credential' as const, id })),
    ...KEYS.map((id) => ({ kind: 'secret' as const, id })), ...ENVIRONMENTS.map((id) => ({ kind: 'environment' as const, id })), ROLES_REF, POLICY_REF,
  ];
  const perturbed = new Set<string>();
  for (let i = tc.draw(gs.integers({ minValue: 1, maxValue: 3 })); i > 0; i -= 1) {
    const ref = pick(tc, refs);
    const key = objectKey(ref);
    const how: Perturbation = pick(tc, ['rollback', 'edit', 'delete', 'unlogged', 'foreign', 'reseal'] as const);
    const history = world.history.get(key) ?? [];
    const now = rows.get(key);
    switch (how) {
      case 'rollback': if (history.length > 0) rows.set(key, pick(tc, history)); break;
      case 'edit': if (now !== undefined) rows.set(key, { ...now, row: edited(now.row) }); break;
      case 'delete': rows.delete(key); break;
      case 'unlogged': if (now === undefined && history.length > 0) rows.set(key, pick(tc, history)); break;
      // Another object's row, with its valid seal, filed under this one's key.
      case 'foreign': {
        const other = [...world.rows.values()].filter(({ row }) => row.kind === ref.kind);
        if (other.length > 0) rows.set(key, pick(tc, other));
        break;
      }
      case 'reseal': if (now !== undefined) rows.set(key, { ...now, seal: sealOf(Buffer.alloc(32, 9), ref, now.row) }); break;
    }
  }
  // What is not the replay's once every perturbation is made: a later one may put back what an earlier one changed.
  for (const ref of refs) {
    const key = objectKey(ref);
    const [before, after] = [replayed.rows.get(key), rows.get(key)];
    const same = before === undefined ? after === undefined
      : after !== undefined && after.seal !== null && before.seal !== null && after.seal.equals(before.seal) && sealOf(SEAL_KEYS[0]!, ref, after.row).equals(sealOf(SEAL_KEYS[0]!, ref, before.row));
    if (!same) perturbed.add(key);
  }
  const request = drawRequest(tc, at + tc.draw(gs.integers({ minValue: 0, maxValue: 3_000 })));
  const cloneBulk = (bulk: Map<string, BulkRows>) => new Map([...bulk].map(([principal, held]) => [principal, new Map(held)]));
  // The bulk rows are outside the seals (docs/design/sealed-inputs.md): erased or moved, now and then, they may change
  // whether the cap refuses, and nothing else.
  const liveBulk = cloneBulk(world.bulk);
  const bulkMoved = tc.draw(gs.booleans());
  if (bulkMoved) {
    for (const held of liveBulk.values()) for (const key of [...held.keys()]) if (tc.draw(gs.booleans())) held.delete(key);
    else held.set(key, held.get(key)! - tc.draw(gs.integers({ minValue: -120_000, maxValue: 120_000 })));
  }
  const liveView = readUse(rows, world.newest, world.limit, liveBulk, request);
  const replayView = readUse(replayed.rows, replayed.newest, replayed.limit, cloneBulk(replayed.bulk), request);
  const live = decideUse(SEAL_KEYS, liveView, request);
  const truth = decideUse(SEAL_KEYS, replayView, request);
  const capOnly = bulkMoved && (live === null || live === 'bulk_limit') && (truth === null || truth === 'bulk_limit');
  if (live !== truth) assert.ok(live === 'stale' || live === 'tampered' || capOnly, `live ${live}, the replay ${truth}`);
  // The inputs the replay's decision weighs, in its order: one of them not the replay's is always caught.
  const weighed = inputsOf(replayView, request);
  if (weighed.some((key) => perturbed.has(key))) assert.ok(live === 'stale' || live === 'tampered', `a weighed input was not the log's, and live answered ${live}`);
}, settings));

/** An edit around the vault: the row changed, its seal kept. */
function edited(row: Input): Input {
  switch (row.kind) {
    case 'principal': return { ...row, role: row.role === 'owner' ? 'member' : 'owner' };
    case 'credential': return { ...row, revoked: !row.revoked };
    case 'secret': return { ...row, nature: row.nature === 'sensitive' ? 'secret' : 'sensitive' };
    case 'environment': return { ...row, deleted: !row.deleted };
    case 'roles': return { ...row, roles: { ...row.roles, viewer: { name: 'Viewer', description: '', permissions: ['secret.read', 'secret.use', 'secret.write'], protected: [] } } };
    case 'policy': return { ...row, bulk: { ...row.bulk, count: row.bulk.count + 1 } };
  }
}

/** The object keys a decision on `view` weighs, in its order. */
function inputsOf(view: UseView, request: UseRequest): string[] {
  const credential = view.credential.row;
  const secret = view.secret.row;
  return [
    objectKey({ kind: 'credential', id: request.credential }),
    ...(credential === null ? [] : [objectKey({ kind: 'principal', id: credential.principal })]),
    objectKey(ROLES_REF), objectKey(POLICY_REF), objectKey({ kind: 'secret', id: request.secretId }),
    ...(secret?.source == null ? [] : [objectKey({ kind: 'secret', id: secret.source })]),
    ...useEnvironments(view, request).map((id) => objectKey({ kind: 'environment', id })),
  ];
}

test(`the bulk cap: no rolling window releases more than count keys, uses decided in number order with times up to the deadline behind or a minute ahead, seed ${settings.seed}`, () => hegel.test((tc) => {
  const count = tc.draw(gs.integers({ minValue: 1, maxValue: 3 }));
  const windowMs = pick(tc, [1_000, 10_000, 60_000]);
  const world = new World();
  world.change(POLICY_REF, limitOp({ count, windowMs }));
  world.change({ kind: 'principal', id: 'token:ci' }, { op: 'member.add', role: 'member', scope: EVERYWHERE });
  world.change({ kind: 'principal', id: 'token:ci' }, { op: 'access.grant', grant: { projectId: PROJECTS[0]!, environmentId: null, environmentSlug: null, role: 'viewer', expiresAt: null } });
  world.change({ kind: 'credential', id: CREDENTIALS[0]! }, { op: 'credential.issue', principal: 'token:ci', caller: 'bearer', scope: null, expiresAt: null });
  world.change({ kind: 'environment', id: ENVIRONMENTS[0]! }, { op: 'environment.create', projectId: PROJECTS[0]!, slug: 'dev', owner: null, parentId: null, protected: false });
  for (const id of KEYS) world.change({ kind: 'secret', id }, { op: 'secret.write', projectId: PROJECTS[0]!, environmentId: ENVIRONMENTS[0]!, version: 'v', nature: 'secret', key: WRAPPED, digest: null, source: null, reference: null });
  const released: { key: string; at: number }[] = [];
  let clock = 100_000;
  for (let i = tc.draw(gs.integers({ minValue: 5, maxValue: 40 })); i > 0; i -= 1) {
    clock += tc.draw(gs.integers({ minValue: 0, maxValue: windowMs / 2 }));
    // Stamped by a Worker up to the deadline before the use is numbered (a slow isolate, a skewed clock), or up to a minute
    // after it (a clock running ahead, as far as `ahead` lets by).
    const at = clock + tc.draw(gs.integers({ minValue: -USE_DEADLINE_MS, maxValue: USE_AHEAD_MS }));
    const secretId = pick(tc, KEYS.slice(0, count + 2));
    if (world.use({ credential: CREDENTIALS[0]!, secretId, place: null, purpose: 'use', keepsSensitive: false, at }) === null) released.push({ key: secretId, at });
  }
  for (const { at: end } of released) {
    const inWindow = new Set(released.filter(({ at }) => end - windowMs < at && at <= end).map(({ key }) => key));
    assert.ok(inWindow.size <= count, `${inWindow.size} keys in the window ending ${end}, the cap ${count} (refresh ${refreshMs({ count, windowMs })})`);
  }
  assert.deepEqual(replay(SEAL_KEYS, world.log).faults, []);
}, settings));
