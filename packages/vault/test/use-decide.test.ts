import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { EVERYWHERE, ROLES } from '@coffre/core/access';

import { bulkStep, refreshMs, USE_AHEAD_MS, USE_DEADLINE_MS } from '../src/bulk.ts';
import { DEFAULT_BULK_LIMIT } from '../src/config.ts';
import { limitOp, applyOp, limitChange, noEdits, objectKey, sealOf, SEAL_BYTES, type PolicyInput, type PrincipalInput } from '../src/inputs.ts';
import { purposeCode, purposeOf, PURPOSES, replay, type LoggedUse } from '../src/log-replay.ts';
import { readerOf, type UseCode } from '../src/decide.ts';
import { ADA, ask, BO, CI, credential, DEV, FORK, key, market, PROD, SEAL_KEYS, World, WRAPPED } from './world.ts';

// The 0.15 decision on sealed inputs, and its replay (docs/design/sealed-inputs.md). Every
// case holds the replay of the log to the live answer too.

/** Each use's live answer, against the replay's of the same log. */
function holdsReplay(w: World): void {
  const replayed: (UseCode | null)[] = [];
  const { faults } = replay(SEAL_KEYS, w.log, (_, code) => replayed.push(code));
  assert.deepEqual(faults, []);
  assert.equal(replayed.length, w.log.filter((entry) => entry.kind === 'use').length);
}

function liveAndReplayed(w: World, uses: Parameters<World['use']>[0][]): (UseCode | null)[] {
  const live = uses.map((request) => w.use(request));
  const replayed: (UseCode | null)[] = [];
  replay(SEAL_KEYS, w.log, (_, code) => replayed.push(code));
  assert.deepEqual(replayed.slice(-live.length), live, 'the replay decides each use as live did');
  return live;
}

test('object keys are the vectors PR 2 and PR 5 compute in SQL', () => {
  const vectors = JSON.parse(readFileSync(new URL('./object-keys.json', import.meta.url), 'utf8')) as { kind: 'principal'; id: string; key: string }[];
  assert.ok(vectors.length >= 6);
  for (const { kind, id, key: expected } of vectors) assert.equal(objectKey({ kind, id }), expected, `${kind} ${id}`);
});

test('a seal is 16 bytes, binds its object, and reads grants as a set', () => {
  const member: PrincipalInput = {
    kind: 'principal', principal: ADA, status: 'active', role: 'member', scope: EVERYWHERE,
    grants: [
      { projectId: 'p', environmentId: 'a', environmentSlug: null, role: 'viewer', expiresAt: null },
      { projectId: 'p', environmentId: 'b', environmentSlug: null, role: 'developer', expiresAt: 5 },
    ],
  };
  const seal = sealOf(SEAL_KEYS[0]!, { kind: 'principal', id: ADA }, member);
  assert.equal(seal.length, SEAL_BYTES);
  assert.deepEqual(sealOf(SEAL_KEYS[0]!, { kind: 'principal', id: ADA }, { ...member, grants: [...member.grants].reverse() }), seal);
  // Filed under another object, the same row is another seal: a row moved under Bo's key is not Bo's.
  assert.notDeepEqual(sealOf(SEAL_KEYS[0]!, { kind: 'principal', id: BO }, member), seal);
  assert.notDeepEqual(sealOf(SEAL_KEYS[0]!, { kind: 'principal', id: ADA }, { ...member, status: 'removed' }), seal);
});

test('a change that does nothing is never applied: creates of what exists, changes of what does not, limits R52 refuses', () => {
  const policy = { kind: 'policy', id: 'instance' } as const;
  assert.equal(applyOp(null, policy, limitOp({ count: 0, windowMs: 60_000 })), undefined);
  assert.equal(applyOp(null, policy, limitOp({ count: 10, windowMs: 24 * 3_600_000 + 1 })), undefined);
  assert.deepEqual(applyOp(null, policy, limitOp({ count: 10, windowMs: 24 * 3_600_000 })), { kind: 'policy', bulk: { count: 10, windowMs: 24 * 3_600_000 } });
  const ci = { kind: 'credential', id: credential(9) } as const;
  assert.equal(applyOp(null, ci, { op: 'credential.issue', principal: CI, caller: 'person', scope: null, expiresAt: null }), undefined);
  assert.equal(applyOp(null, ci, { op: 'credential.issue', principal: CI, caller: 'workload', scope: null, expiresAt: null }), undefined);
  assert.equal(applyOp(null, ci, { op: 'credential.revoke' }), undefined);
  const w = market();
  assert.equal(w.change({ kind: 'principal', id: ADA }, { op: 'member.add', role: 'owner', scope: EVERYWHERE }), false);
  assert.equal(w.change({ kind: 'principal', id: BO }, { op: 'access.revoke', place: { projectId: 'other', environmentId: null, environmentSlug: null } }), false);
  // A key does not move: a write of it elsewhere does nothing.
  assert.equal(w.change({ kind: 'secret', id: key(1) }, { op: 'secret.write', projectId: 'other', environmentId: PROD, version: 'x', nature: 'secret', key: null, source: null }), false);
  holdsReplay(w);
});

test('the 0.14 rules decide, on the objects: grants, protection, sensitivity, personal configs, references and forks', () => {
  const w = market({ count: 100, windowMs: 60_000 });
  assert.deepEqual(liveAndReplayed(w, [
    ask(2, 1), // Bo, a Viewer of dev, reveals dev's key
    ask(2, 3), // nothing of Bo's covers prod
    ask(2, 2), // a sensitive value is never handed back to a person
    ask(2, 2, { purpose: 'use' }), // but used, through the proxy
    ask(1, 3), // Ada, an Owner, reads prod: protected, which an Owner reads still
    ask(1, 6), // Ada's own personal config
    ask(2, 6), // nobody else's, whatever they hold
    ask(2, 9), // the fork's reference: Bo holds nothing in the fork
    ask(1, 9), // Ada does
    ask(1, 1, { place: FORK }), // the fork reads its parent's key, decided in dev
    ask(1, 1, { place: DEV }), // a key is never read through its own environment
    ask(3, 1), // ci, a Viewer of market
    ask(2, 1, { at: 1_000_000 }), // Bo's session has ended
    ask(7, 1), // no such credential
    ask(2, 8), // no such key
  ]), [null, 'no_grant', 'sensitive', null, null, null, 'personal', 'no_grant', null, null, 'bad_claim', null, 'credential', 'credential', 'missing']);
});

test('a revoke, a removal and a deleted environment refuse, as the replay does', () => {
  const w = market();
  w.change({ kind: 'principal', id: BO }, { op: 'access.revoke', place: { projectId: '00000000-0000-4000-8000-000000000001', environmentId: DEV, environmentSlug: null } });
  w.change({ kind: 'principal', id: CI }, { op: 'member.remove' });
  w.change({ kind: 'environment', id: PROD }, { op: 'environment.delete' });
  w.change({ kind: 'secret', id: key(1) }, { op: 'secret.delete' });
  assert.deepEqual(liveAndReplayed(w, [ask(2, 4), ask(3, 4), ask(1, 3), ask(1, 9), ask(1, 1)]), ['no_grant', 'removed', 'deleted', 'ended', 'missing']);
});

test('a row put back from before a change is stale, a row edited is tampered, and the replay names neither: rows must be the log\'s', () => {
  for (const [what, perturb] of [
    ['a member put back from before a revoke', (w: World) => {
      const bo = objectKey({ kind: 'principal', id: BO });
      const granted = w.rows.get(bo)!;
      w.change({ kind: 'principal', id: BO }, { op: 'access.revoke', place: { projectId: '00000000-0000-4000-8000-000000000001', environmentId: DEV, environmentSlug: null } });
      w.rows.set(bo, granted);
      return 'stale';
    }],
    ['a credential put back from before its revoke', (w: World) => {
      const c = objectKey({ kind: 'credential', id: credential(2) });
      const issued = w.rows.get(c)!;
      w.change({ kind: 'credential', id: credential(2) }, { op: 'credential.revoke' });
      w.rows.set(c, issued);
      return 'stale';
    }],
    ['a key put back from before a new version', (w: World) => {
      const k = objectKey({ kind: 'secret', id: key(1) });
      const old = w.rows.get(k)!;
      w.change({ kind: 'secret', id: key(1) }, { op: 'secret.write', projectId: '00000000-0000-4000-8000-000000000001', environmentId: DEV, version: 'v1b', nature: 'secret', key: { kekProvider: 'local', kekId: 'k1', kekVersion: '1', bytes: 'BBBB' }, source: null });
      w.rows.set(k, old);
      return 'stale';
    }],
    ['an environment put back from before its deletion', (w: World) => {
      const e = objectKey({ kind: 'environment', id: DEV });
      const old = w.rows.get(e)!;
      w.change({ kind: 'environment', id: DEV }, { op: 'environment.delete' });
      w.rows.set(e, old);
      return 'stale';
    }],
    ['a member edited around the vault', (w: World) => {
      const bo = objectKey({ kind: 'principal', id: BO });
      const row = w.rows.get(bo)!;
      w.rows.set(bo, { ...row, row: { ...(row.row as PrincipalInput), role: 'owner' } });
      return 'tampered';
    }],
    ['a member\'s row deleted outright', (w: World) => {
      w.rows.delete(objectKey({ kind: 'principal', id: BO }));
      return 'stale';
    }],
    ['a policy written with no change', (w: World) => {
      const p = objectKey({ kind: 'policy', id: 'instance' });
      w.rows.set(p, { row: { kind: 'policy', bulk: { count: 1000, windowMs: 60_000 } }, seal: sealOf(SEAL_KEYS[0]!, { kind: 'policy', id: 'instance' }, { kind: 'policy', bulk: { count: 1000, windowMs: 60_000 } }) });
      return 'stale';
    }],
  ] as const) {
    const w = market();
    const expected = perturb(w);
    const live = w.use(ask(2, 1));
    const replayed: (UseCode | null)[] = [];
    replay(SEAL_KEYS, w.log, (_, code) => replayed.push(code));
    assert.equal(live, expected, what);
    assert.notEqual(replayed.at(-1), 'stale', what);
    assert.notEqual(replayed.at(-1), 'tampered', what);
  }
});

test('putting back an identical state is no rollback: grant, revoke, grant again', () => {
  const w = market();
  const bo = objectKey({ kind: 'principal', id: BO });
  const first = w.rows.get(bo)!;
  const place = { projectId: '00000000-0000-4000-8000-000000000001', environmentId: DEV, environmentSlug: null };
  w.change({ kind: 'principal', id: BO }, { op: 'access.revoke', place });
  w.change({ kind: 'principal', id: BO }, { op: 'access.grant', grant: { ...place, role: 'viewer', expiresAt: null } });
  w.rows.set(bo, first);
  assert.deepEqual(liveAndReplayed(w, [ask(2, 1)]), [null]);
});

test('the bulk cap: count keys a window, repeats pass, a refused request moves nothing, and others count over window + refresh + deadline + ahead', () => {
  const w = market({ count: 2, windowMs: 60_000 });
  // Ada reads keys 1 and 4, then 5 is a third: refused. 1 again passes; after the window and its margins, 5 passes.
  const later = 1000 + 60_000 + refreshMs({ count: 2, windowMs: 60_000 }) + USE_DEADLINE_MS + USE_AHEAD_MS + 1;
  assert.deepEqual(liveAndReplayed(w, [ask(1, 1), ask(1, 4), ask(1, 5), ask(1, 1, { at: 2000 }), ask(1, 5, { at: later })]), [null, null, 'bulk_limit', null, null]);
  // A request refused for any other reason counts all the same: Bo asks for prod's key, refused, and then has room for one key only.
  const v = market({ count: 2, windowMs: 60_000 });
  assert.deepEqual(liveAndReplayed(v, [ask(2, 3), ask(2, 1), ask(2, 4)]), ['no_grant', null, 'bulk_limit']);
});

test('a stale use still moves the cap, live and replayed alike (HotPathOneStaleBulk)', () => {
  const w = market({ count: 1, windowMs: 60_000 });
  const c = objectKey({ kind: 'credential', id: credential(1) });
  const row = w.rows.get(c)!;
  w.rows.set(c, { ...row, seal: Buffer.alloc(SEAL_BYTES) });
  assert.equal(w.use(ask(1, 1)), 'tampered');
  w.rows.set(c, row);
  // Key 1 counted: key 4 is over the cap of one.
  assert.deepEqual(liveAndReplayed(w, [ask(1, 4)]), ['bulk_limit']);
});

test("the cap's count is the log's newest policy change: changed at a restart, the replay holds live across the change (CapSealed, BulkReplayAgrees)", () => {
  const w = market({ count: 1, windowMs: 60_000 });
  const policy = () => w.rows.get(objectKey({ kind: 'policy', id: 'instance' }))!.row as PolicyInput;
  assert.equal(limitChange(policy(), { count: 1, windowMs: 60_000 }), null);
  assert.deepEqual(liveAndReplayed(w, [ask(1, 1), ask(1, 4)]), [null, 'bulk_limit']);
  // A restart with a count of 3: the vault writes the change before it serves a use.
  const change = limitChange(policy(), { count: 3, windowMs: 60_000 });
  assert.deepEqual(change, limitOp({ count: 3, windowMs: 60_000 }));
  assert.equal(w.change({ kind: 'policy', id: 'instance' }, change!), true);
  assert.deepEqual(liveAndReplayed(w, [ask(1, 4, { at: 1100 }), ask(1, 5, { at: 1200 }), ask(1, 2, { at: 1300, purpose: 'use' })]), [null, null, 'bulk_limit']);
  const uses: LoggedUse[] = [];
  replay(SEAL_KEYS, w.log, (use) => uses.push(use));
  assert.equal(uses.length, 5);
  // And with no policy at all, nothing is served.
  const bare = new World();
  assert.equal(bare.use(ask(1, 1)), 'credential');
  assert.equal(limitChange(null, DEFAULT_BULK_LIMIT)?.op, 'bulk.limit');
});

test('a policy-less log refuses every use: the cap is the log\'s, never a number in the code', () => {
  const w = market();
  w.rows.delete(objectKey({ kind: 'policy', id: 'instance' }));
  w.newest.delete(objectKey({ kind: 'policy', id: 'instance' }));
  assert.equal(w.use(ask(1, 1)), 'no_policy');
});

test('the replay names what does not hold: a change that does nothing, a seal not the object\'s, numbers out of order', () => {
  const w = market();
  const entries = [...w.log];
  const last = entries.at(-1)!;
  const created = entries.find((entry) => entry.kind === 'change' && entry.op.op === 'environment.create');
  if (last.kind !== 'change' || created?.kind !== 'change') throw new Error('the world makes environments and ends with a change');
  const faults = replay(SEAL_KEYS, [
    ...entries,
    { ...created, number: last.number + 1n },
    { ...last, number: last.number + 2n, op: { op: 'secret.delete' }, seal: Buffer.alloc(SEAL_BYTES) },
    { kind: 'use', number: 1n, request: ask(1, 1) },
  ]).faults;
  assert.equal(faults.length, 3, faults.join('\n'));
  assert.match(faults[0]!, /does nothing/);
  assert.match(faults[1]!, /seal is not/);
  assert.match(faults[2]!, /out of number order/);
});

test('bulkStep refreshes a hot key once a refresh, not on every use', () => {
  const limit = { count: 5, windowMs: 15 * 60_000 };
  const rows = new Map<string, number>();
  bulkStep(rows, 'k', 0, limit);
  bulkStep(rows, 'k', 30_000, limit);
  assert.equal(rows.get('k'), 0);
  bulkStep(rows, 'k', 60_000, limit);
  assert.equal(rows.get('k'), 60_000);
  assert.equal(refreshMs({ count: 1, windowMs: 1500 }), 150);
});

test("a personal config's owner on a token: Ada's viewer token for dev reads her own config of dev, and nothing in prod", () => {
  const w = market();
  w.change({ kind: 'credential', id: credential(4) }, {
    op: 'credential.issue', principal: ADA, caller: 'person', expiresAt: null,
    scope: [{ projectId: '00000000-0000-4000-8000-000000000001', environmentId: DEV, role: 'viewer', permissions: { normal: ['secret.read', 'secret.use'], protected: ['secret.use'] } }],
  });
  assert.deepEqual(liveAndReplayed(w, [ask(4, 6), ask(4, 6, { purpose: 'use' }), ask(4, 3)]), [null, null, 'no_grant']);
});

test("a fork is read through as 0.14 does: it gates the read and decides nothing, the key is decided where it is held", () => {
  const w = market({ count: 100, windowMs: 60_000 });
  const dev = { projectId: '00000000-0000-4000-8000-000000000001', environmentId: DEV, environmentSlug: null };
  // Bo, a Viewer of dev alone, reads dev's key through the fork: decided in dev.
  assert.deepEqual(liveAndReplayed(w, [ask(2, 1, { place: FORK })]), [null]);
  // A Viewer of the fork alone reads none of dev's keys through it: inherited values take read on the parent.
  w.change({ kind: 'principal', id: BO }, { op: 'access.revoke', place: dev });
  w.change({ kind: 'principal', id: BO }, { op: 'access.grant', grant: { ...dev, environmentId: FORK, role: 'viewer', expiresAt: null } });
  assert.deepEqual(liveAndReplayed(w, [ask(2, 1, { place: FORK }), ask(2, 9)]), ['no_grant', null]);
  // Through an environment of another project, or the key's own: refused, whatever is held.
  const other = '00000000-0000-4000-8000-0000000000f1';
  w.change({ kind: 'environment', id: other }, { op: 'environment.create', projectId: '00000000-0000-4000-8000-00000000000f', slug: 'fork', owner: null, parentId: DEV, protected: false });
  assert.deepEqual(liveAndReplayed(w, [ask(1, 1, { place: other }), ask(1, 1, { place: DEV }), ask(1, 1, { place: FORK })]), ['bad_claim', 'bad_claim', null]);
  w.change({ kind: 'environment', id: FORK }, { op: 'environment.archive', archived: true });
  assert.deepEqual(liveAndReplayed(w, [ask(1, 1, { place: FORK })]), ['bad_claim']);
  w.change({ kind: 'environment', id: FORK }, { op: 'environment.delete' });
  assert.deepEqual(liveAndReplayed(w, [ask(1, 1, { place: FORK })]), ['bad_claim']);
});

test('a replay resumed on its own state goes on from its last number: an entry repeated at the seam is out of order', () => {
  const w = market();
  w.use(ask(1, 1));
  const state = replay(SEAL_KEYS, w.log);
  assert.deepEqual(state.faults, []);
  replay(SEAL_KEYS, w.log.slice(-1), undefined, state);
  assert.equal(state.faults.length, 1);
  assert.match(state.faults[0]!, /out of number order/);
  // Against the highest number seen: 10, then 5 and 7, faults twice.
  const use = (number: bigint) => ({ kind: 'use' as const, number, request: ask(1, 1) });
  const base = replay(SEAL_KEYS, w.log.slice(0, -1));
  const at = base.last;
  const after = replay(SEAL_KEYS, [use(at + 10n), use(at + 5n), use(at + 7n)], undefined, base);
  assert.equal(after.faults.filter((fault) => /out of number order/.test(fault)).length, 2);
  assert.equal(after.last, at + 10n);
});

test('the roles and the policy are one object each: a change to another of their kind does nothing, and moves no cap', () => {
  const other = { kind: 'policy', id: 'other' } as const;
  assert.equal(applyOp(null, other, limitOp({ count: 999, windowMs: 60_000 })), undefined);
  assert.equal(applyOp(null, { kind: 'roles', id: 'other' }, { op: 'role.define', table: 'roles', role: 'viewer', definition: null }), undefined);
  const w = market({ count: 1, windowMs: 60_000 });
  const forged = { kind: 'policy' as const, bulk: { count: 999, windowMs: 60_000 } };
  const result = replay(SEAL_KEYS, [...w.log, { kind: 'change', number: 1000n, at: 0, ref: other, op: limitOp({ count: 999, windowMs: 60_000 }), seal: sealOf(SEAL_KEYS[0]!, other, forged) }]);
  assert.equal(result.faults.length, 1);
  assert.deepEqual(result.limit, { count: 1, windowMs: 60_000 });
});

test('a vault start refuses a cap no change would apply, rather than leave the log with no policy', () => {
  assert.throws(() => limitChange(null, { count: 10, windowMs: 74_074.02 }), /whole number of milliseconds/);
  assert.throws(() => limitChange(null, { count: 0, windowMs: 60_000 }));
});

test("the roles object holds an Owner's edits only: a role as it ships is no edit, and the release's tables decide the rest", () => {
  const ref = { kind: 'roles', id: 'instance' } as const;
  const viewer = ROLES.viewer;
  assert.deepEqual(applyOp(null, ref, { op: 'role.define', table: 'roles', role: 'viewer', definition: null }), noEdits());
  assert.deepEqual(applyOp(null, ref, { op: 'role.define', table: 'roles', role: 'viewer', definition: { ...viewer, permissions: [...viewer.permissions].reverse() } }), noEdits());
  const narrowed = { ...viewer, permissions: ['secret.use' as const], protected: ['secret.use' as const] };
  const edited = applyOp(null, ref, { op: 'role.define', table: 'roles', role: 'viewer', definition: narrowed });
  assert.deepEqual(edited, { kind: 'roles', roles: { viewer: narrowed }, instanceRoles: {} });
  assert.deepEqual(applyOp(edited!, ref, { op: 'role.define', table: 'roles', role: 'viewer', definition: null }), noEdits());
  // Narrowed, a Viewer no longer reveals dev's key, and uses it still; put back as it ships, reveals it again.
  const w = market({ count: 100, windowMs: 60_000 });
  w.change(ref, { op: 'role.define', table: 'roles', role: 'viewer', definition: narrowed });
  assert.deepEqual(liveAndReplayed(w, [ask(2, 1), ask(2, 1, { purpose: 'use' })]), ['no_grant', null]);
  w.change(ref, { op: 'role.define', table: 'roles', role: 'viewer', definition: null });
  assert.deepEqual(liveAndReplayed(w, [ask(2, 1)]), [null]);
});

test('the bulk rows are outside the seals: erased, they let a request the replay refuses bulk_limit through, which the row audit names', () => {
  // A database writer who erases a principal's bulk rows resets its cap, and no input reads stale: the cap is a rate,
  // not a right, and PR 8's row audit holds every bulk row to the replay's (docs/design/sealed-inputs.md).
  const w = market({ count: 2, windowMs: 60_000 });
  assert.deepEqual(liveAndReplayed(w, [ask(1, 1), ask(1, 4)]), [null, null]);
  w.bulk.clear();
  const live = w.use(ask(1, 5));
  const replayed: (UseCode | null)[] = [];
  const result = replay(SEAL_KEYS, w.log, (_, code) => replayed.push(code));
  assert.equal(live, null);
  assert.equal(replayed.at(-1), 'bulk_limit');
  assert.notDeepEqual(result.bulk.get(ADA), w.bulk.get(ADA));
});

test('purpose and keepsSensitive are one smallint in the use row: the purpose code, plus 256 for a copy kept sensitive', () => {
  assert.deepEqual([...PURPOSES], ['reveal', 'run', 'compare', 'copy', 'use', 'expose']);
  for (const purpose of PURPOSES) {
    for (const keepsSensitive of [false, true]) assert.deepEqual(purposeOf(purposeCode({ purpose, keepsSensitive })), { purpose, keepsSensitive });
  }
  assert.equal(purposeCode({ purpose: 'copy', keepsSensitive: true }), 259);
  assert.equal(purposeOf(6), null);
  assert.equal(purposeOf(512), null);
  assert.equal(purposeOf(-1), null);
});

test("a policy row put back moves the cap as the log's newest policy change does, never as the row says (CapSealed)", () => {
  const w = market({ count: 1, windowMs: 60_000 });
  const p = objectKey({ kind: 'policy', id: 'instance' });
  const old = w.rows.get(p)!;
  w.change({ kind: 'policy', id: 'instance' }, limitOp({ count: 5, windowMs: 60_000 }));
  assert.deepEqual(liveAndReplayed(w, [ask(1, 1)]), [null]);
  // The count-1 row put back: the use is stale, and the cap moves by the logged count of 5, as the replay's does.
  w.rows.set(p, old);
  assert.equal(w.use(ask(1, 4)), 'stale');
  const result = replay(SEAL_KEYS, w.log);
  assert.deepEqual(result.bulk, w.bulk);
  assert.equal(w.bulk.get(ADA)?.has(key(4)), true);
});

test('a role named __proto__ is a role like any other in the edits, never their prototype', () => {
  const definition = { name: 'Odd', description: '', permissions: ['secret.use' as const], protected: [] };
  const edits = applyOp(null, { kind: 'roles', id: 'instance' }, { op: 'role.define', table: 'roles', role: '__proto__', definition });
  assert.ok(edits?.kind === 'roles' && Object.hasOwn(edits.roles, '__proto__'));
  assert.deepEqual(Object.getPrototypeOf(edits.roles), Object.prototype);
});

test("every change to the policy carries the whole policy as its value, at the path the use's statement reads", () => {
  const op = limitOp({ count: 7, windowMs: 90_000 });
  assert.deepEqual(JSON.parse(JSON.stringify(op)), { op: 'bulk.limit', value: { kind: 'policy', bulk: { count: 7, windowMs: 90_000 } } });
  const genesis = { op: 'genesis' as const, value: { kind: 'policy' as const, bulk: { count: 7, windowMs: 90_000 } } };
  assert.deepEqual(applyOp(null, { kind: 'policy', id: 'instance' }, genesis), applyOp(null, { kind: 'policy', id: 'instance' }, op));
});

test('a rename reaches the log: a Developer scoped to staging loses the environment renamed prod, live and replayed alike', () => {
  const w = market({ count: 100, windowMs: 60_000 });
  const STAGING = '00000000-0000-4000-8000-0000000000d5';
  const SCOPED = 'user:cy@acme.example';
  w.change({ kind: 'environment', id: STAGING }, { op: 'environment.create', projectId: '00000000-0000-4000-8000-000000000001', slug: 'staging', owner: null, parentId: null, protected: false });
  w.change({ kind: 'secret', id: key(20) }, { op: 'secret.write', projectId: '00000000-0000-4000-8000-000000000001', environmentId: STAGING, version: 'v', nature: 'secret', key: WRAPPED, source: null });
  w.change({ kind: 'principal', id: SCOPED }, { op: 'member.add', role: 'developer', scope: { projects: 'all', environments: { only: ['staging'] } } });
  w.change({ kind: 'credential', id: credential(5) }, { op: 'credential.issue', principal: SCOPED, caller: 'person', scope: null, expiresAt: null });
  assert.deepEqual(liveAndReplayed(w, [ask(5, 20)]), [null]);
  assert.equal(w.change({ kind: 'environment', id: STAGING }, { op: 'environment.rename', slug: 'prod' }), true);
  assert.deepEqual(liveAndReplayed(w, [ask(5, 20)]), ['no_grant']);
  w.change({ kind: 'environment', id: STAGING }, { op: 'environment.delete' });
  assert.equal(w.change({ kind: 'environment', id: STAGING }, { op: 'environment.rename', slug: 'staging' }), false);
});

test('a plain value, or any with no wrapped key, is no use: the app hands it back, as 0.14\'s vault never decides one', () => {
  const w = market({ count: 100, windowMs: 60_000 });
  w.change({ kind: 'secret', id: key(21) }, { op: 'secret.write', projectId: '00000000-0000-4000-8000-000000000001', environmentId: DEV, version: 'p', nature: 'plain', key: null, source: null });
  w.change({ kind: 'secret', id: key(22) }, { op: 'secret.write', projectId: '00000000-0000-4000-8000-000000000001', environmentId: FORK, version: 'r', nature: 'secret', key: null, source: key(21) });
  assert.deepEqual(liveAndReplayed(w, [ask(1, 21), ask(1, 22)]), ['bad_claim', 'bad_claim']);
});

test('genesis is held to what the ops that make an object hold it to', () => {
  assert.equal(applyOp(null, { kind: 'policy', id: 'instance' }, { op: 'genesis', value: { kind: 'policy', bulk: { count: 0, windowMs: 60_000 } } }), undefined);
  const ci = { kind: 'credential', id: 'c', principal: CI, caller: 'person', scope: null, expiresAt: null, revoked: false } as const;
  assert.equal(applyOp(null, { kind: 'credential', id: 'c' }, { op: 'genesis', value: ci }), undefined);
  assert.deepEqual(applyOp(null, { kind: 'credential', id: 'c' }, { op: 'genesis', value: { ...ci, caller: 'bearer' } }), { ...ci, caller: 'bearer' });
  assert.equal(applyOp(null, { kind: 'principal', id: BO }, { op: 'genesis', value: { kind: 'principal', principal: ADA, status: 'active', role: 'member', scope: EVERYWHERE, grants: [] } }), undefined);
});

test("a project id a plain object already holds is a project like another to the reader's policy", () => {
  const environment = { kind: 'environment' as const, id: 'e', projectId: 'constructor', slug: 'dev', owner: null, parentId: null, protected: true, deleted: false, archived: false };
  const credentialRow = { kind: 'credential' as const, id: 'c', principal: ADA, caller: 'person' as const, scope: null, expiresAt: null, revoked: false };
  const member = { kind: 'principal' as const, principal: ADA, status: 'active' as const, role: 'owner' as const, scope: EVERYWHERE, grants: [] };
  const reader = readerOf(member, credentialRow, noEdits(), [environment], 0);
  assert.deepEqual(reader.live.policy?.protectedIn.constructor, [{ environmentId: 'e', slug: 'dev' }]);
});
