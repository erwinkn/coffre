// PROTOTYPE (W109): automatic rotation against a fake provider, crashed at
// every point, and the overlap's phases. No database, no network.
import test from 'node:test';
import assert from 'node:assert/strict';

import { advance, namePrefix, type Rotation, type RotationDeps, type RotationStore } from '../src/rotation/machine.ts';
import { exportedNames, laggards, slots, type Phase, type Read } from '../src/rotation/overlap.ts';
import type { Credential, CredentialProvider } from '../src/rotation/provider.ts';

const BEAT = 5 * 60_000;
const HOUR = 60 * 60_000;

/** Where a fault can strike: before a call reaches the provider, or after it acted and its answer was lost. */
type Fault = 'issue' | 'issue-lost' | 'store' | 'store-lost' | 'save' | 'revoke' | 'revoke-lost' | 'list';
const FAULTS: Fault[] = ['issue', 'issue-lost', 'store', 'store-lost', 'save', 'revoke', 'revoke-lost', 'list'];

/** An AWS IAM user's access keys: at most `limit` at once, each value shown once, its last use known. */
class FakeProvider implements CredentialProvider {
  readonly kind = 'aws-iam-user';
  live = new Map<string, { credential: Credential; value: string; lastUsed: number | null }>();
  #ids = 0;
  readonly limit: number;
  readonly fault: (at: Fault) => boolean;
  constructor(limit: number, fault: (at: Fault) => boolean) {
    this.limit = limit;
    this.fault = fault;
  }

  async issue(name: string) {
    if (this.fault('issue')) throw new Error('ServiceUnavailable');
    if (this.live.size >= this.limit) throw new Error('LimitExceeded');
    const credential = { id: `AKIA${++this.#ids}`, name };
    const value = `secret-${this.#ids}`;
    this.live.set(credential.id, { credential, value, lastUsed: null });
    if (this.fault('issue-lost')) throw new Error('socket hang up');
    return { credential, value };
  }
  async revoke(credential: Credential) {
    if (this.fault('revoke')) throw new Error('ServiceUnavailable');
    this.live.delete(credential.id); // gone already is fine
    if (this.fault('revoke-lost')) throw new Error('socket hang up');
  }
  async list(prefix: string) {
    if (this.fault('list')) throw new Error('ServiceUnavailable');
    return [...this.live.values()].map((l) => l.credential).filter((c) => c.name.startsWith(prefix));
  }
  async lastUsed(credential: Credential) {
    return this.live.get(credential.id)?.lastUsed ?? null;
  }
  /** A consumer authenticating with a value: true when it works. */
  use(value: string, at: number): boolean {
    const hit = [...this.live.values()].find((l) => l.value === value);
    if (hit !== undefined) hit.lastUsed = at;
    return hit !== undefined;
  }
}

/** The secret's versions and the rotation's row, each write all or nothing. */
class FakeStore implements RotationStore {
  versions: string[] = [];
  row: Rotation;
  readonly fault: (at: Fault) => boolean;
  constructor(initial: Rotation, first: string, fault: (at: Fault) => boolean) {
    this.fault = fault;
    this.row = initial;
    this.versions.push(first);
  }
  get current() {
    return this.versions.length;
  }
  async storeValue(before: Rotation, after: Rotation, value: string) {
    if (this.fault('store')) throw new Error('connection reset');
    if (JSON.stringify(this.row) !== JSON.stringify(before)) return null;
    this.versions.push(value);
    this.row = { ...after, version: this.versions.length };
    // Committed, and the answer lost on the way back.
    if (this.fault('store-lost')) throw new Error('connection reset');
    return this.versions.length;
  }
  async save(before: Rotation, after: Rotation) {
    if (this.fault('save')) throw new Error('connection reset');
    if (JSON.stringify(this.row) !== JSON.stringify(before)) return false;
    this.row = after;
    return true;
  }
}

/** A deploy of `service:api` every `every` ms: it reads the current version, then authenticates with it until the next. */
class Consumer {
  value: string | null = null;
  reads: Read[] = [];
  readonly every: number;
  constructor(every: number) {
    this.every = every;
  }
  tick(store: FakeStore, provider: FakeProvider, now: number) {
    if (this.value === null || now % this.every === 0) {
      this.value = store.versions[store.current - 1];
      this.reads.push({ actor: 'token:api', version: store.current, at: now });
    }
    return provider.use(this.value, now);
  }
}

function setup(fault: (at: Fault) => boolean, { limit = 2, deployEvery = 6 * HOUR } = {}) {
  let now = 0;
  const provider = new FakeProvider(limit, fault);
  // The key coffre holds before the rotation, made by hand and adopted: coffre knows its ID.
  const old = { credential: { id: 'AKIA-OLD', name: 'made by hand' }, value: 'secret-old', lastUsed: null };
  provider.live.set(old.credential.id, old);
  const rotation: Rotation = { id: 'rot_1', step: 'issue', old: old.credential, next: null, version: null, storedAt: null, failures: 0, lastError: null };
  const store = new FakeStore(rotation, old.value, fault);
  const consumer = new Consumer(deployEvery);
  const deps: RotationDeps = {
    provider,
    store,
    policy: { overlapMs: HOUR, idleMs: HOUR },
    now: () => now,
    laggards: async (r) =>
      laggards(consumer.reads, { replaced: r.version! - 1, stored: r.version!, storedAt: r.storedAt!, lookbackMs: 30 * 24 * HOUR }),
  };
  return {
    provider,
    store,
    consumer,
    deps,
    beat() {
      now += BEAT;
      return now;
    },
  };
}

/** Beat until done, checking after each that the consumer's value works and the provider's limit holds. */
async function run(world: ReturnType<typeof setup>, maxBeats = 2000) {
  const { provider, store, consumer, deps } = world;
  for (let beat = 0; beat < maxBeats; beat++) {
    const now = world.beat();
    assert.ok(consumer.tick(store, provider, now), `beat ${beat}: the consumer's value stopped working, at ${store.row.step}`);
    const current = store.versions[store.current - 1];
    assert.ok([...provider.live.values()].some((l) => l.value === current), `beat ${beat}: coffre serves a revoked value`);
    const { outcome } = await advance(store.row, deps);
    if (outcome === 'done') return beat;
  }
  assert.fail(`not done after ${maxBeats} beats, at ${world.store.row.step}: ${world.store.row.lastError}`);
}

function assertClean({ provider, store }: ReturnType<typeof setup>) {
  assert.equal(store.row.step, 'done');
  // Exactly one credential is left: the one coffre stores as current.
  assert.deepEqual([...provider.live.values()].map((l) => l.value), [store.versions[store.current - 1]]);
  assert.ok(!provider.live.has('AKIA-OLD'));
}

test('a rotation with nothing failing: stored, waits for the deploy and the old key to go idle, then revokes', async () => {
  const world = setup(() => false);
  const beats = await run(world);
  assertClean(world);
  // The consumer redeploys every 6 hours, so the old key goes idle after that, then an hour more.
  assert.ok(beats * BEAT >= 6 * HOUR, `revoked after ${beats} beats, before the consumer moved`);
  assert.equal(world.store.versions.length, 2);
});

test('it waits on the reader who has not moved, and on the old key still in use', async () => {
  const world = setup(() => false);
  await advance(world.store.row, world.deps); // issue
  world.consumer.reads.push({ actor: 'token:api', version: 1, at: -1 });
  world.beat();
  world.beat();
  const step = await advance(world.store.row, world.deps);
  assert.equal(step.outcome, 'waiting');
  assert.ok(step.outcome === 'waiting' && step.on.includes('token:api'));
});

for (const at of FAULTS) {
  test(`a fault at ${at}, once, at each of its calls in turn, still ends with one live key, the stored one`, async () => {
    for (let nth = 1; nth <= 4; nth++) {
      let calls = 0;
      const world = setup((point) => point === at && ++calls === nth);
      await run(world);
      assertClean(world);
    }
  });
}

test('random faults everywhere, 300 times over: it always ends clean, and the consumer never holds a dead key', async () => {
  for (let seed = 1; seed <= 300; seed++) {
    let state = seed;
    const random = () => ((state = (state * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);
    const world = setup(() => random() < 0.25);
    await run(world);
    assertClean(world);
  }
});

test('two beats at once: one stores, the other revokes what it made', async () => {
  const world = setup(() => false, { limit: 3 });
  const row = world.store.row;
  const [a, b] = await Promise.all([advance(row, world.deps), advance(row, world.deps)]);
  assert.deepEqual([a.outcome, b.outcome].sort(), ['failed', 'moved']);
  assert.equal(world.store.versions.length, 2);
  assert.equal((await world.provider.list(namePrefix(row))).length, 1);
});

test('the overlap: any two phases a step apart share a value, so a signer and a verifier always agree', () => {
  const phases: (Phase | null)[] = [null, 'staged', 'promoted', 'retired'];
  const values = { 4: 'v4', 5: 'v5' } as Record<number, string>;
  const signs = (phase: Phase | null) => values[slots(phase, 4, 5).current];
  const accepts = (phase: Phase | null) => Object.values(exportedNames('WEBHOOK_SECRET', slots(phase, 4, 5))).map((v) => values[v]);
  for (let i = 0; i + 1 < phases.length; i++) {
    for (const [signer, verifier] of [[phases[i], phases[i + 1]], [phases[i + 1], phases[i]]]) {
      assert.ok(accepts(verifier).includes(signs(signer)), `a signer at ${signer} and a verifier at ${verifier}`);
    }
  }
  // Without `staged`, a signer deployed first signs with v5 while the verifier knows only v4.
  assert.ok(!accepts(null).includes(signs('promoted')));
  assert.deepEqual(exportedNames('WEBHOOK_SECRET', slots('promoted', 4, 5)), { WEBHOOK_SECRET: 5, WEBHOOK_SECRET_PREVIOUS: 4 });
});

test('laggards: who read the replaced value lately and has not read the new one', () => {
  const reads: Read[] = [
    { actor: 'token:api', version: 4, at: 100 },
    { actor: 'token:worker', version: 4, at: 150 },
    { actor: 'token:worker', version: 5, at: 250 },
    { actor: 'user:ada@acme.example', version: 3, at: 10 }, // too long ago to wait for
  ];
  assert.deepEqual(laggards(reads, { replaced: 4, stored: 5, storedAt: 200, lookbackMs: 150 }), ['token:api']);
});
