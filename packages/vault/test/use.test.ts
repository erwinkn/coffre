// 0.15's use path (docs/design/0.15-plan.md, PR 5), on both engines: fence-one's
// cases (hot-path-one.md) against the real schema, each named for the part of
// formal/HotPathOne.tla it holds. The change path is PR 4's, not built yet: the
// owner plays it (use-world.ts). Every run's live answers are held to the
// replay of the log (R53).
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import { decrypt } from '@coffre/core/envelope';
import type { UseOutcome } from '@coffre/core/vault';
import { tablesOf } from '@coffre/db';
import { appendEntries } from '@coffre/db/log';
import { sql } from 'drizzle-orm';

import { objectKey, sealOf, type Input, type Op, type Ref } from '../src/inputs.ts';
import { vaultLogKey } from '../src/log.ts';
import { purposeOf, replay, type Logged } from '../src/log-replay.ts';
import { ENGINE, openTestDatabase, postgresOnly, rows, run, type TestDatabase } from './database.ts';
import { ask, change, CONFIG, DAY, emptyLog, FENCE, isolate, ROOT, SEAL, seal, SIGNING_KEY, useDatabases, world } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());
beforeEach(emptyLog);

/** Every live answer, by entry number: what the replay must say. */
const answered = new Map<string, UseOutcome>();
function heard(outcome: UseOutcome): UseOutcome {
  if (!('busy' in outcome) && outcome.number !== null && !(outcome.ok && outcome.covered)) answered.set(outcome.number, outcome);
  return outcome;
}

/** The log replayed (log-replay.ts) and each use's decision held to its live answer. */
async function replayAgrees(): Promise<number> {
  const changes = await rows<{ number: string | number; at: string | number; object: string; payload: string; seal: Buffer | null }>(db.owner,
    sql`SELECT number, at, object, payload, seal FROM log_changes`);
  const uses = await rows<{ number: string | number; at: string | number; credential: string; secret: string; purpose: number; place: string | null }>(db.owner,
    sql`SELECT number, at, credential, secret, purpose, place FROM log_uses`);
  const refs = new Map<string, Ref>();
  const entries: Logged[] = [
    ...changes.map((row) => {
      const op = JSON.parse(row.payload) as Op & { old?: string };
      const ref = refOf(op, row.object, refs);
      return { kind: 'change' as const, number: BigInt(row.number), at: Number(row.at), ref, op: stripped(op), seal: row.seal === null ? null : Buffer.from(row.seal) };
    }),
    ...uses.map((row) => ({
      kind: 'use' as const, number: BigInt(row.number),
      request: { credential: row.credential, secretId: row.secret, place: row.place, at: Number(row.at), ...purposeOf(Number(row.purpose))! },
    })),
  ].sort((a, b) => (a.number < b.number ? -1 : 1));
  let checked = 0;
  const result = replay([SEAL], entries, (entry, code) => {
    const live = answered.get(entry.number.toString());
    if (live === undefined) return;
    // Live may refuse `stale` or `tampered` where the log allows (a row put back or edited, a late 0.14 write), never otherwise.
    if (!live.ok && 'code' in live && (live.code === 'stale' || live.code === 'tampered')) return;
    assert.equal(live.ok ? null : (live as { code: string }).code, code, `entry ${entry.number}: live and replay disagree`);
    checked += 1;
  });
  assert.deepEqual(result.faults, []);
  return checked;
}

function stripped(op: Op & { old?: string }): Op {
  const { old: _, ...rest } = op;
  return rest as Op;
}

/** The object a change is about: the kind and id its key is of, from a genesis's value or a ref seen before. */
function refOf(op: Op, key: string, seen: Map<string, Ref>): Ref {
  if (op.op === 'genesis') {
    const value = op.value;
    const ref: Ref = value.kind === 'principal' ? { kind: 'principal', id: value.principal } : value.kind === 'roles' || value.kind === 'policy' ? { kind: value.kind, id: 'instance' } : { kind: value.kind, id: value.id };
    assert.equal(objectKey(ref), key);
    seen.set(key, ref);
  }
  return seen.get(key)!;
}

beforeEach(() => answered.clear());

// --- the cases ----------------------------------------------------------------------------------------

test('a use is one entry, its value opened from what the statement read, and the replay says the same', async () => {
  const w = await world();
  const id = await w.key('postgres://prod');
  const { use } = await isolate();
  const outcome = heard(await use(ask(w, id)));
  assert.ok(outcome.ok, JSON.stringify(outcome));
  const { value } = outcome;
  const plain = decrypt({ envelopeVersion: value.envelope.version, ciphertext: Buffer.from(value.envelope.ciphertext, 'base64'), iv: Buffer.from(value.envelope.iv, 'base64'), authTag: Buffer.from(value.envelope.authTag, 'base64') },
    value.context, Buffer.from(value.key, 'base64'));
  assert.equal(plain.toString(), 'postgres://prod');
  assert.equal((await rows(db.owner, sql`SELECT 1 FROM log_uses`)).length, 1);
  assert.equal(await replayAgrees(), 1);
});

test('a use the rules refuse is logged as its request all the same, and refused by the replay too', async () => {
  const w = await world();
  const id = await w.key();
  const { use } = await isolate();
  // Revoke the grant: a change to the principal (PR 4's access.revoke, played here).
  const revoked = { ...(w.objects.principal as Extract<Input, { kind: 'principal' }>), grants: [] };
  await change({ kind: 'principal', id: w.principal }, { op: 'access.revoke', place: { projectId: w.project, environmentId: w.dev, environmentSlug: null } }, revoked, async (tx, value) => {
    await run(tx, sql`DELETE FROM vault_grants WHERE principal = ${w.principal}`);
    await seal('vault_members', 'principal', w.principal)(tx, value);
  });
  const outcome = heard(await use(ask(w, id)));
  assert.equal(!outcome.ok && 'code' in outcome && outcome.code, 'no_grant');
  assert.equal((await rows(db.owner, sql`SELECT 1 FROM log_uses`)).length, 1, 'a refusal is a request like any other');
  assert.equal(await replayAgrees(), 1);
});

test('StatementSnapshot: a use that waits behind a change reads what the change wrote, where a bare CTE reads what was before', postgresOnly('the fence'), async () => {
  const w = await world();
  const id = await w.key();
  const { use } = await isolate();
  const request = ask(w, id);
  // The change holds the fence while the use waits for it, then revokes the credential and commits.
  let release!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  const revoking = db.owner.transaction(async (tx) => {
    await run(tx, FENCE);
    await released;
    const after = { ...(w.objects.credential as Extract<Input, { kind: 'credential' }>), revoked: true };
    await run(tx, sql`UPDATE credentials SET revoked_at = now(), seal = ${sealOf(SEAL, { kind: 'credential', id: w.credentialId }, after)} WHERE id = ${w.credentialId}`);
    await run(tx, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac) VALUES (nextval('log_number'), ${Date.now()}, ${randomUUID()},
      ${objectKey({ kind: 'credential', id: w.credentialId })}, ${ROOT}, ${JSON.stringify({ op: 'credential.revoke' })}, ${sealOf(SEAL, { kind: 'credential', id: w.credentialId }, after)}, ${randomBytes(16)})`);
  });
  await waitForFence();
  const using = use(request);
  // The bare CTE: the lock and the read in one statement, whose one snapshot predates the wait.
  const bare = rows<{ revoked: boolean }>(db.owner, sql`WITH l AS MATERIALIZED (SELECT pg_advisory_xact_lock_shared(1668244070, 0))
    SELECT c.revoked_at IS NOT NULL AS revoked FROM l, credentials c WHERE c.id = ${w.credentialId}`);
  await waitForWaiters(2);
  release();
  await revoking;
  const outcome = heard(await using);
  assert.equal(!outcome.ok && 'code' in outcome && outcome.code, 'credential', 'the function read the revoke');
  assert.equal((await bare)[0]!.revoked, false, 'the bare CTE read the credential as before the revoke, numbered after it');
  assert.equal(await replayAgrees(), 1);
});

async function waitForFence(): Promise<void> {
  for (let i = 0; i < 100; i += 1) {
    const [row] = await rows<{ n: string }>(db.owner, sql`SELECT count(*) AS n FROM pg_locks l JOIN pg_database d ON d.oid = l.database
      WHERE d.datname = current_database() AND l.locktype = 'advisory' AND l.classid = 1668244070 AND l.granted`);
    if (Number(row!.n) > 0) return;
    await sleep(20);
  }
  throw new Error('the fence was never held');
}

async function waitForWaiters(n: number): Promise<void> {
  for (let i = 0; i < 200; i += 1) {
    const [row] = await rows<{ n: string }>(db.owner, sql`SELECT count(*) AS n FROM pg_locks l JOIN pg_database d ON d.oid = l.database
      WHERE d.datname = current_database() AND l.locktype = 'advisory' AND l.classid = 1668244070 AND NOT l.granted`);
    if (Number(row!.n) >= n) return;
    await sleep(20);
  }
  throw new Error(`fewer than ${n} waited for the fence`);
}

test('replays: a retry of a call that wrote is answered replayed, and writes nothing', async () => {
  const w = await world();
  const id = await w.key();
  const { use } = await isolate();
  const request = ask(w, id);
  assert.ok(heard(await use(request)).ok);
  const again = await (await isolate()).use(request);
  assert.deepEqual(again, { ok: false, busy: 'replayed', retryAfter: 1 });
  assert.equal((await rows(db.owner, sql`SELECT 1 FROM log_uses`)).length, 1);
});

test('DeadlineChecked: a call past its deadline, or with one longer than 3 s, does nothing', async () => {
  const w = await world();
  const id = await w.key();
  const { use } = await isolate();
  const at = Date.now();
  assert.deepEqual(await use(ask(w, id, { at, deadline: at + 3001 })), { ok: false, busy: 'late', retryAfter: 1 });
  assert.deepEqual(await use(ask(w, id, { at: at - 3000, deadline: at - 1 })), { ok: false, busy: 'late', retryAfter: 1 });
  assert.equal((await rows(db.owner, sql`SELECT 1 FROM log_uses`)).length, 0);
});

test('DeadlineChecked, in Postgres: a use held past its deadline by its principal\'s lock writes nothing', postgresOnly('advisory locks'), async () => {
  const w = await world();
  const id = await w.key();
  const { use } = await isolate();
  const holder = await db.connect(1);
  // The principal's lock (0022: 1668244066, hashtext(principal)), held by another: a new key must wait for it.
  let release!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  const holding = holder.transaction(async (tx) => {
    await run(tx, sql`SELECT pg_advisory_xact_lock(1668244066, hashtext(${w.principal}))`);
    await released;
  });
  await sleep(50);
  const at = Date.now();
  const using = use(ask(w, id, { at, deadline: at + 300 }));
  const outcome = await using;
  release();
  await holding;
  assert.equal('busy' in outcome && outcome.busy, 'late', 'the Worker answered at its deadline');
  // The call it left behind does nothing once it gets its lock (DeadlineChecked), however late it runs.
  await sleep(200);
  assert.equal((await rows(db.owner, sql`SELECT 1 FROM log_uses`)).length, 0);
});

test('FloorChecked: a use stamped below the floor of `at` writes nothing', async () => {
  const w = await world();
  const id = await w.key();
  const { use } = await isolate();
  await run(db.owner, sql`UPDATE log_fence SET at_floor = ${Date.now() + 500}`);
  assert.deepEqual(await use(ask(w, id)), { ok: false, busy: 'late', retryAfter: 1 });
  assert.equal((await rows(db.owner, sql`SELECT 1 FROM log_uses`)).length, 0);
});

test('Unsealed = {}: each input put back from before its change is refused stale, live; the replay refuses or allows as the log says', async () => {
  const w = await world();
  const id = await w.key();
  const other = await w.key();
  const { use } = await isolate();
  assert.ok(heard(await use(ask(w, id))).ok);
  const credentialRef: Ref = { kind: 'credential', id: w.credentialId };
  const credentialBefore = (await rows<{ seal: Buffer }>(db.owner, sql`SELECT seal FROM credentials WHERE id = ${w.credentialId}`))[0]!.seal;
  // The credential revoked, then put back as it was, with its old, valid seal.
  const revoked = { ...(w.objects.credential as Extract<Input, { kind: 'credential' }>), revoked: true };
  await change(credentialRef, { op: 'credential.revoke' }, revoked, async (tx, value) => {
    await run(tx, sql`UPDATE credentials SET revoked_at = ${ENGINE === 'postgres' ? sql`now()` : sql`${Date.now()}`}, seal = ${value} WHERE id = ${w.credentialId}`);
  });
  await run(db.owner, sql`UPDATE credentials SET revoked_at = NULL, seal = ${credentialBefore} WHERE id = ${w.credentialId}`);
  assert.equal(code(heard(await use(ask(w, id)))), 'stale');
  // The member put back with a grant revoked; the key put back from before its value moved; the environment from before its deletion.
  const v = await isolate();
  const w2 = await world();
  const key2 = await w2.key();
  const memberBefore = (await rows<{ seal: Buffer }>(db.owner, sql`SELECT seal FROM vault_members WHERE principal = ${w2.principal}`))[0]!.seal;
  const revokedMember = { ...(w2.objects.principal as Extract<Input, { kind: 'principal' }>), grants: [] };
  await change({ kind: 'principal', id: w2.principal }, { op: 'access.revoke', place: { projectId: w2.project, environmentId: w2.dev, environmentSlug: null } }, revokedMember,
    async (tx, value) => {
      await run(tx, sql`DELETE FROM vault_grants WHERE principal = ${w2.principal}`);
      await seal('vault_members', 'principal', w2.principal)(tx, value);
    });
  const t = tablesOf(db.owner);
  await db.owner.insert(t.vaultGrants).values({ principal: w2.principal, projectId: null, environmentId: w2.dev, environmentSlug: null, role: 'viewer', grantedAt: Date.now(), grantedBy: ROOT });
  await run(db.owner, sql`UPDATE vault_members SET seal = ${memberBefore} WHERE principal = ${w2.principal}`);
  assert.equal(code(heard(await v.use(ask(w2, key2)))), 'stale', 'the member put back');
  const w3 = await world();
  const key3 = await w3.key();
  const environmentBefore = (await rows<{ seal: Buffer }>(db.owner, sql`SELECT seal FROM environments WHERE id = ${w3.dev}`))[0]!.seal;
  const deleted = { ...(w3.objects.environment as Extract<Input, { kind: 'environment' }>), deleted: true };
  await change({ kind: 'environment', id: w3.dev }, { op: 'environment.delete' }, deleted, async (tx, value) => {
    await run(tx, sql`UPDATE environments SET slug = 'dev~deleted-1', seal = ${value} WHERE id = ${w3.dev}`);
  });
  assert.equal(code(heard(await v.use(ask(w3, key3)))), 'deleted', 'deleted, as the log says');
  await run(db.owner, sql`UPDATE environments SET slug = 'dev', seal = ${environmentBefore} WHERE id = ${w3.dev}`);
  assert.equal(code(heard(await v.use(ask(w3, key3)))), 'stale', 'the environment put back');
  // A key's row edited around the log: its seal is no longer the vault's over it.
  await repoint(other);
  assert.equal(code(heard(await use(ask(w, other)))), 'stale', "the credential, before the key's own seal");
  const w4 = await world();
  const key4 = await w4.key();
  await repoint(key4);
  assert.equal(code(heard(await v.use(ask(w4, key4)))), 'tampered', 'a key edited around the log');
  await replayAgrees();
});

/** A key's row pointed around the log at a version of a writer's, under the seal it had. */
async function repoint(secretId: string): Promise<void> {
  const version = randomUUID();
  await run(db.owner, sql`INSERT INTO secret_versions (id, secret_id, version, envelope_version, ciphertext, iv, auth_tag, wrapped_dek, kek_provider, kek_id, kek_version, created_by, sensitive)
    SELECT ${version}, secret_id, version + 1, envelope_version, ciphertext, iv, auth_tag, wrapped_dek, kek_provider, kek_id, kek_version, created_by, sensitive
      FROM secret_versions WHERE secret_id = ${secretId}`);
  await run(db.owner, sql`UPDATE secrets SET current_version_id = ${version} WHERE id = ${secretId}`);
}

const code = (outcome: UseOutcome) => (outcome.ok ? null : 'code' in outcome ? outcome.code : outcome.busy);

test('the roles and the policy: a row put back is stale; the cap is the policy\'s newest change\'s, not its row\'s (CapSealed)', async () => {
  const w = await world({ count: 1, windowMs: DAY });
  const first = await w.key();
  const second = await w.key();
  const { use } = await isolate();
  // Its row says 99, its newest change 1: the second key is refused, and the use stale before anything (StaleFirst).
  await run(db.owner, sql`UPDATE log_config SET value = ${JSON.stringify({ kind: 'policy', bulk: { count: 99, windowMs: DAY } })} WHERE name = 'policy'`);
  assert.equal(code(heard(await use(ask(w, first)))), 'tampered', 'its seal is not over the row any more');
  const rows2 = await rows<{ last: unknown }>(db.owner, sql`SELECT last FROM log_bulk`);
  assert.equal(rows2.length, 1, 'the cap moved as the newest change says: one key in');
  assert.equal(code(heard(await use(ask(w, second)))), 'tampered');
  assert.equal((await rows(db.owner, sql`SELECT last FROM log_bulk`)).length, 1, 'and the second was not let in');
  await replayAgrees();
});

test('the bulk cap at count 10 over a day: ten keys in, the eleventh refused, repeats of the ten pass, and the replay agrees', async () => {
  const w = await world({ count: 10, windowMs: DAY });
  const ids: string[] = [];
  for (let i = 0; i < 11; i += 1) ids.push(await w.key());
  const { use } = await isolate();
  for (const id of ids.slice(0, 10)) assert.ok(heard(await use(ask(w, id))).ok);
  assert.equal(code(heard(await use(ask(w, ids[10]!)))), 'bulk_limit');
  for (const id of ids.slice(0, 10)) assert.ok(heard(await use(ask(w, id, { purpose: 'reveal' }))).ok);
  assert.equal(code(heard(await use(ask(w, ids[10]!)))), 'bulk_limit');
  assert.ok(await replayAgrees() >= 12);
});

test('covers: a repeat rides its entry, and writes none, until any input changes', async () => {
  const w = await world();
  const id = await w.key();
  const { use } = await isolate();
  const first = heard(await use(ask(w, id)));
  assert.ok(first.ok && !first.covered);
  const repeat = await use(ask(w, id));
  assert.ok(repeat.ok && repeat.covered && repeat.number === first.number, JSON.stringify(repeat));
  assert.equal((await rows(db.owner, sql`SELECT 1 FROM log_uses`)).length, 1, 'a repeat writes nothing');
  // Another purpose is another request: no cover.
  const reveal = heard(await use(ask(w, id, { purpose: 'reveal' })));
  assert.ok(reveal.ok && !reveal.covered);
  // A change to the key (its value moved): the next repeat is an entry of its own.
  const key = w.keys[0]!.object as Extract<Input, { kind: 'secret' }>;
  const moved = { ...key, nature: 'secret' as const };
  await change({ kind: 'secret', id }, { op: 'secret.write', projectId: key.projectId, environmentId: key.environmentId, version: key.version, nature: 'secret', key: key.key, source: null }, moved,
    seal('secrets', 'id', id));
  const after = heard(await use(ask(w, id)));
  assert.ok(after.ok && !after.covered, 'a cover from before a change covers nothing');
  assert.equal((await rows(db.owner, sql`SELECT 1 FROM log_uses`)).length, 3);
  assert.equal(await replayAgrees(), 3);
});

test('CoverExists: a cover whose entry is gone (a restore) covers nothing', async () => {
  const w = await world();
  const id = await w.key();
  const { use } = await isolate();
  assert.ok(heard(await use(ask(w, id))).ok);
  await run(db.owner, sql`DELETE FROM log_uses`);
  const again = heard(await use(ask(w, id)));
  assert.ok(again.ok && !again.covered);
  assert.equal((await rows(db.owner, sql`SELECT 1 FROM log_uses`)).length, 1);
});

test('the seal cache: the next use probes nothing while the newest change is the one it read at, by number and MAC (CacheSameChange)', async () => {
  const w = await world();
  const id = await w.key();
  const other = await w.key();
  const { use } = await isolate();
  assert.ok(heard(await use(ask(w, id))).ok);
  // The same key from the cache: allowed, and decided on the cached seals.
  assert.ok(heard(await use(ask(w, id, { purpose: 'reveal' }))).ok);
  // The newest change's MAC moved under the same number (a log restored, then written again): the cache is not trusted.
  await run(db.owner, sql`UPDATE log_changes SET mac = ${randomBytes(16)} WHERE number = (SELECT max(number) FROM log_changes)`);
  // A row put back now must still be caught: the credential revoked then restored as the cache knew it.
  const credentialBefore = (await rows<{ seal: Buffer }>(db.owner, sql`SELECT seal FROM credentials WHERE id = ${w.credentialId}`))[0]!.seal;
  const revoked = { ...(w.objects.credential as Extract<Input, { kind: 'credential' }>), revoked: true };
  await change({ kind: 'credential', id: w.credentialId }, { op: 'credential.revoke' }, revoked, async (tx, value) => {
    await run(tx, sql`UPDATE credentials SET seal = ${value} WHERE id = ${w.credentialId}`);
  });
  await run(db.owner, sql`UPDATE credentials SET seal = ${credentialBefore} WHERE id = ${w.credentialId}`);
  assert.equal(code(heard(await use(ask(w, other)))), 'stale');
  assert.equal(code(heard(await use(ask(w, id, { purpose: 'compare' })))), 'stale', 'the cached seals were not used past the change');
  await replayAgrees();
});

test('UsesSeeOldWrites: a 0.14 access entry about the principal that the new log does not account for makes its uses stale', async () => {
  const w = await world();
  const id = await w.key();
  const { use } = await isolate();
  assert.ok(heard(await use(ask(w, id))).ok);
  // A late 0.14 grant (an old isolate's), its entry in 0.14's log: until the new log adopts it, the principal is stale.
  const appended = await db.vault.transaction((tx) => appendEntries(tx, vaultLogKey(SIGNING_KEY), [{ actor: ROOT, action: 'access.grant', decision: 'allow', subjectPrincipal: w.principal, metadata: '{}' }]));
  assert.equal(code(heard(await use(ask(w, id, { purpose: 'reveal' })))), 'stale');
  // An adoption (PR 9) accounts for it: the principal's newest change names the entry.
  await change({ kind: 'principal', id: w.principal }, { op: 'genesis', value: w.objects.principal }, w.objects.principal, seal('vault_members', 'principal', w.principal), appended.seqStart);
  assert.ok(heard(await use(ask(w, id, { purpose: 'compare' }))).ok);
  await replayAgrees();
});

test('admission: past its calls in flight, an isolate refuses at once, holding no connection', async () => {
  const w = await world();
  const id = await w.key();
  const { use } = await isolate({ uses: { inFlight: 2 } });
  const all = await Promise.all(Array.from({ length: 6 }, () => use(ask(w, id, { purpose: 'reveal' }))));
  const refused = all.filter((outcome) => 'busy' in outcome && outcome.busy === 'overloaded');
  assert.ok(refused.length >= 1 && refused.length <= 4, `refused ${refused.length}`);
  for (const outcome of refused) assert.deepEqual(outcome, { ok: false, busy: 'overloaded', retryAfter: 1 });
});

test('before the policy is logged, a use does nothing', async () => {
  const w = await world();
  const id = await w.key();
  await run(db.owner, sql`DELETE FROM log_changes WHERE object = ${objectKey({ kind: 'policy', id: 'instance' })}`);
  const { use } = await isolate();
  assert.deepEqual(await use(ask(w, id)), { ok: false, busy: 'unconfigured', retryAfter: 5 });
  assert.equal((await rows(db.owner, sql`SELECT 1 FROM log_uses`)).length, 0);
});

/** An environment of the world's project, sealed by its genesis: a fork, or `owner`'s personal config of `parent`. */
async function environment(w: { project: string }, slug: string, extra: { owner?: string; parentId?: string } = {}): Promise<string> {
  const id = randomUUID();
  await db.owner.insert(tablesOf(db.owner).environments).values({ id, projectId: w.project, slug, name: slug, protected: false, owner: extra.owner ?? null, parentId: extra.parentId ?? null });
  const object: Input = { kind: 'environment', id, projectId: w.project, slug, owner: extra.owner ?? null, parentId: extra.parentId ?? null, protected: false, deleted: false, archived: false };
  await change({ kind: 'environment', id }, { op: 'genesis', value: object }, object, seal('environments', 'id', id));
  return id;
}

/** The world's principal granted `role` at `environmentId` too, by a change. */
async function grant(w: Awaited<ReturnType<typeof world>>, environmentId: string, role = 'viewer'): Promise<void> {
  const before = w.objects.principal as Extract<Input, { kind: 'principal' }>;
  const added = { projectId: w.project, environmentId, environmentSlug: null, role, expiresAt: null };
  const after = { ...before, grants: [...before.grants, added] };
  await change({ kind: 'principal', id: w.principal }, { op: 'access.grant', grant: added }, after, async (tx, value) => {
    await run(tx, sql`INSERT INTO vault_grants (principal, environment_id, role, granted_at, granted_by) VALUES (${w.principal}, ${environmentId}, ${role}, ${Date.now()}, ${ROOT})`);
    await seal('vault_members', 'principal', w.principal)(tx, value);
  });
  w.objects.principal = after;
}

test('a use through a place (a fork it is inherited in) reads every input, and is decided where the key is held', async () => {
  const w = await world();
  const id = await w.key('inherited');
  const fork = await environment(w, 'fork');
  const { use } = await isolate();
  const through = heard(await use(ask(w, id, { place: fork })));
  assert.ok(through.ok, JSON.stringify(through));
  assert.equal((await rows<{ place: string }>(db.owner, sql`SELECT place FROM log_uses`))[0]!.place, fork, 'the read is named where it was');
  // From the cache too, and a place that is the key's own is no place to read it through (0.14's throughOk).
  assert.ok(heard(await use(ask(w, id, { place: fork, purpose: 'reveal' }))).ok);
  assert.equal(code(heard(await use(ask(w, id, { place: w.dev })))), 'bad_claim');
  assert.equal(await replayAgrees(), 3);
});

test('a reference reads its source\'s value, decided at its holder: the whole shape, probed and from the cache', async () => {
  const w = await world();
  const source = await w.key('the source');
  const prod = await environment(w, 'prod');
  await grant(w, prod);
  const holder = randomUUID();
  const appended = await db.vault.transaction((tx) => appendEntries(tx, vaultLogKey(SIGNING_KEY), [{ actor: ROOT, action: 'reference.create', decision: 'allow', metadata: '{}' }]));
  await db.owner.insert(tablesOf(db.owner).secrets).values({ id: holder, projectId: w.project, environmentId: prod, key: `HELD_${holder.slice(0, 4)}` });
  await db.owner.insert(tablesOf(db.owner).secretReferences).values({
    id: randomUUID(), projectId: w.project, environmentId: prod, secretId: holder, sourceProjectId: w.project, sourceEnvironmentId: w.dev, sourceSecretId: source,
    createdSeq: appended.seqStart, createdBy: ROOT,
  });
  const object: Input = { kind: 'secret', id: holder, projectId: w.project, environmentId: prod, version: '', nature: 'secret', key: null, source };
  await change({ kind: 'secret', id: holder }, { op: 'genesis', value: object }, object, seal('secrets', 'id', holder));
  const { use } = await isolate();
  for (const purpose of ['run', 'reveal'] as const) {
    const outcome = heard(await use(ask(w, holder, { purpose })));
    assert.ok(outcome.ok, JSON.stringify(outcome));
    assert.equal(outcome.value.context.secretId, source, "the source's value, bound to the source");
    const plain = decrypt({ envelopeVersion: outcome.value.envelope.version, ciphertext: Buffer.from(outcome.value.envelope.ciphertext, 'base64'), iv: Buffer.from(outcome.value.envelope.iv, 'base64'),
      authTag: Buffer.from(outcome.value.envelope.authTag, 'base64') }, outcome.value.context, Buffer.from(outcome.value.key, 'base64'));
    assert.equal(plain.toString(), 'the source');
  }
  // The source's row put back from before a change: the reference's use is stale too.
  const sourceObject = w.keys[0]!.object as Extract<Input, { kind: 'secret' }>;
  const sealBefore = (await rows<{ seal: Buffer }>(db.owner, sql`SELECT seal FROM secrets WHERE id = ${source}`))[0]!.seal;
  await change({ kind: 'secret', id: source }, { op: 'secret.write', projectId: sourceObject.projectId, environmentId: sourceObject.environmentId, version: sourceObject.version, nature: 'sensitive', key: sourceObject.key, source: null },
    { ...sourceObject, nature: 'sensitive' }, seal('secrets', 'id', source));
  await run(db.owner, sql`UPDATE secrets SET seal = ${sealBefore} WHERE id = ${source}`);
  assert.equal(code(heard(await use(ask(w, holder, { purpose: 'compare' })))), 'stale');
  assert.equal(await replayAgrees(), 2);
});

test("a personal config's key: its owner reads it while they read its parent, which the use weighs (the plain shape's fourth environment)", async () => {
  const w = await world({ caller: 'person' });
  const mine = await environment(w, 'dev-mine', { owner: w.principal, parentId: w.dev });
  const t = tablesOf(db.owner);
  // A key of the personal config, sealed as `w.key` seals one in dev.
  const id = randomUUID();
  const version = randomUUID();
  const { encrypt, freshDek } = await import('@coffre/core/envelope');
  const { ownerKey } = await import('@coffre/core/envelope');
  const dek = freshDek();
  const sealed = encrypt(Buffer.from('mine'), { projectId: w.project, environmentId: mine, secretId: id }, dek);
  const wrapped = await CONFIG.keks.wrap(dek, { projectId: w.project, environmentId: mine, secretId: id, owner: ownerKey(w.principal) }, { deadline: Date.now() + 5000, signal: new AbortController().signal });
  await db.owner.insert(t.secrets).values({ id, projectId: w.project, environmentId: mine, key: 'MINE' });
  await db.owner.insert(t.secretVersions).values({
    id: version, secretId: id, version: 1, envelopeVersion: sealed.envelopeVersion, ciphertext: sealed.ciphertext, iv: sealed.iv, authTag: sealed.authTag,
    wrappedDek: wrapped.bytes, kekProvider: wrapped.kekProvider, kekId: wrapped.kekId, kekVersion: wrapped.kekVersion, createdBy: ROOT, sensitive: false,
  });
  await run(db.owner, sql`UPDATE secrets SET current_version_id = ${version}, current_version = 1 WHERE id = ${id}`);
  const object: Input = { kind: 'secret', id, projectId: w.project, environmentId: mine, version, nature: 'secret',
    key: { kekProvider: wrapped.kekProvider, kekId: wrapped.kekId, kekVersion: wrapped.kekVersion, bytes: Buffer.from(wrapped.bytes).toString('base64') }, source: null };
  await change({ kind: 'secret', id }, { op: 'genesis', value: object }, object, seal('secrets', 'id', id));
  const { use } = await isolate();
  const outcome = heard(await use(ask(w, id)));
  assert.ok(outcome.ok, JSON.stringify(outcome));
  assert.equal(outcome.value.context.owner, ownerKey(w.principal), "opened as its owner's");
  // The parent put back from before its deletion: weighed, so the use is stale.
  const parentBefore = (await rows<{ seal: Buffer }>(db.owner, sql`SELECT seal FROM environments WHERE id = ${w.dev}`))[0]!.seal;
  await change({ kind: 'environment', id: w.dev }, { op: 'environment.delete' }, { ...(w.objects.environment as Extract<Input, { kind: 'environment' }>), deleted: true }, async (tx, value) => {
    await run(tx, sql`UPDATE environments SET slug = 'dev~deleted-2', seal = ${value} WHERE id = ${w.dev}`);
  });
  assert.equal(code(heard(await use(ask(w, id, { purpose: 'compare' })))), 'deleted', 'its parent deleted: refused, as the log says');
  await run(db.owner, sql`UPDATE environments SET slug = 'dev', seal = ${parentBefore} WHERE id = ${w.dev}`);
  assert.equal(code(heard(await use(ask(w, id, { purpose: 'reveal' })))), 'stale');
  await replayAgrees();
});

test('whole numbers past 2^53 come back exact, entry numbers included', async () => {
  const w = await world();
  const id = await w.key();
  const big = 2n ** 53n + 100n;
  if (ENGINE === 'postgres') await run(db.owner, sql`SELECT setval('log_number', ${big.toString()}::bigint)`);
  else await run(db.owner, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac) VALUES (${big}, ${Date.now()}, ${randomUUID()}, ${randomUUID()}, ${ROOT}, '{"op":"x"}', NULL, ${randomBytes(16)})`);
  const { use } = await isolate();
  const outcome = await use(ask(w, id));
  assert.ok(outcome.ok, JSON.stringify(outcome));
  const [stored] = await rows<{ number: string }>(db.owner, sql`SELECT CAST(number AS TEXT) AS number FROM log_uses`);
  assert.equal(outcome.number, stored!.number);
  assert.ok(BigInt(outcome.number) > big, `${outcome.number} is past 2^53`);
  // And again from the seal cache, the newest change named by its exact number.
  const again = await use(ask(w, id, { purpose: 'reveal' }));
  assert.ok(again.ok && BigInt(again.number) > BigInt(outcome.number), JSON.stringify(again));
});

test('CacheSameChange: a newest change of the same number but another MAC (a log restored) sends the cache back to the probes', async () => {
  const w = await world();
  const id = await w.key();
  // The log's newest change, which the cache is read at: another object's, which a restore takes away.
  await environment(w, 'spare');
  const { use } = await isolate();
  assert.ok(heard(await use(ask(w, id))).ok);
  // The log as a restore leaves it: under the newest change's number, another change, the credential's revoke, its row as that change wrote it.
  const credentialRef: Ref = { kind: 'credential', id: w.credentialId };
  const revoked = { ...(w.objects.credential as Extract<Input, { kind: 'credential' }>), revoked: true };
  const revokedSeal = sealOf(SEAL, credentialRef, revoked);
  await db.owner.transaction(async (tx) => {
    const [newest] = await rows<{ number: string | number }>(tx, sql`SELECT max(number) AS number FROM log_changes`);
    await run(tx, sql`DELETE FROM log_changes WHERE number = ${newest!.number}`);
    await run(tx, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
      VALUES (${newest!.number}, ${Date.now()}, ${randomUUID()}, ${objectKey(credentialRef)}, ${ROOT}, ${JSON.stringify({ op: 'credential.revoke' })}, ${revokedSeal}, ${randomBytes(16)})`);
    await run(tx, sql`UPDATE credentials SET revoked_at = ${ENGINE === 'postgres' ? sql`now()` : sql`${Date.now()}`}, seal = ${revokedSeal} WHERE id = ${w.credentialId}`);
  });
  // Trusting the cache by number alone would hold the row to the credential's old seal (`stale`); read again, it is revoked.
  assert.equal(code(await use(ask(w, id, { purpose: 'reveal' }))), 'credential');
});
