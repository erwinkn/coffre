// 0.15's log across a rotation of the vault's signing key (T168; formal/Rotation.tla; docs/design/audit-tree.md, "A
// rotation"): a vault and its checkpointer under the old key, then the deploy to the new one, the old key kept to verify
// what came before. A local KEK rotated (its signing key derived from it) and a key service's explicit signingKey
// rotated (the old one in previousSigningKeys) give the vault the same list of signing keys, the new first; each is run
// here end to end.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { encrypt, freshDek } from '@coffre/core/envelope';
import { KekRegistry, LocalKekProvider, type KekProvider } from '@coffre/core/kek';
import { decodePair, encodePair, signPair, splitNote, type PairNotes } from '@coffre/core/merkle';
import type { TreeVerification, UseOutcome } from '@coffre/core/vault';
import { type Database } from '@coffre/db';
import { sql } from 'drizzle-orm';

import { genesisCall, type ChangeKeys } from '../src/changes.ts';
import { Checkpointer, type Memory, type SealThrough } from '../src/checkpointer.ts';
import { resolveVaultConfig, type ResolvedVaultConfig, type VaultConfig } from '../src/config.ts';
import { sealKey, type Input, type Ref } from '../src/inputs.ts';
import { openLocalVault as openEntry, spoken } from '../src/local.ts';
import { keyringOf } from '../src/keyring.ts';
import { openLogCheckpointer, logKey, logKeys } from '../src/log-checkpointer.ts';
import { verifierKeys } from '../src/verifier.ts';
import { authentic, entryMac, KEY_OBJECT, logMacKey, rotationPayload } from '../src/log-entry.ts';
import { logStore } from '../src/log-store.ts';
import { credentialObject, environmentObject, secretObject } from '../src/objects.ts';
import * as store from '../src/store.ts';
import { newRequestId } from '../src/use.ts';
import { variableMemory } from './audit-tree.ts';
import { emptyDatabase, openTestDatabase, places, rows, run, sealed, speaking, type LocalVault, type TestDatabase } from './database.ts';
import { checkpointFence, credentials, secretVersions } from '@coffre/db/schema';

/** A vault in this process, spoken to through the version gate's envelope (`spoken`). */
const openLocalVault = async (...args: Parameters<typeof openEntry>) => spoken(await openEntry(...args));

const ROOT = 'user:root@acme.example';
const ADA = 'user:ada@acme.example';
const owners = ['root@acme.example'];

let db: TestDatabase;
let hot: Database;
/** The KEK the instance wraps values with, the same across the deploy: what rotates here is the key the vault signs with. */
let keks: KekRegistry;
before(async () => {
  db = await openTestDatabase();
  hot = await db.hot();
});
after(() => db.close());
beforeEach(async () => {
  keks = new KekRegistry(LocalKekProvider.generate('test-kek-1'));
  await emptyDatabase(db.owner);
  for (const table of ['log_uses', 'bulk_cap', 'log_checkpoints', 'log_tiles']) await run(db.owner, sql.raw(`DELETE FROM ${table}`));
  await run(db.owner, sql`UPDATE checkpoint_fence SET at_floor = ${Date.now() - 60_000}, retired = '{}'`);
  const today = new Date().toISOString().slice(0, 10);
  await run(db.owner, sql`SELECT make_day(${today}::date - 1), make_day(${today}::date), make_day(${today}::date + 1)`);
});

const b64 = () => randomBytes(32).toString('base64');

/** A key service's key, as config.ts takes one: nothing here asks it to wrap. */
const kms = {
  provider: 'test-kms', keyId: 'key-1', keyVersion: '1',
  wrap: () => Promise.reject(new Error('not asked')), unwrap: () => Promise.reject(new Error('not asked')),
} as unknown as KekProvider;

/** Each way a deployment rotates the key its vault signs with: the config before, and after. */
const ROTATIONS: { name: string; before: VaultConfig; after: VaultConfig }[] = (() => {
  const [a, b, s1, s2] = [b64(), b64(), b64(), b64()];
  return [
    {
      name: 'a local KEK rotated',
      before: { kek: { id: 'vault-a', key: a }, owners },
      after: { kek: { id: 'vault-b', key: b }, previousKeks: [{ id: 'vault-a', key: a }], owners },
    },
    {
      name: "a key service's signingKey rotated",
      before: { kek: kms, signingKey: s1, owners },
      after: { kek: kms, signingKey: s2, previousSigningKeys: [s1], owners },
    },
  ];
})();

type Checked = Extract<TreeVerification, { kept: true }>;

/**
 * A vault keeping 0.15's log under `config`'s signing keys, with a
 * checkpointer of its own over `memory`, which seals each change before it
 * answers. Its KEK is a local one whatever `config` names: a key service is
 * only where its signing key comes from here.
 */
async function vaultUnder(config: VaultConfig, memory: Memory & { record: string | null }, alarms: string[] = []) {
  const resolved: ResolvedVaultConfig = { ...resolveVaultConfig(config), keks };
  const cp = await openLogCheckpointer({ store: logStore(db.vault), signingKeys: resolved.signingKeys, memory, record: (alarm) => void alarms.push(alarm.message) });
  const sealThrough: SealThrough = (number, deadline) => cp.sealThrough(number, deadline);
  const heldOutside = async () => (memory.record === null ? [] : [decodePair(memory.record)!]);
  const vault = speaking(await openLocalVault(db.vault, resolved, { sealThrough, heldOutside }, async () => {}, hot));
  const keys: ChangeKeys = { seals: resolved.signingKeys.map((seed) => sealKey(seed)), mac: logMacKey(resolved.signingKeys[0]!) };
  return { config: resolved, cp, vault, keys, memory, alarms };
}

/** The log as the old key leaves it: dev, Ada with a grant there, her session and a key with a value, each sealed; uses of it. */
async function underOldKey(config: VaultConfig) {
  const memory = variableMemory();
  const old = await vaultUnder(config, memory);
  const where = await places(db.owner);
  const genesis = async (keys: ChangeKeys, cp: Checkpointer, ref: Ref, input: Input) => {
    const [number] = await db.vault.transaction((tx) => store.changeInputs(tx, [genesisCall(keys, ref, input, Date.now(), 'system:cutover')]));
    assert.ok(number !== null && number !== undefined, `${ref.kind} ${ref.id} sealed`);
    await cp.sealThrough(number);
  };
  assert.equal((await old.vault.access(ROOT)).role, 'owner');
  await genesis(old.keys, old.cp, { kind: 'environment', id: where.dev }, environmentObject({ id: where.dev, projectId: where.project, slug: 'dev', owner: null, parentId: null, protected: false, archived: false, projectArchived: false }));
  assert.ok((await old.vault.admit({ actor: ROOT, principal: ADA })).ok);
  assert.ok((await old.vault.setAccess({ actor: ROOT, principal: ADA, changes: [{ projectId: where.project, environmentId: where.dev, role: 'developer', expiresAt: null }] })).ok);
  const credential = randomUUID();
  const expires = new Date(Date.now() + 86_400_000);
  await db.owner.insert(credentials).values({
    id: credential, kind: 'cli', authMac: Buffer.alloc(32), tokenHash: randomBytes(32), tokenHint: 'hint', generation: 0, principal: ADA, createdBy: ROOT, expiresAt: expires, scope: null,
  });
  await genesis(old.keys, old.cp, { kind: 'credential', id: credential }, credentialObject({ id: credential, principal: ADA, kind: 'cli', scope: null, revoked: false, expiresAt: expires.getTime(), generation: 0 }));
  /** A key with a value, made by a vault under `under`'s keys and sealed by its checkpointer. */
  const key = async (under: { config: ResolvedVaultConfig; keys: ChangeKeys; cp: Checkpointer }) => {
    const ref = await where.secret(where.dev);
    const version = randomUUID();
    const dek = freshDek();
    const context = { projectId: where.project, environmentId: where.dev, secretId: ref.secretId };
    const sealed = encrypt(Buffer.from('postgres://dev'), context, dek);
    const wrapped = await under.config.keks.wrap(dek, context, { deadline: Date.now() + 5000, signal: new AbortController().signal });
    await db.owner.insert(secretVersions).values({
      id: version, secretId: ref.secretId, version: 1, envelopeVersion: sealed.envelopeVersion, ciphertext: sealed.ciphertext, iv: sealed.iv, authTag: sealed.authTag,
      wrappedDek: wrapped.bytes, kekProvider: wrapped.kekProvider, kekId: wrapped.kekId, kekVersion: wrapped.kekVersion, createdBy: ROOT,
    });
    await run(db.owner, sql`UPDATE secrets SET current_version_id = ${version}, current_version = 1 WHERE id = ${ref.secretId}`);
    await genesis(under.keys, under.cp, { kind: 'secret', id: ref.secretId }, secretObject({
      id: ref.secretId, projectId: where.project, environmentId: where.dev, source: null, reference: null,
      version: { id: version, sensitive: false, plaintext: null, kekProvider: wrapped.kekProvider, kekId: wrapped.kekId, kekVersion: wrapped.kekVersion, wrappedDek: Buffer.from(wrapped.bytes).toString('base64') },
    }));
    return ref.secretId;
  };
  /** A use of a key on Ada's session, now, through `vault`. */
  const use = (vault: LocalVault, secretId: string): Promise<UseOutcome> => {
    const at = Date.now();
    return vault.use({ credential, secretId, place: null, purpose: 'run', requestId: newRequestId(), at, deadline: at + 3000 });
  };
  const secret = await key(old);
  for (let i = 0; i < 2; i += 1) assert.ok((await use(old.vault, secret)).ok);
  await old.cp.tick();
  return { old, memory, where, genesis, key, use, secret };
}

/** A page's check through `vault`. */
async function verify(vault: LocalVault): Promise<Checked> {
  const answer = await vault.verifyTrees!();
  assert.ok(answer.kept, JSON.stringify(answer));
  return answer;
}

function clean(checked: Checked): void {
  assert.deepEqual(checked.problems, []);
  assert.ok(checked.ok, JSON.stringify(checked));
}

const rotations = async () => (await rows<{ number: string | number; payload: string }>(db.owner, sql`SELECT number, payload FROM log_changes WHERE object = ${KEY_OBJECT} ORDER BY number`))
  .map((r) => ({ number: BigInt(r.number), payload: JSON.parse(r.payload) as { op: string; from: string; to: string; at: string } }));

/** The fence's retired tags, hex. */
async function retired(): Promise<string[]> {
  return (await rows<{ tag: string }>(db.owner, sql`SELECT encode(unnest(retired), 'hex') AS tag FROM checkpoint_fence`)).map((r) => r.tag);
}

/** The origin a pair's changes note is signed under. */
const signer = (notes: PairNotes) => splitNote(notes.changes).signatures[0]!.name.replace(/\/changes$/, '');

for (const rotation of ROTATIONS) {
  test(`${rotation.name}: the checkpointer carries its memory across, writes one rotation, and the log goes on under the new key`, async () => {
    const w = await underOldKey(rotation.before);
    const [current, previous] = resolveVaultConfig(rotation.after).signingKeys;
    const [oldKey, newKey] = [await logKey(previous!), await logKey(current!)];
    assert.equal(signer(w.old.cp.pair.notes), oldKey.origin);
    await w.old.cp.close();
    // The deploy: a checkpointer under the new key over the old one's memory, and a vault under the new config.
    const alarms: string[] = [];
    const now = await vaultUnder(rotation.after, w.memory, alarms);
    const [moved] = await rotations();
    assert.deepEqual(moved?.payload, { ref: { kind: 'log', id: 'key' }, op: 'rotate', from: oldKey.origin, to: newKey.origin, at: String(moved!.number) });
    assert.deepEqual(await retired(), [oldKey.mac.tag.toString('hex')]);
    assert.ok(alarms.some((a) => a.includes(`moves on from ${oldKey.origin}`)), alarms.join('\n'));
    // Its first tick seals the rotation under the new key, and remembers that pair.
    assert.ok((await now.cp.tick()).signed);
    assert.equal(signer(now.cp.pair.notes), newKey.origin);
    assert.equal(signer(decodePair(w.memory.record!)!), newKey.origin);
    assert.ok(now.cp.pair.pair.upto >= moved!.number);
    // Changes seal, uses go on, a key made since uses its new seals, and the log checks clean.
    assert.ok((await now.vault.admit({ actor: ROOT, principal: 'user:bo@acme.example' })).ok);
    const used = await w.use(now.vault, w.secret);
    assert.ok(used.ok, JSON.stringify(used));
    assert.ok((await w.use(now.vault, await w.key(now))).ok);
    assert.equal((await db.owner.select().from(checkpointFence)).length, 1);
    clean(await verify(now.vault));
    // Started again, it neither rotates twice nor refuses its memory.
    await now.cp.close();
    const again = await vaultUnder(rotation.after, w.memory);
    assert.equal((await rotations()).length, 1);
    assert.ok((await again.vault.admit({ actor: ROOT, principal: 'user:cy@acme.example' })).ok);
    clean(await verify(again.vault));
  });
}

test('the old key, still serving after the rotation, writes nothing: its use is superseded, its change refused', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  await w.old.cp.close();
  const now = await vaultUnder(rotation.after, w.memory);
  await now.cp.tick();
  const refused = await w.use(w.old.vault, w.secret);
  assert.deepEqual(refused, { ok: false, busy: 'superseded', retryAfter: 1 });
  // A change under the old key, past the rotation: the trigger refuses it, whoever writes it. Its object, a key no
  // change has sealed yet.
  const secret = await w.where.secret(w.where.dev);
  await assert.rejects(
    db.vault.transaction((tx) => store.changeInputs(tx, [genesisCall(w.old.keys, { kind: 'secret', id: secret.secretId }, secretObject({
      id: secret.secretId, projectId: w.where.project, environmentId: w.where.dev, source: null, reference: null, version: null,
    }), Date.now(), 'system:cutover')])),
    (error: Error & { cause?: Error }) => /the log moved on from the signing key this entry is under/.test(`${error.message} ${error.cause?.message}`),
  );
  // The new key's go on, and nothing under the old one is in the log past the rotation.
  assert.ok((await w.use(now.vault, w.secret)).ok);
  await now.cp.tick();
  const [moved] = await rotations();
  const past = await rows<{ mac: Buffer | Uint8Array }>(db.owner, sql`SELECT mac FROM log_changes WHERE number > ${moved!.number} UNION ALL SELECT mac FROM log_uses WHERE number > ${moved!.number}`);
  assert.ok(past.length > 0);
  assert.ok(past.every((r) => Buffer.from(r.mac).subarray(0, 4).equals(now.keys.mac.tag)));
  clean(await verify(now.vault));
});

test('before the rotation, both keys write: the old key\'s entries count below it, the new one\'s anywhere', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  const [one, two] = [await w.key(w.old), await w.key(w.old)];
  await w.old.cp.close();
  // The new config's isolates serve before the checkpointer starts under it: a use under each key, in the window.
  // Its first call holds the cutover to its seal, the old key's: answered as sealed (`sealed`), with no checkpointer.
  const resolved = { ...resolveVaultConfig(rotation.after), keks };
  const early = speaking(await openLocalVault(db.vault, resolved, { sealThrough: sealed, heldOutside: async () => [] }, async () => {}, hot));
  assert.ok((await w.use(early, one)).ok);
  assert.ok((await w.use(w.old.vault, two)).ok);
  // The rotation under way, before the new key's checkpointer writes it: the newest pair under the old key checks clean.
  clean(await verify(early));
  const now = await vaultUnder(rotation.after, w.memory);
  clean(await verify(now.vault));
  const tick = await now.cp.tick();
  assert.deepEqual(tick.failures, []);
  assert.ok(tick.signed);
  clean(await verify(now.vault));
});

test('a crash between the rotation and its first seal: the next start writes no second rotation, and seals it', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  await w.old.cp.close();
  const first = await vaultUnder(rotation.after, w.memory);
  await first.cp.close();
  // Its memory still holds the old key's pair; the rotation is in the window.
  assert.equal(signer(decodePair(w.memory.record!)!), signer(w.old.cp.pair.notes));
  const second = await vaultUnder(rotation.after, w.memory);
  assert.equal((await rotations()).length, 1);
  assert.ok((await second.cp.tick()).signed);
  assert.ok((await second.vault.admit({ actor: ROOT, principal: 'user:bo@acme.example' })).ok);
  clean(await verify(second.vault));
});

test('a crash between remembering the first pair under the new key and writing it: the next start writes it from the entries', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  await w.old.cp.close();
  const real = logStore(db.vault);
  // A store whose next write fails: the pair is remembered, not written.
  let fail = true;
  const failing = { ...real, write: (...args: Parameters<typeof real.write>) => (fail ? Promise.reject(new Error('the connection went')) : real.write(...args)) };
  const keys = resolveVaultConfig(rotation.after).signingKeys;
  const cp = await openLogCheckpointer({ store: failing, signingKeys: keys, memory: w.memory });
  await assert.rejects(cp.tick());
  await cp.close();
  fail = false;
  const remembered = decodePair(w.memory.record!)!;
  const [newest] = await rows<{ upto: string | number }>(db.owner, sql`SELECT max(upto) AS upto FROM log_checkpoints`);
  assert.ok(BigInt(newest!.upto) < BigInt(splitNote(remembered.changes).text.split('\n')[3]!.slice(5)), 'the memory is ahead');
  const again = await vaultUnder(rotation.after, w.memory);
  assert.equal(encodePair(again.cp.pair.notes), encodePair(remembered));
  assert.equal((await rotations()).length, 1);
  assert.ok((await again.vault.admit({ actor: ROOT, principal: 'user:bo@acme.example' })).ok);
  clean(await verify(again.vault));
});

test('the signer\'s memory lost at the rotation: it takes the database\'s pair under the old key, alarmed, and rotates', async () => {
  const rotation = ROTATIONS[1]!;
  const w = await underOldKey(rotation.before);
  await w.old.cp.close();
  const alarms: string[] = [];
  const now = await vaultUnder(rotation.after, variableMemory(), alarms);
  assert.ok(alarms.some((a) => a.includes('remembers no pair')), alarms.join('\n'));
  assert.equal((await rotations()).length, 1);
  assert.ok((await now.vault.admit({ actor: ROOT, principal: 'user:bo@acme.example' })).ok);
  clean(await verify(now.vault));
});

/** A use under `key`, written straight to `log_uses`, numbered next: past the fence, as a database writer puts it. Its number. */
async function plantUse(key: ChangeKeys['mac']): Promise<bigint> {
  const at = Date.now();
  const row = { at, requestId: BigInt(newRequestId()), credential: randomUUID(), secret: randomUUID(), purpose: 1, place: null };
  const mac = entryMac(key, { tree: 'uses', row });
  const [planted] = await rows<{ number: string | number }>(db.owner, sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place) VALUES (nextval('log_number'), ${at}, ${row.requestId}, ${row.credential}, ${row.secret}, 1, ${mac}, NULL) RETURNING number`);
  return BigInt(planted!.number);
}

test('an entry under the old key past the rotation is refused by the tick and named by the check (BoundaryChecked)', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  await w.old.cp.close();
  const now = await vaultUnder(rotation.after, w.memory);
  // A use under the old key, numbered past the rotation, as someone who holds it writes it: past the fence, which no
  // trigger guards on log_uses (use_credential refuses it, which a writer goes around).
  const forged = await plantUse(w.old.keys.mac);
  const check = await verify(now.vault);
  assert.deepEqual(check.problems, [`${forged}: under a key the log moved on from, past its rotation`]);
  const tick = await now.cp.tick();
  assert.deepEqual(tick.failures, [`${forged}: under a key the log moved on from, past its rotation`]);
  assert.ok(!tick.signed);
});

test('a rotation renumbered higher counts for nothing: the old key\'s entry where it no longer is, refused by the next start, the check and the keyring (NumberInRotation, review r1)', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  await w.old.cp.close();
  const now = await vaultUnder(rotation.after, w.memory);
  assert.ok((await now.cp.tick()).signed);
  await now.cp.close();
  // Someone who writes the database moves the sealed rotation's row far up, its MAC whole (it covers no number), and
  // writes a use under the old key between the two places.
  const [moved] = await rotations();
  const planted = await plantUse(w.old.keys.mac);
  const far = planted + 1_000n;
  await run(db.owner, sql`UPDATE log_changes SET number = ${far} WHERE number = ${moved!.number}`);
  assert.ok(planted > moved!.number && planted < far);
  // Its payload names the number it was written at: moved, it is no rotation to any reader, and the old key, the newest
  // pair under the new one, vouches for nothing.
  const keys = await verifierKeys(resolveVaultConfig(rotation.after).signingKeys);
  const ring = await keyringOf(keys, logStore(db.vault));
  assert.deepEqual(ring.previous.map((p) => p.until), [-1n]);
  const again = await vaultUnder(rotation.after, w.memory);
  const tick = await again.cp.tick();
  assert.ok(!tick.signed && tick.failures.some((f) => f.startsWith(`${planted}: `)), tick.failures.join('; '));
  assert.ok((await verify(again.vault)).problems.some((p) => p.startsWith(`${planted}: `)));
});

test('a pair the old key signs over its rotation, carrying the new key\'s name, is taken under the key it is signed with: refused by the check (SignerVerified, review r1)', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  await w.old.cp.close();
  const now = await vaultUnder(rotation.after, w.memory);
  clean(await verify(now.vault));
  await now.cp.close();
  // A pair under the old key over the rotation, its notes given a signature line naming the new key's trees, which
  // does not verify: the old check took the name for the key, and its fast path for the current key.
  const [current, previous] = resolveVaultConfig(rotation.after).signingKeys;
  const [oldKey, newKey] = [await logKey(previous!), await logKey(current!)];
  const forger = await Checkpointer.open(logStore(db.vault), oldKey.signers, { memory: variableMemory(), authentic: () => true });
  assert.ok((await forger.tick()).signed);
  const named = (note: string, tree: 'changes' | 'uses') => `${note}— ${newKey.signers[tree].name} ${Buffer.concat([newKey.signers[tree].id, randomBytes(64)]).toString('base64')}\n`;
  const upto = forger.pair.pair.upto;
  await run(db.owner, sql`UPDATE log_checkpoints SET changes_note = ${named(forger.pair.notes.changes, 'changes')}, uses_note = ${named(forger.pair.notes.uses, 'uses')} WHERE upto = ${upto}`);
  const [moved] = await rotations();
  const problems = (await verify(now.vault)).problems;
  assert.ok(problems.includes(`checkpoint ${upto}: under ${oldKey.origin}, at or past the rotation that retired it (${moved!.number})`), problems.join('\n'));
});

test('a backlog sealed a part at a time across the rotation: a pair under the new key below it, the old key\'s entries above that pair counted, and nothing alarmed (KeyringBound, review r1)', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  // A backlog under the old key, its checkpointer gone before sealing it: uses its isolates wrote, MAC'd under it.
  for (let i = 0; i < 6; i += 1) await plantUse(w.old.keys.mac);
  await w.old.cp.close();
  // The deploy, its checkpointer sealing two entries a pair.
  const resolved: ResolvedVaultConfig = { ...resolveVaultConfig(rotation.after), keks };
  const cp = await openLogCheckpointer({ store: logStore(db.vault), signingKeys: resolved.signingKeys, memory: w.memory, windowMax: 2 });
  const [moved] = await rotations();
  const vault = speaking(await openLocalVault(db.vault, resolved, {
    sealThrough: (number, deadline) => cp.sealThrough(number, deadline), heldOutside: async () => (w.memory.record === null ? [] : [decodePair(w.memory.record)!]),
  }, async () => {}, hot));
  const first = await cp.tick();
  assert.deepEqual(first.failures, []);
  assert.ok(cp.pair.pair.upto < moved!.number, 'a pair under the new key below the rotation');
  assert.equal(signer(cp.pair.notes), (await logKey(resolved.signingKeys[0]!)).origin);
  clean(await verify(vault));
  for (let i = 0; i < 20 && cp.pair.pair.upto < moved!.number; i += 1) assert.deepEqual((await cp.tick()).failures, []);
  assert.ok(cp.pair.pair.upto >= moved!.number);
  clean(await verify(vault));
});

/**
 * What someone who holds the old key and writes the database plants: a use under it past the rotation, the old key's tag
 * taken out of the fence (a row like the floor beside it), and a rotation into the old key, from any origin, MAC'd under
 * it, at the number it names. The newest rotation then says the log is under the old key. The planted use's number.
 */
async function plantRotationIntoOld(w: Awaited<ReturnType<typeof underOldKey>>, oldOrigin: string): Promise<{ planted: bigint; number: bigint }> {
  const planted = await plantUse(w.old.keys.mac);
  await run(db.owner, sql`UPDATE checkpoint_fence SET retired = '{}'`);
  const [next] = await rows<{ n: string | number }>(db.owner, sql`SELECT nextval('log_number') AS n`);
  const number = BigInt(next!.n);
  const row = { at: Date.now(), requestId: randomUUID(), object: KEY_OBJECT, actor: 'system:vault', payload: rotationPayload(`coffre.log/${randomBytes(8).toString('hex')}`, oldOrigin, number), seal: null };
  const mac = entryMac(w.old.keys.mac, { tree: 'changes', row });
  await run(db.owner, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac) VALUES (${number}, ${row.at}, ${row.requestId}, ${KEY_OBJECT}, 'system:vault', ${row.payload}, NULL, ${mac})`);
  assert.ok(planted < number);
  return { planted, number };
}

test('a rotation into the old key, planted past its own with the fence emptied before its first seal, counts for nothing: the next start writes no second boundary, and its tick refuses what was planted (ChainRule, review r2)', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  await w.old.cp.close();
  // The rotation written, nothing sealed under the new key yet: the signer's head is still the old key's pair, so only
  // the rotation's row says the log moved on from it.
  const now = await vaultUnder(rotation.after, w.memory);
  await now.cp.close();
  const [moved] = await rotations();
  const oldKey = await logKey(resolveVaultConfig(rotation.after).signingKeys[1]!);
  const { planted, number } = await plantRotationIntoOld(w, oldKey.origin);
  assert.ok(moved!.number < planted);
  // The planted rotation is into the old key past that key's own rotation, where its MAC vouches for nothing: no
  // rotation, so the log is under the new key and the signer, started again, writes none (a second boundary would have
  // let the old key vouch for the planted use, below it).
  const again = await vaultUnder(rotation.after, w.memory);
  assert.equal((await rotations()).length, 2);
  assert.deepEqual(await retired(), []);
  const ring = await keyringOf(await verifierKeys(resolveVaultConfig(rotation.after).signingKeys), logStore(db.vault));
  assert.deepEqual(ring.previous.map((p) => p.until), [moved!.number]);
  const tick = await again.cp.tick();
  assert.ok(!tick.signed);
  assert.deepEqual(tick.failures, [planted, number].map((n) => `${n}: under a key the log moved on from, past its rotation`));
});

for (const gone of ['deleted', 'renumbered'] as const) {
  test(`a rotation into the old key, planted with the fence emptied and the vault's own rotation, sealed, ${gone}, counts for nothing: the old key vouches for nothing, and the tick refuses what was planted (ChainRule, review r3)`, async () => {
    const rotation = ROTATIONS[0]!;
    const w = await underOldKey(rotation.before);
    await w.old.cp.close();
    const now = await vaultUnder(rotation.after, w.memory);
    assert.ok((await now.cp.tick()).signed);
    await now.cp.close();
    const [moved] = await rotations();
    assert.ok(now.cp.pair.pair.upto >= moved!.number);
    const oldKey = await logKey(resolveVaultConfig(rotation.after).signingKeys[1]!);
    // The rotation's row gone, or moved to a number its payload does not name (which `rotationOf` drops): the rows hold
    // no rotation from the old key, and the fence names none.
    if (gone === 'deleted') await run(db.owner, sql`DELETE FROM log_changes WHERE number = ${moved!.number}`);
    else await run(db.owner, sql`UPDATE log_changes SET number = ${moved!.number + 1_000_000n} WHERE number = ${moved!.number}`);
    const { planted, number } = await plantRotationIntoOld(w, oldKey.origin);
    // At or past the rotation.
    assert.ok(moved!.number <= planted);
    // The newest pair is under the new key, so the old key, no rotation of it counting, vouches for nothing: the planted
    // rotation into it counts for nothing either, and the signer writes none (Rotation.tla's ChainRule).
    const again = await vaultUnder(rotation.after, w.memory);
    assert.equal((await rotations()).length, gone === 'deleted' ? 1 : 2);
    assert.deepEqual(await retired(), []);
    const ring = await keyringOf(await verifierKeys(resolveVaultConfig(rotation.after).signingKeys), logStore(db.vault));
    assert.deepEqual(ring.previous.map((p) => p.until), [-1n]);
    const tick = await again.cp.tick();
    assert.ok(!tick.signed);
    // Each above the head.
    const above = [planted, number].filter((n) => n > now.cp.pair.pair.upto);
    assert.ok(above.includes(number));
    assert.deepEqual(tick.failures.filter((f) => above.some((n) => f.startsWith(`${n}:`))), above.map((n) => `${n}: its MAC does not hold`));
  });
}

test('two rotations, A to B to C: each key vouches below its own rotation, the second written from B with A\'s bound carried, a restart writing none', async () => {
  const [a, b, c] = [b64(), b64(), b64()];
  const configs = {
    a: { kek: { id: 'vault-a', key: a }, owners },
    b: { kek: { id: 'vault-b', key: b }, previousKeks: [{ id: 'vault-a', key: a }], owners },
    c: { kek: { id: 'vault-c', key: c }, previousKeks: [{ id: 'vault-b', key: b }, { id: 'vault-a', key: a }], owners },
  } satisfies Record<string, VaultConfig>;
  const w = await underOldKey(configs.a);
  await w.old.cp.close();
  const underB = await vaultUnder(configs.b, w.memory);
  assert.ok((await underB.cp.tick()).signed);
  assert.ok((await w.use(underB.vault, w.secret)).ok);
  const madeUnderB = await w.key(underB);
  assert.deepEqual((await underB.cp.tick()).failures, []);
  await underB.cp.close();
  // The second deploy: C signs, B and A kept.
  const [kc, kb, ka] = await Promise.all(resolveVaultConfig(configs.c).signingKeys.map((key) => logKey(key)));
  const underC = await vaultUnder(configs.c, w.memory);
  const [first, second] = await rotations();
  assert.deepEqual([first!.payload.from, first!.payload.to], [ka!.origin, kb!.origin]);
  assert.deepEqual([second!.payload.from, second!.payload.to], [kb!.origin, kc!.origin]);
  assert.deepEqual((await retired()).sort(), [ka!.mac.tag.toString('hex'), kb!.mac.tag.toString('hex')].sort());
  assert.ok((await underC.cp.tick()).signed);
  assert.ok((await w.use(underC.vault, w.secret)).ok);
  assert.ok((await w.use(underC.vault, madeUnderB)).ok);
  clean(await verify(underC.vault));
  // Every reader takes the same bounds: A's rotation, authentic under B, now a previous key; B's under C.
  const ring = await keyringOf(await verifierKeys(resolveVaultConfig(configs.c).signingKeys), logStore(db.vault));
  assert.deepEqual(ring.previous.map((p) => p.until), [second!.number, first!.number]);
  // A restart under C writes no third rotation, and the log still checks clean.
  await underC.cp.close();
  const again = await vaultUnder(configs.c, w.memory);
  assert.equal((await rotations()).length, 2);
  assert.ok((await again.vault.admit({ actor: ROOT, principal: 'user:bo@acme.example' })).ok);
  clean(await verify(again.vault));
  // An entry under A or under B past its own rotation: refused by the check and the tick.
  const pastA = await plantUse(w.old.keys.mac);
  const pastB = await plantUse(underB.keys.mac);
  const problems = (await verify(again.vault)).problems;
  assert.deepEqual(problems, [pastA, pastB].map((n) => `${n}: under a key the log moved on from, past its rotation`));
  const tick = await again.cp.tick();
  assert.ok(!tick.signed);
  assert.deepEqual(tick.failures, problems);
});

test('two rotations, A to B to C, and someone who holds A and B: a rotation from A planted under B past B\'s own counts for nothing, the vault\'s deleted or not (ChainRule, Fable\'s review r6)', async () => {
  const [a, b, c] = [b64(), b64(), b64()];
  const configs = {
    a: { kek: { id: 'vault-a', key: a }, owners },
    b: { kek: { id: 'vault-b', key: b }, previousKeks: [{ id: 'vault-a', key: a }], owners },
    c: { kek: { id: 'vault-c', key: c }, previousKeks: [{ id: 'vault-b', key: b }, { id: 'vault-a', key: a }], owners },
  } satisfies Record<string, VaultConfig>;
  const w = await underOldKey(configs.a);
  await w.old.cp.close();
  const underB = await vaultUnder(configs.b, w.memory);
  assert.ok((await underB.cp.tick()).signed);
  await underB.cp.close();
  const underC = await vaultUnder(configs.c, w.memory);
  assert.ok((await underC.cp.tick()).signed);
  const [first, second] = await rotations();
  const [, kb, ka] = await Promise.all(resolveVaultConfig(configs.c).signingKeys.map((key) => logKey(key)));
  const keys = await verifierKeys(resolveVaultConfig(configs.c).signingKeys);
  const bounds = async () => (await keyringOf(keys, logStore(db.vault))).previous.map((p) => p.until);
  assert.deepEqual(await bounds(), [second!.number, first!.number]);
  // A rotation from A into B, MAC'd under B, at the number it names: authentic, and past B's own rotation, where B
  // vouches for nothing. A use under A below it, which such a rotation would vouch for.
  const plant = async () => {
    const use = await plantUse(ka!.mac);
    // The fence's `retired` emptied first: a row she writes, and its trigger would refuse a change under B.
    await run(db.owner, sql`UPDATE checkpoint_fence SET retired = '{}'`);
    const [next] = await rows<{ n: string | number }>(db.owner, sql`SELECT nextval('log_number') AS n`);
    const number = BigInt(next!.n);
    const row = { at: Date.now(), requestId: randomUUID(), object: KEY_OBJECT, actor: 'system:vault', payload: rotationPayload(ka!.origin, kb!.origin, number), seal: null };
    await run(db.owner, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac) VALUES (${number}, ${row.at}, ${row.requestId}, ${KEY_OBJECT}, 'system:vault', ${row.payload}, NULL, ${entryMac(kb!.mac, { tree: 'changes', row })})`);
    assert.ok(second!.number < use && use < number);
    return { use, number };
  };
  // Beside the vault's own rotation from A: A's bound stays the vault's.
  const one = await plant();
  assert.deepEqual(await bounds(), [second!.number, first!.number]);
  // The vault's own deleted: A vouches for nothing, never up to the planted one (a rotation counting on its MAC alone
  // would have given A the planted rotation's number, and vouched for the use below it).
  await run(db.owner, sql`DELETE FROM log_changes WHERE number = ${first!.number}`);
  const two = await plant();
  assert.deepEqual(await bounds(), [second!.number, -1n]);
  const problems = (await verify(underC.vault)).problems;
  for (const n of [one.use, two.use]) assert.ok(problems.includes(`${n}: under a key the log moved on from, past its rotation`), JSON.stringify(problems));
  // vouch, the same keyring: a use under A between B's rotation and the planted one is forged.
  const vouched = (number: bigint) => {
    const row = { at: Date.now(), requestId: 7n, credential: randomUUID(), secret: randomUUID(), purpose: 1, place: null };
    return { tree: 'uses', number: String(number), at: row.at, requestId: String(row.requestId), credential: row.credential, secret: row.secret, purpose: 1, place: null, mac: entryMac(ka!.mac, { tree: 'uses', row }).toString('hex') } as const;
  };
  assert.deepEqual((await underC.vault.vouch!({ entries: [vouched(two.use)] })).forged, [String(two.use)]);
});

test('a rotation over a database whose fence row is gone fails whole: no rotation, no key left unretired past it (Fable\'s review r6)', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  await w.old.cp.close();
  await run(db.owner, sql`DELETE FROM checkpoint_fence`);
  try {
    // Postgres's says it in the failed query's cause.
    await assert.rejects(vaultUnder(rotation.after, w.memory), (e: Error) => /the log's fence row is gone/.test(`${e.message} ${(e.cause as Error | undefined)?.message}`));
    assert.deepEqual(await rotations(), []);
  } finally {
    // Put back for the tests after (`empty` updates the row, it never makes it).
    await run(db.owner, sql`INSERT INTO checkpoint_fence (only_row, at_floor) VALUES (true, 0)`);
  }
});

test('a pair the old key signs over its own rotation is refused, by the next start and by the check (RotationProbed)', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  await w.old.cp.close();
  const now = await vaultUnder(rotation.after, w.memory);
  // Its first call made (the cutover's seal, through its checkpointer) before that one closes (T169: closed for good).
  clean(await verify(now.vault));
  await now.cp.close();
  // Someone who holds the old key signs a pair over the window, the rotation in it, its MACs taken on faith.
  const [, previous] = resolveVaultConfig(rotation.after).signingKeys;
  const oldKey = await logKey(previous!);
  const forger = await Checkpointer.open(logStore(db.vault), oldKey.signers, { memory: variableMemory(), authentic: () => true });
  assert.ok((await forger.tick()).signed);
  const [moved] = await rotations();
  assert.ok(forger.pair.pair.upto >= moved!.number);
  const problem = `checkpoint ${forger.pair.pair.upto}: under ${oldKey.origin}, at or past the rotation that retired it (${moved!.number})`;
  assert.ok((await verify(now.vault)).problems.includes(problem));
  await assert.rejects(vaultUnder(rotation.after, variableMemory()), /at or past the rotation that retired it/);
});

test('a pair the old key signs above the signer\'s first pair under the new key is refused, by the next start and by the check (AnchorKeyHeld)', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  await w.old.cp.close();
  const now = await vaultUnder(rotation.after, w.memory);
  assert.ok((await now.cp.tick()).signed);
  await now.cp.close();
  const [moved] = await rotations();
  // Someone who holds the old key and writes the database: the new key's pairs and the rotation's row gone, a pair under
  // the old key above them, the same entries and the rotation's leaf kept, so that every consistency proof holds.
  assert.ok((await w.use(now.vault, w.secret)).ok);
  const [, previous] = resolveVaultConfig(rotation.after).signingKeys;
  const oldKey = await logKey(previous!);
  const before = BigInt((await rows<{ upto: string | number }>(db.owner, sql`SELECT max(upto) AS upto FROM log_checkpoints WHERE upto < ${moved!.number}`))[0]!.upto);
  const newer = await rows<Record<string, unknown>>(db.owner, sql`SELECT * FROM log_checkpoints WHERE upto > ${before}`);
  await run(db.owner, sql`DELETE FROM log_checkpoints WHERE upto > ${before}`);
  const forger = await Checkpointer.open(logStore(db.vault), oldKey.signers, { memory: variableMemory(), authentic: () => true });
  assert.ok((await forger.tick()).signed);
  await run(db.owner, sql`DELETE FROM log_changes WHERE number = ${moved!.number}`);
  assert.ok(forger.pair.pair.upto > now.cp.pair.pair.upto);
  const check = await verify(now.vault);
  assert.ok(check.problems.some((p) => p.includes('a replaced key, at or past the pair held outside under the current key')), check.problems.join('\n'));
  await assert.rejects(vaultUnder(rotation.after, w.memory), /a key the signer replaced, at or past the pair it remembers under its own/);
  assert.ok(newer.length > 0);
});

test('a pair the old key signs at the very place of the signer\'s pair under the new key, its heads, time and floor, is refused by the check as by the next start (AnchorKeyHeld, Muse\'s review r7)', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  await w.old.cp.close();
  const now = await vaultUnder(rotation.after, w.memory);
  // Its first call made (the cutover's seal, through its checkpointer) before that one closes (T169: closed for good).
  clean(await verify(now.vault));
  await now.cp.tick();
  await now.cp.close();
  const [moved] = await rotations();
  const held = now.cp.pair.pair;
  assert.ok(held.upto >= moved!.number);
  // Someone who holds the old key and writes the database: the rotation's row gone, the newest row signed again under the
  // old key, every number of it the same (the walk takes it for the held pair), and a use under the old key above it.
  const [, previous] = resolveVaultConfig(rotation.after).signingKeys;
  const oldKey = await logKey(previous!);
  const forged = await signPair(oldKey.signers, held.upto, held.at, { changes: held.changes, uses: held.uses }, held.floor, held.prev);
  assert.equal(signer(forged.notes), oldKey.origin);
  await run(db.owner, sql`UPDATE log_checkpoints SET changes_note = ${forged.notes.changes}, uses_note = ${forged.notes.uses} WHERE upto = ${held.upto}`);
  const planted = await plantUse(w.old.keys.mac);
  assert.ok(planted > held.upto);
  await run(db.owner, sql`DELETE FROM log_changes WHERE number = ${moved!.number}`);
  const check = await verify(now.vault);
  assert.ok(!check.ok);
  assert.ok(check.problems.includes(`checkpoint ${held.upto}: under ${oldKey.origin}, a replaced key, at or past the pair held outside under the current key (up to ${held.upto})`), check.problems.join('\n'));
  await assert.rejects(vaultUnder(rotation.after, w.memory), /a key the signer replaced, at or past the pair it remembers under its own/);
});

test('a replaced key, back as the signing key, signs nothing: the rotation that retired it stands (KeyNeverBack)', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  await w.old.cp.close();
  const now = await vaultUnder(rotation.after, w.memory);
  await now.cp.tick();
  await now.cp.close();
  // The config rolled back: the old key signs, the new one kept as previous.
  const [current, previous] = resolveVaultConfig(rotation.after).signingKeys;
  await assert.rejects(openLogCheckpointer({ store: logStore(db.vault), signingKeys: [previous!, current!], memory: w.memory }), /the log moved on from this signer's key/);
});

test('the check holds a page to its keys: no previous key, no pair under one', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  await w.old.cp.close();
  // A deploy that dropped the old key: the log's pairs and memory under it open under none.
  const alone = { ...rotation.after, previousKeks: [] };
  await assert.rejects(vaultUnder(alone, w.memory), /the signer remembers a pair it did not sign/);
  await assert.rejects(vaultUnder(alone, variableMemory()), /is not a pair signed by this log/);
});

test('every MAC names its key in its first four bytes, the key\'s tag, and holds under that key alone', () => {
  const [a, b] = [logMacKey(randomBytes(32)), logMacKey(randomBytes(32))];
  const row = { at: 1, requestId: 2n, credential: randomUUID(), secret: randomUUID(), purpose: 1, place: null };
  const mac = entryMac(a, { tree: 'uses', row });
  assert.equal(mac.length, 16);
  assert.ok(mac.subarray(0, 4).equals(a.tag));
  const entry = { tree: 'uses' as const, number: 1n, at: 1, columns: [1n, 2n, row.credential, row.secret, 1, null, mac] };
  assert.ok(authentic(a)(entry));
  assert.ok(!authentic(b)(entry));
  // The same HMAC under another tag is no MAC of either.
  assert.ok(!authentic(a)({ ...entry, columns: [...entry.columns.slice(0, -1), Buffer.concat([b.tag, mac.subarray(4)])] }));
});

test('config: a rotation keeps the replaced signing key, after the one the vault signs with', () => {
  const [a, b, s1, s2] = [b64(), b64(), b64(), b64()];
  const local = resolveVaultConfig({ kek: { id: 'vault-b', key: b }, previousKeks: [{ id: 'vault-a', key: a }], owners }).signingKeys;
  const derivedA = resolveVaultConfig({ kek: { id: 'vault-a', key: a }, owners }).signingKeys[0]!;
  const derivedB = resolveVaultConfig({ kek: { id: 'vault-b', key: b }, owners }).signingKeys[0]!;
  assert.deepEqual(local, [derivedB, derivedA]);
  assert.deepEqual(resolveVaultConfig({ kek: kms, signingKey: s2, previousSigningKeys: [s1], owners }).signingKeys, [Buffer.from(s2, 'base64'), Buffer.from(s1, 'base64')]);
  assert.throws(() => resolveVaultConfig({ kek: kms, signingKey: s2, previousSigningKeys: ['short'], owners }), /previousSigningKeys\[0\] must be 32 bytes/);
});

test('no two of the vault\'s signing keys may share a log tag, replaced ones included: the database tells their entries apart by it (review r5 of #444)', async () => {
  const [a, b] = [randomBytes(32), randomBytes(32)];
  await assert.rejects(logKeys([b, a, b]), /the signing key's log tag is that of a key it replaced/);
  await assert.rejects(logKeys([b, a, a]), /two keys the signing key replaced share a log tag/);
  const { previous } = await logKeys([b, a]);
  assert.equal(previous.length, 1);
});
