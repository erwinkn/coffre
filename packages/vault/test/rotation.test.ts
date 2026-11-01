// 0.15's log across a rotation of the vault's signing key (T168; formal/Rotation.tla; docs/design/audit-tree.md, "A
// rotation"): a vault and its checkpointer under the old key, then the deploy to the new one, the old key kept to verify
// what came before. A local KEK rotated (its signing key derived from it) and a key service's explicit signingKey
// rotated (the old one in previousSigningKeys) give the vault the same list of signing keys, the new first; each is run
// here end to end, on both engines.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { encrypt, freshDek } from '@coffre/core/envelope';
import { KekRegistry, LocalKekProvider, type KekProvider } from '@coffre/core/kek';
import { decodePair, encodePair, splitNote, type PairNotes } from '@coffre/core/merkle';
import type { TreeVerification, UseOutcome } from '@coffre/core/vault';
import { tablesOf, type Database } from '@coffre/db';
import { sql } from 'drizzle-orm';

import { genesisCall, type ChangeKeys } from '../src/changes.ts';
import { Checkpointer, type Memory, type SealThrough } from '../src/checkpointer.ts';
import { resolveVaultConfig, type ResolvedVaultConfig, type VaultConfig } from '../src/config.ts';
import { sealKey, type Input, type Ref } from '../src/inputs.ts';
import { openLocalVault } from '../src/local.ts';
import { openLogCheckpointer, logKey } from '../src/log-checkpointer.ts';
import { authentic, entryMac, KEY_OBJECT, logMacKey } from '../src/log-entry.ts';
import { logStore } from '../src/log-store.ts';
import { credentialObject, environmentObject, secretObject } from '../src/objects.ts';
import * as store from '../src/store.ts';
import { newRequestId } from '../src/use.ts';
import { variableMemory } from './audit-tree.ts';
import { cutOver, emptyDatabase, ENGINE, openTestDatabase, places, rows, run, sealed, speaking, type LocalVault, type TestDatabase } from './database.ts';

const ROOT = 'user:root@acme.example';
const ADA = 'user:ada@acme.example';
const owners = ['root@acme.example'];

let db: TestDatabase;
let hot: Database;
/** The KEK the instance wraps values with, the same across the deploy: what rotates here is the key the vault signs with. */
let keks: KekRegistry;
before(async () => {
  db = await openTestDatabase();
  hot = ENGINE === 'postgres' ? await db.hot() : db.vault;
});
after(() => db.close());
beforeEach(async () => {
  keks = new KekRegistry(LocalKekProvider.generate('test-kek-1'));
  await emptyDatabase(db.owner);
  for (const table of ['log_uses', 'log_bulk', 'log_checkpoints', 'log_tiles']) await run(db.owner, sql.raw(`DELETE FROM ${table}`));
  await run(db.owner, ENGINE === 'postgres' ? sql`UPDATE log_fence SET at_floor = ${Date.now() - 60_000}, retired = '{}'` : sql`UPDATE log_fence SET at_floor = ${Date.now() - 60_000}, retired = '[]'`);
  if (ENGINE === 'postgres') {
    const today = new Date().toISOString().slice(0, 10);
    await run(db.owner, sql`SELECT make_day(${today}::date - 1), make_day(${today}::date), make_day(${today}::date + 1)`);
  }
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
  const vault = speaking(await openLocalVault(db.vault, resolved, { log: '0.15', sealThrough, heldOutside }, async () => {}, hot));
  const keys: ChangeKeys = { seals: resolved.signingKeys.map((seed) => sealKey(seed)), mac: logMacKey(resolved.signingKeys[0]!) };
  return { config: resolved, cp, vault, keys, memory, alarms };
}

/** The log as the old key leaves it: dev, Ada with a grant there, her session and a key with a value, each sealed; uses of it. */
async function underOldKey(config: VaultConfig) {
  const memory = variableMemory();
  const old = await vaultUnder(config, memory);
  await cutOver(old.vault, db.vault);
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
  const t = tablesOf(db.owner);
  const credential = randomUUID();
  const expires = new Date(Date.now() + 86_400_000);
  await db.owner.insert(t.credentials).values({
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
    await db.owner.insert(t.secretVersions).values({
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
  .map((r) => ({ number: BigInt(r.number), payload: JSON.parse(r.payload) as { op: string; from: string; to: string } }));

/** The fence's retired tags, hex. */
async function retired(): Promise<string[]> {
  if (ENGINE === 'postgres') return (await rows<{ tag: string }>(db.owner, sql`SELECT encode(unnest(retired), 'hex') AS tag FROM log_fence`)).map((r) => r.tag);
  return JSON.parse((await rows<{ retired: string }>(db.owner, sql`SELECT retired FROM log_fence`))[0]!.retired) as string[];
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
    assert.deepEqual(moved?.payload, { ref: { kind: 'log', id: 'key' }, op: 'rotate', from: oldKey.origin, to: newKey.origin });
    assert.deepEqual(await retired(), [oldKey.mac.tag.toString('hex')]);
    assert.ok(alarms.some((a) => a.includes(`moves on from ${oldKey.origin}`)), alarms.join('\n'));
    // Its first tick seals the rotation under the new key, and remembers that pair.
    assert.ok((await now.cp.tick()).signed);
    assert.equal(signer(now.cp.pair.notes), newKey.origin);
    assert.equal(signer(decodePair(w.memory.record!)!), newKey.origin);
    assert.ok(now.cp.pair.pair.upto >= moved!.number);
    // Changes seal, uses go on, a key made since uses its new seals, and the log checks clean.
    const t = tablesOf(db.owner);
    assert.ok((await now.vault.admit({ actor: ROOT, principal: 'user:bo@acme.example' })).ok);
    const used = await w.use(now.vault, w.secret);
    assert.ok(used.ok, JSON.stringify(used));
    assert.ok((await w.use(now.vault, await w.key(now))).ok);
    assert.equal((await db.owner.select().from(t.logFence)).length, 1);
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
  const early = speaking(await openLocalVault(db.vault, resolved, { log: '0.15', sealThrough: sealed, heldOutside: async () => [] }, async () => {}, hot));
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

test('an entry under the old key past the rotation is refused by the tick and named by the check (BoundaryChecked)', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  await w.old.cp.close();
  const now = await vaultUnder(rotation.after, w.memory);
  // A use under the old key, numbered past the rotation, as someone who holds it writes it: past the fence, which no
  // trigger guards on log_uses (use_credential refuses it, which a writer goes around).
  const at = Date.now();
  const row = { at, requestId: BigInt(newRequestId()), credential: randomUUID(), secret: randomUUID(), purpose: 1, place: null };
  const mac = entryMac(w.old.keys.mac, { tree: 'uses', row });
  const [forged] = await rows<{ number: string | number }>(db.owner, ENGINE === 'postgres'
    ? sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place) VALUES (nextval('log_number'), ${at}, ${row.requestId}, ${row.credential}, ${row.secret}, 1, ${mac}, NULL) RETURNING number`
    : sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place) VALUES ((SELECT max(n) + 1 FROM (SELECT max(number) AS n FROM log_changes UNION ALL SELECT max(number) FROM log_uses)), ${at}, ${row.requestId}, ${row.credential}, ${row.secret}, 1, ${mac}, NULL) RETURNING number`);
  const check = await verify(now.vault);
  assert.deepEqual(check.problems, [`${forged!.number}: under a key the log moved on from, past its rotation`]);
  const tick = await now.cp.tick();
  assert.deepEqual(tick.failures, [`${forged!.number}: under a key the log moved on from, past its rotation`]);
  assert.ok(!tick.signed);
});

test('a pair the old key signs over its own rotation is refused, by the next start and by the check (RotationProbed)', async () => {
  const rotation = ROTATIONS[0]!;
  const w = await underOldKey(rotation.before);
  await w.old.cp.close();
  const now = await vaultUnder(rotation.after, w.memory);
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
  assert.ok(check.problems.some((p) => p.includes('a replaced key, past the pair held outside under the current key')), check.problems.join('\n'));
  await assert.rejects(vaultUnder(rotation.after, w.memory), /a key the signer replaced, at or past the pair it remembers under its own/);
  assert.ok(newer.length > 0);
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
