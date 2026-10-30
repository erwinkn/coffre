// 0.15's verifier (docs/design/0.15-plan.md, PR 8; verifier.ts): a page's check from the newest pair, every entry above
// it by its MAC and request, held to the signer's memory, over a vault that keeps 0.15's log under a real checkpointer,
// on both engines. Changes are the vault's own (admit, setAccess) and the cutover's genesis; uses go through the use
// path.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { encrypt, freshDek } from '@coffre/core/envelope';
import { decodePair, openPair } from '@coffre/core/merkle';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { TreeVerification, UseOutcome } from '@coffre/core/vault';
import { tablesOf, type Database } from '@coffre/db';
import { eq, sql } from 'drizzle-orm';

import { genesisCall, type ChangeKeys } from '../src/changes.ts';
import type { SealThrough } from '../src/checkpointer.ts';
import type { ResolvedVaultConfig } from '../src/config.ts';
import { sealKey, type Input, type Ref } from '../src/inputs.ts';
import { openLocalVault } from '../src/local.ts';
import { entryMac, logMacKey, RETENTION_ACTOR, RETENTION_OBJECT, retentionPayload } from '../src/log-entry.ts';
import { openLogCheckpointer } from '../src/log-checkpointer.ts';
import { logStore } from '../src/log-store.ts';
import { credentialObject, environmentObject, secretObject } from '../src/objects.ts';
import * as store from '../src/store.ts';
import { DAY_MS, dayOf } from '../src/retention.ts';
import { newRequestId } from '../src/use.ts';
import { verifierKeys } from '../src/verifier.ts';
import { variableMemory } from './audit-tree.ts';
import { cutOver, emptyDatabase, ENGINE, openTestDatabase, places, rows, run, speaking, type TestDatabase } from './database.ts';

const ROOT = 'user:root@acme.example';
const ADA = 'user:ada@acme.example';
const BO = 'token:bo';

let db: TestDatabase;
let hot: Database;
before(async () => {
  db = await openTestDatabase();
  hot = ENGINE === 'postgres' ? await db.hot() : db.vault;
});
after(() => db.close());
beforeEach(async () => {
  await emptyDatabase(db.owner);
  for (const table of ['log_uses', 'log_bulk', 'log_checkpoints', 'log_tiles']) await run(db.owner, sql.raw(`DELETE FROM ${table}`));
  await run(db.owner, sql`UPDATE log_fence SET at_floor = ${Date.now() - 60_000}`);
  if (ENGINE === 'postgres') {
    const today = new Date().toISOString().slice(0, 10);
    await run(db.owner, sql`SELECT make_day(${today}::date - 1), make_day(${today}::date), make_day(${today}::date + 1)`);
  }
});

type Checked = Extract<TreeVerification, { kept: true }>;

/** A check's verdict, of a vault that keeps 0.15's log. */
function checkedOf(answer: TreeVerification): Checked {
  assert.ok(answer.kept, JSON.stringify(answer));
  return answer;
}

/**
 * A vault keeping 0.15's log, each change sealed by a checkpointer of its
 * own before it answers, unless `hold` keeps the next ones in the window
 * (sealed at the next `tick`). A member, Ada, with a grant on `dev`; Bo, a service account, granted by `grant`, her
 * credential and a key there, each sealed.
 */
async function instance() {
  const config: ResolvedVaultConfig = {
    keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')),
    owners: ['root@acme.example'],
    signingKeys: [randomBytes(32)],
    bulkLimit: { count: 1000, windowMs: 15 * 60_000 },
  };
  const seed = config.signingKeys[0]!;
  const memory = variableMemory();
  const cp = await openLogCheckpointer({ store: logStore(db.vault), seed, memory });
  // The signer's memory, where no database writer reaches: what each walk is held to.
  const heldOutside = async () => {
    await control.asked?.();
    return memory.record === null ? [] : [decodePair(memory.record)!];
  };
  const control = { hold: false, before: null as null | ((number: bigint) => Promise<void>), asked: null as null | (() => Promise<void>) };
  const sealThrough: SealThrough = async (number, deadline) => {
    await control.before?.(number);
    if (control.hold) return {} as Awaited<ReturnType<SealThrough>>;
    return cp.sealThrough(number, deadline);
  };
  const opened = await openLocalVault(db.vault, config, { log: '0.15', sealThrough, heldOutside }, async () => {}, hot);
  await cutOver(opened, db.vault);
  const vault = speaking(opened);
  const keys: ChangeKeys = { seals: [sealKey(seed)], mac: logMacKey(seed) };
  const where = await places(db.owner);
  const genesis = async (ref: Ref, input: Input) => {
    const [number] = await db.vault.transaction((tx) => store.changeInputs(tx, [genesisCall(keys, ref, input, Date.now(), 'system:cutover')]));
    assert.ok(number !== null && number !== undefined, `${ref.kind} ${ref.id} sealed`);
    await cp.sealThrough(number);
  };
  // The instance's dev environment, made since the cutover (which made its roles), sealed as it would have.
  assert.equal((await vault.access(ROOT)).role, 'owner');
  await genesis({ kind: 'environment', id: where.dev }, environmentObject({ id: where.dev, projectId: where.project, slug: 'dev', owner: null, parentId: null, protected: false, archived: false, projectArchived: false }));
  assert.ok((await vault.admit({ actor: ROOT, principal: ADA })).ok);
  assert.ok((await vault.setAccess({ actor: ROOT, principal: ADA, changes: [{ projectId: where.project, environmentId: where.dev, role: 'developer', expiresAt: null }] })).ok);

  // Ada's session, and a key with a value, each sealed as it is.
  const t = tablesOf(db.owner);
  const credential = randomUUID();
  const expires = new Date(Date.now() + 86_400_000);
  await db.owner.insert(t.credentials).values({
    id: credential, kind: 'cli', authMac: Buffer.alloc(32), tokenHash: randomBytes(32), tokenHint: 'hint', generation: 0, principal: ADA, createdBy: ROOT, expiresAt: expires, scope: null,
  });
  await genesis({ kind: 'credential', id: credential }, credentialObject({ id: credential, principal: ADA, kind: 'cli', scope: null, revoked: false, expiresAt: expires.getTime(), generation: 0 }));
  const key = async () => {
    const ref = await where.secret(where.dev);
    const version = randomUUID();
    const dek = freshDek();
    const context = { projectId: where.project, environmentId: where.dev, secretId: ref.secretId };
    const sealed = encrypt(Buffer.from('postgres://dev'), context, dek);
    const wrapped = await config.keks.wrap(dek, context, { deadline: Date.now() + 5000, signal: new AbortController().signal });
    await db.owner.insert(t.secretVersions).values({
      id: version, secretId: ref.secretId, version: 1, envelopeVersion: sealed.envelopeVersion, ciphertext: sealed.ciphertext, iv: sealed.iv, authTag: sealed.authTag,
      wrappedDek: wrapped.bytes, kekProvider: wrapped.kekProvider, kekId: wrapped.kekId, kekVersion: wrapped.kekVersion, createdBy: ROOT,
    });
    await run(db.owner, sql`UPDATE secrets SET current_version_id = ${version}, current_version = 1 WHERE id = ${ref.secretId}`);
    await genesis({ kind: 'secret', id: ref.secretId }, secretObject({
      id: ref.secretId, projectId: where.project, environmentId: where.dev, source: null, reference: null,
      version: { id: version, sensitive: false, plaintext: null, kekProvider: wrapped.kekProvider, kekId: wrapped.kekId, kekVersion: wrapped.kekVersion, wrappedDek: Buffer.from(wrapped.bytes).toString('base64') },
    }));
    return ref.secretId;
  };
  const secret = await key();

  /** A use of `secretId` on Ada's session, now. */
  const use = async (secretId = secret): Promise<UseOutcome> => {
    const at = Date.now();
    return vault.use({ credential, secretId, place: null, purpose: 'run', requestId: newRequestId(), at, deadline: at + 3000 });
  };
  /** A page's check. */
  const verify = async (): Promise<Checked> => checkedOf(await vault.verifyTrees!());
  const grant = (principal: string, role: string | null, environmentId = where.dev) =>
    vault.setAccess({ actor: ROOT, principal, ...(role === null ? {} : { admit: true }), changes: [{ projectId: where.project, environmentId, role, expiresAt: null }] });
  return { vault, cp, control, config, seed, keys, ...where, credential, secret, key, use, verify, grant, genesis };
}

/** A check that found nothing, and reached the present. */
function clean(checked: Checked): void {
  assert.deepEqual(checked.problems, []);
  assert.ok(checked.ok, JSON.stringify(checked));
}

/** The newest pair's row, taken out, and a function to put it back as it was: the signer's write a moment away. */
async function newestRow() {
  const [newest] = await rows<Record<string, unknown>>(db.owner, sql`SELECT * FROM log_checkpoints ORDER BY upto DESC LIMIT 1`);
  await run(db.owner, sql`DELETE FROM log_checkpoints WHERE upto = ${BigInt(newest!.upto as string | number)}`);
  const { logCheckpoints } = tablesOf(db.owner);
  return () => db.owner.insert(logCheckpoints).values({
    upto: BigInt(newest!.upto as string | number), at: Number(newest!.at), atFloor: Number(newest!.at_floor), changesSize: BigInt(newest!.changes_size as string | number),
    changesRoot: Buffer.from(newest!.changes_root as Uint8Array), changesNote: newest!.changes_note as string, usesSize: BigInt(newest!.uses_size as string | number),
    usesRoot: Buffer.from(newest!.uses_root as Uint8Array), usesNote: newest!.uses_note as string,
  }).then(() => {});
}

test('a log the vault wrote verifies on a page\'s check; with 0.14\'s alone there is none', async () => {
  const w = await instance();
  for (let i = 0; i < 3; i += 1) assert.ok((await w.use()).ok);
  assert.ok((await w.grant(BO, 'viewer')).ok);
  await w.cp.tick();
  // One use above the newest pair: walked unsealed, and the rows already hold what it moved.
  assert.ok((await w.use(await w.key())).ok);
  const checked = await w.verify();
  clean(checked);
  assert.equal(checked.unsealed, 1);
  assert.equal(checked.checkpoint?.upto, w.cp.pair.pair.upto.toString());

  const old = await openLocalVault(db.vault, w.config, { log: '0.14' }, async () => {}, hot);
  assert.deepEqual(await old.verifyTrees!(), { kept: false });
});

test('R25: a page\'s check reads the newest pair and the entries since, whatever the log holds below it, and no row', async () => {
  const w = await instance();
  // Each a key of its own: a repeat use within its cover writes no entry (R53).
  for (let i = 0; i < 4; i += 1) await w.use(await w.key());
  const fresh = [await w.key(), await w.key(), await w.key()];
  await w.cp.tick();
  for (const secret of fresh) assert.ok((await w.use(secret)).ok);
  const page = await w.verify();
  clean(page);
  assert.deepEqual([page.unsealed, page.capped], [3, false], 'only the entries above the newest pair');
  assert.equal(page.checkpoint?.upto, w.cp.pair.pair.upto.toString());
  // A row written around the vault is not the page's to find: it reads none. Every use of it refuses it (D145): its
  // object is not the one its seal covers.
  const { credentials } = tablesOf(db.owner);
  await db.owner.update(credentials).set({ expiresAt: new Date(Date.now() + 7 * 86_400_000) }).where(eq(credentials.id, w.credential));
  clean(await w.verify());
  const refused = await w.use(await w.key());
  assert.ok(!refused.ok && 'code' in refused && refused.code === 'tampered', JSON.stringify(refused));
});

test('a page\'s check names a forged entry above the newest pair, a forged newest pair, and the indexes that keep requests unique, gone', async () => {
  const w = await instance();
  const outcome = await w.use();
  assert.ok(outcome.ok);
  await run(db.owner, sql`UPDATE log_uses SET mac = ${randomBytes(16)} WHERE number = ${BigInt(outcome.number)}`);
  assert.deepEqual((await w.verify()).problems, [`${outcome.number}: its MAC does not hold`]);
  await run(db.owner, sql`DELETE FROM log_uses WHERE number = ${BigInt(outcome.number)}`);
  // The newest pair's notes, swapped for another's: not signed by the log at that place.
  const [newest, older] = await rows<{ upto: string | number; changes_note: string }>(db.owner, sql`SELECT upto, changes_note FROM log_checkpoints ORDER BY upto DESC LIMIT 2`);
  await run(db.owner, sql`UPDATE log_checkpoints SET changes_note = ${older!.changes_note} WHERE upto = ${BigInt(newest!.upto)}`);
  assert.ok(!(await w.verify()).ok);
  await run(db.owner, sql`UPDATE log_checkpoints SET changes_note = ${newest!.changes_note} WHERE upto = ${BigInt(newest!.upto)}`);
  clean(await w.verify());
  // A copy of an entry passes a walk's own check when far enough apart, and a page's below its start; the database
  // refuses it while its index stands: gone, or one of its name over other columns (review r2).
  const [drop, add] = ENGINE === 'postgres'
    ? [sql`ALTER TABLE log_changes DROP CONSTRAINT log_changes_request_id_key`, sql`ALTER TABLE log_changes ADD CONSTRAINT log_changes_request_id_key UNIQUE (request_id)`]
    : [sql`DROP INDEX log_changes_request_id_key`, sql`CREATE UNIQUE INDEX log_changes_request_id_key ON log_changes (request_id)`];
  const gone = 'the indexes that keep each request to one entry are gone: a copy of an entry would pass';
  await run(db.owner, drop);
  try {
    assert.ok((await w.verify()).problems.includes(gone));
    await run(db.owner, sql`CREATE UNIQUE INDEX log_changes_request_id_key ON log_changes (number)`);
    assert.ok((await w.verify()).problems.includes(gone), 'a decoy over the number');
    await run(db.owner, sql`DROP INDEX log_changes_request_id_key`);
  } finally {
    await run(db.owner, add);
  }
  clean(await w.verify());
});

test('review r1: a database rolled back whole to an earlier pair is named against the signer\'s memory on a page\'s check', async () => {
  const w = await instance();
  const [earlier] = await rows<{ upto: string | number }>(db.owner, sql`SELECT max(upto) AS upto FROM log_checkpoints`);
  assert.ok((await w.grant(BO, 'viewer')).ok);
  const signed = w.cp.pair.pair.upto;
  // Every row the grant and its seal left, gone: its entries, the pairs above, Bo.
  await run(db.owner, sql`DELETE FROM log_checkpoints WHERE upto > ${BigInt(earlier!.upto)}`);
  await run(db.owner, sql`DELETE FROM log_changes WHERE number > ${BigInt(earlier!.upto)}`);
  await run(db.owner, sql`DELETE FROM vault_grants WHERE principal = ${BO}`);
  await run(db.owner, sql`DELETE FROM vault_members WHERE principal = ${BO}`);
  const named = `the database ends up to ${earlier!.upto}; a pair held outside seals up to ${signed}: entries or checkpoints were deleted`;
  const checked = await w.verify();
  assert.ok(!checked.ok);
  assert.ok(checked.problems.includes(named), checked.problems.join('\n'));
});

test('review r4: a check that lands between the signer remembering a pair and the database holding it is checked again, not called a deletion', async () => {
  const w = await instance();
  for (const role of ['viewer', 'developer']) {
    assert.ok((await w.grant(BO, role)).ok);
    // The newest pair's row, gone for a moment: the signer remembers it, the database has it a tick later.
    const putBack = await newestRow();
    let restored: Promise<unknown> = Promise.resolve();
    const back = setTimeout(() => restored = putBack(), 200);
    try {
      const checked = await w.verify();
      await restored;
      clean(checked);
    } finally {
      clearTimeout(back);
    }
  }
});

test('a retention change in the log is the log\'s own, and the uses below its cut not walked', async () => {
  const w = await instance();
  for (let i = 0; i < 3; i += 1) assert.ok((await w.use(await w.key())).ok);
  await w.cp.tick();
  // A retention change, sealed, as retention writes it (retention.ts), for a day ten days ago. Postgres's log_retention
  // holds its cut to the first pair past the day's end, the first of this log; SQLite's checks nothing, so it cuts at
  // the newest, and the uses below it are dropped.
  const store = logStore(db.vault);
  const day = dayOf(Date.now() - 10 * DAY_MS);
  const cut = (ENGINE === 'postgres' ? await store.cutAt(Date.parse(`${day}T00:00:00Z`) + DAY_MS) : await store.newest())!;
  const pair = (await openPair(cut.notes, (await verifierKeys([w.seed])).verifiers))!;
  const at = Date.now();
  const requestId = `retention:${day}`;
  const payload = retentionPayload(day, { upto: pair.upto, at: pair.at, uses: { size: pair.uses.size, root: pair.uses.root } });
  const change = await store.appendRetention({ requestId, at, payload, mac: entryMac(w.keys.mac, { tree: 'changes', row: { at, requestId, object: RETENTION_OBJECT, actor: RETENTION_ACTOR, payload, seal: null } }) });
  await w.cp.sealThrough(change);
  await run(db.owner, sql`DELETE FROM log_uses WHERE number <= ${pair.upto}`);
  clean(await w.verify());
});

test('review r9: a floor raised on the newest pair\'s row hides no entry above it: every read is from the floor the pair signed', async () => {
  const w = await instance();
  const outcome = await w.use();
  assert.ok(outcome.ok);
  await run(db.owner, sql`UPDATE log_uses SET mac = ${randomBytes(16)} WHERE number = ${BigInt(outcome.number)}`);
  // The writer raises the row's floor past every use's time: its notes, and the signer's memory, unchanged.
  await run(db.owner, sql`UPDATE log_checkpoints SET at_floor = ${Date.now() + 3_600_000} WHERE upto = (SELECT max(upto) FROM log_checkpoints)`);
  const checked = await w.verify();
  assert.ok(checked.problems.includes(`${outcome.number}: its MAC does not hold`), checked.problems.join('\n'));
});
