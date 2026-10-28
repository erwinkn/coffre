// 0.15's verifier (docs/design/0.15-plan.md, PR 8; verifier.ts): a page's check from the newest pair, and the whole
// walk, the trees, every entry's MAC and request, the replay and the row audit, over a vault that keeps 0.15's log
// under a real checkpointer, on both engines. Changes are the vault's own (admit, setAccess) and the cutover's genesis;
// uses go through the use path. Each tampering case is one the plan names: a row put back, an entry deleted before and
// after its seal, numbers swapped inside the window.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { encrypt, freshDek } from '@coffre/core/envelope';
import { decodePair, openPair, type LogEntry } from '@coffre/core/merkle';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { TreesBusy, TreeVerification, UseOutcome } from '@coffre/core/vault';
import { tablesOf, type Database } from '@coffre/db';
import { eq, sql } from 'drizzle-orm';

import { genesisCall, type ChangeKeys } from '../src/changes.ts';
import { FRESH_MS, type SealThrough } from '../src/checkpointer.ts';
import type { ResolvedVaultConfig } from '../src/config.ts';
import { noEdits, ROLES_REF, sealKey, type Input, type Ref } from '../src/inputs.ts';
import { openLocalVault } from '../src/local.ts';
import { entryMac, logMacKey, RETENTION_ACTOR, RETENTION_OBJECT, retentionPayload } from '../src/log-entry.ts';
import { openLogCheckpointer } from '../src/log-checkpointer.ts';
import { logStore } from '../src/log-store.ts';
import { credentialObject, environmentObject, secretObject } from '../src/objects.ts';
import * as store from '../src/store.ts';
import { DAY_MS, dayOf } from '../src/retention.ts';
import { newRequestId } from '../src/use.ts';
import { Requests, verifierKeys, weightOf } from '../src/verifier.ts';
import type { VaultOptions } from '../src/vault.ts';
import { variableMemory } from './audit-tree.ts';
import { emptyDatabase, ENGINE, openTestDatabase, places, rows, run, speaking, type TestDatabase } from './database.ts';

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

/** A check's verdict, which no test here finds refused as busy. */
function checkedOf(answer: TreeVerification | TreesBusy): Checked {
  assert.ok(!('busy' in answer) && answer.kept, JSON.stringify(answer));
  return answer;
}

/**
 * A vault keeping 0.15's log, each change sealed by a checkpointer of its
 * own before it answers, unless `hold` keeps the next ones in the window
 * (sealed at the next `tick`). A member, Ada, with a grant on `dev`; Bo, a service account, granted by `grant`, her
 * credential and a key there, each sealed; `walks.whole` entries a whole walk.
 */
async function instance(walks: VaultOptions['walks'] = {}) {
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
  const vault = speaking(await openLocalVault(db.vault, config, { log: '0.15', sealThrough, heldOutside, walks }, async () => {}, hot));
  const keys: ChangeKeys = { seals: [sealKey(seed)], mac: logMacKey(seed) };
  const where = await places(db.owner);
  const genesis = async (ref: Ref, input: Input) => {
    const [number] = await db.vault.transaction((tx) => store.changeInputs(tx, [genesisCall(keys, ref, input, Date.now(), 'system:cutover')]));
    assert.ok(number !== null && number !== undefined, `${ref.kind} ${ref.id} sealed`);
    await cp.sealThrough(number);
  };
  // The instance's roles and its dev environment, as the cutover seals them.
  assert.equal((await vault.access(ROOT)).role, 'owner');
  await genesis(ROLES_REF, noEdits());
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
  await genesis({ kind: 'credential', id: credential }, credentialObject({ id: credential, principal: ADA, kind: 'cli', scope: null, revoked: false, expiresAt: expires.getTime() }));
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
  /** A page's check, or (`whole`) the walk from the first entry. */
  const verify = async (input: { whole?: boolean } = {}): Promise<Checked> => {
    const checked = checkedOf(await vault.verifyTrees!(input));
    assert.equal(checked.whole, input.whole === true);
    return checked;
  };
  const whole = () => verify({ whole: true });
  const grant = (principal: string, role: string | null, environmentId = where.dev) =>
    vault.setAccess({ actor: ROOT, principal, ...(role === null ? {} : { admit: true }), changes: [{ projectId: where.project, environmentId, role, expiresAt: null }] });
  /** Another vault over the same log and signer, walking `walks` a call. */
  const reopened = async (walks: VaultOptions['walks']) => speaking(await openLocalVault(db.vault, config, { log: '0.15', sealThrough, heldOutside, walks }, async () => {}, hot));
  return { vault, cp, control, config, seed, keys, ...where, credential, secret, key, use, verify, whole, grant, genesis, reopened };
}

/** A check that found nothing, and reached the present. */
function clean(checked: Checked): void {
  assert.deepEqual(checked.problems, []);
  assert.ok(checked.ok && checked.tooLarge === null, JSON.stringify(checked));
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

test('a log the vault wrote verifies, walked whole and on a page\'s check; with 0.14\'s alone there is none', async () => {
  const w = await instance();
  for (let i = 0; i < 3; i += 1) assert.ok((await w.use()).ok);
  assert.ok((await w.grant(BO, 'viewer')).ok);
  await w.cp.tick();
  // One use above the newest pair: walked unsealed, and the rows already hold what it moved.
  assert.ok((await w.use(await w.key())).ok);
  const checked = await w.whole();
  clean(checked);
  assert.equal(checked.unsealed, 1);
  assert.ok(checked.sealed >= 9, `${checked.sealed} sealed`);
  assert.equal(checked.checkpoint?.upto, w.cp.pair.pair.upto.toString());
  clean(await w.verify());

  const old = await openLocalVault(db.vault, w.config, {}, async () => {}, hot);
  assert.deepEqual(await old.verifyTrees!({}), { kept: false });
  assert.deepEqual(await old.verifyTrees!({ whole: true }), { kept: false });
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
  assert.deepEqual([page.checkpoints, page.sealed, page.unsealed], [0, 0, 3], 'only the entries above the newest pair');
  assert.equal(page.checkpoint?.upto, w.cp.pair.pair.upto.toString());
  // A row written around the vault is the whole walk's to find: the page reads none.
  const { credentials } = tablesOf(db.owner);
  await db.owner.update(credentials).set({ expiresAt: new Date(Date.now() + 7 * 86_400_000) }).where(eq(credentials.id, w.credential));
  clean(await w.verify());
  assert.deepEqual((await w.whole()).problems, [`the credential ${w.credential}: its rows are not the object the log makes`]);
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
    assert.ok((await w.whole()).problems.includes(gone));
    await run(db.owner, sql`CREATE UNIQUE INDEX log_changes_request_id_key ON log_changes (number)`);
    assert.ok((await w.verify()).problems.includes(gone), 'a decoy over the number');
    await run(db.owner, sql`DROP INDEX log_changes_request_id_key`);
  } finally {
    await run(db.owner, add);
  }
  clean(await w.verify());
});

test('a row put back from before a revoke is named: its seal is an older change\'s', async () => {
  const w = await instance();
  assert.ok((await w.grant(BO, 'viewer')).ok);
  const [before] = await rows<{ seal: Buffer }>(db.owner, sql`SELECT seal FROM vault_members WHERE principal = ${BO}`);
  const grants = await rows<Record<string, unknown>>(db.owner, sql`SELECT * FROM vault_grants WHERE principal = ${BO}`);
  assert.ok((await w.grant(BO, null)).ok);
  clean(await w.whole());
  // The writer puts the member's row and grant back as they were before the revoke: sealed by the vault, once.
  await run(db.owner, sql`UPDATE vault_members SET seal = ${before!.seal} WHERE principal = ${BO}`);
  const { vaultGrants } = tablesOf(db.owner);
  await db.owner.insert(vaultGrants).values(grants.map((g) => ({
    principal: g.principal as string, projectId: g.project_id as string | null, environmentId: g.environment_id as string | null, environmentSlug: g.environment_slug as string | null,
    role: g.role as string, expiresAt: g.expires_at === null ? null : Number(g.expires_at), grantedAt: Number(g.granted_at), grantedBy: g.granted_by as string,
  })));
  // The whole walk's audit finds it; every use of it is refused `stale` meanwhile.
  const checked = await w.whole();
  assert.ok(!checked.ok);
  assert.deepEqual(checked.problems, [`the principal ${BO}: its rows carry another change's seal than the newest: put back, or written around the vault`]);
});

test('a row written with no change, and a key\'s seal replaced, are named', async () => {
  const w = await instance();
  const { credentials } = tablesOf(db.owner);
  await db.owner.update(credentials).set({ expiresAt: new Date(Date.now() + 7 * 86_400_000) }).where(eq(credentials.id, w.credential));
  const other = await w.key();
  await run(db.owner, sql`UPDATE secrets SET seal = ${randomBytes(16)} WHERE id = ${other}`);
  const checked = await w.whole();
  assert.deepEqual(checked.problems.sort(), [
    `the credential ${w.credential}: its rows are not the object the log makes`,
    `the secret ${other}: its rows carry another change's seal than the newest: put back, or written around the vault`,
  ]);
});

test('an entry deleted after its seal: the next pair\'s heads are not the entries\'', async () => {
  const w = await instance();
  await w.use();
  assert.ok((await w.grant(BO, 'viewer')).ok);
  const [first] = await rows<{ number: string | number }>(db.owner, sql`SELECT number FROM log_uses ORDER BY number LIMIT 1`);
  await run(db.owner, sql`DELETE FROM log_uses WHERE number = ${BigInt(first!.number)}`);
  const checked = await w.whole();
  assert.ok(!checked.ok);
  assert.ok(checked.problems.some((p) => /the uses head differ from the entries: entries deleted/.test(p)), checked.problems.join('\n'));
});

test('a change\'s entry deleted before its seal: the change fails, and its row carries a seal no entry left', async () => {
  const w = await instance();
  w.control.before = async (number) => {
    await run(db.owner, sql`DELETE FROM log_changes WHERE number = ${number}`);
  };
  await assert.rejects(Promise.resolve(w.grant(BO, 'viewer')).then((outcome) => {
    if (!outcome.ok) throw new Error(JSON.stringify(outcome));
  }));
  w.control.before = null;
  await w.cp.tick();
  const checked = await w.whole();
  assert.ok(!checked.ok);
  // Its row carries the deleted entry's seal; the log's newest change of Bo is the admission before it.
  assert.deepEqual(checked.problems, [`the principal ${BO}: its rows carry another change's seal than the newest: put back, or written around the vault`]);
});

test('numbers swapped inside the window: two changes of one object, replayed out of order, fail their seals', async () => {
  // Grants at two places: each change's seal is over the member with the grants before it, so the order shows. Two
  // grants at one place would replay to the same objects either way; the row audit then names the row (its seal is
  // the one the log has as older).
  const w = await instance();
  w.control.hold = true;
  assert.ok((await w.grant(BO, 'viewer')).ok);
  assert.ok((await w.grant(BO, 'viewer', w.prod)).ok);
  w.control.hold = false;
  const [a, b] = await rows<{ number: string | number }>(db.owner, sql`SELECT number FROM log_changes ORDER BY number DESC LIMIT 2`);
  // Before the tick: the writer gives each the other's number.
  await run(db.owner, sql`UPDATE log_changes SET number = -1 WHERE number = ${BigInt(a!.number)}`);
  await run(db.owner, sql`UPDATE log_changes SET number = ${BigInt(a!.number)} WHERE number = ${BigInt(b!.number)}`);
  await run(db.owner, sql`UPDATE log_changes SET number = ${BigInt(b!.number)} WHERE number = -1`);
  assert.ok((await w.cp.tick()).signed, 'sealed as they stand: each MAC holds, the number is not under it');
  const checked = await w.whole();
  assert.ok(!checked.ok);
  assert.ok(checked.problems.some((p) => p.startsWith(`${b!.number}: its seal is not the vault's over principal ${BO}`)), checked.problems.join('\n'));
});

test('a forged use is named at its entry by the whole walk', async () => {
  const w = await instance();
  const outcome = await w.use();
  assert.ok(outcome.ok);
  await run(db.owner, sql`UPDATE log_uses SET mac = ${randomBytes(16)} WHERE number = ${BigInt(outcome.number)}`);
  // The bulk row it moved is T138's to hold to the log.
  assert.deepEqual((await w.whole()).problems, [`${outcome.number}: its MAC does not hold`]);
});

test('review r1: grants come back from the rows in any order, and a member revoked and granted again still verifies', async () => {
  const w = await instance();
  assert.ok((await w.grant(BO, 'viewer')).ok);
  assert.ok((await w.grant(BO, 'viewer', w.prod)).ok);
  assert.ok((await w.grant(BO, null)).ok);
  // The grant lands in the slot the revoke freed, ahead of the one it kept: the replay has them the other way round.
  assert.ok((await w.grant(BO, 'developer')).ok);
  clean(await w.whole());
});

test('review r2: a roles row that reads as no object is named, not thrown on', async () => {
  const w = await instance();
  await run(db.owner, sql`UPDATE log_config SET value = '"not an object"' WHERE name = 'roles'`);
  assert.deepEqual((await w.whole()).problems, ['the roles instance: its rows do not read as an object']);
  // An object of another kind, its seal left (review r12): named, never a comparison thrown on.
  await run(db.owner, sql`UPDATE log_config SET value = '{"kind":"principal"}' WHERE name = 'roles'`);
  assert.deepEqual((await w.whole()).problems, ['the roles instance: its rows do not read as an object']);
});

test('review r1: a database rolled back whole to an earlier pair is named against the signer\'s memory, on a page\'s check too', async () => {
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
  for (const checked of [await w.verify(), await w.whole()]) {
    assert.ok(!checked.ok);
    assert.ok(checked.problems.includes(named), checked.problems.join('\n'));
  }
});

test('review r1: an object whose rows are gone is named from the replay; a check asked for in another shape is refused', async () => {
  const w = await instance();
  const { credentials } = tablesOf(db.owner);
  await db.owner.delete(credentials).where(eq(credentials.id, w.credential));
  assert.deepEqual((await w.whole()).problems, [`the credential ${w.credential}: the log holds it, its rows do not`]);
  await assert.rejects(w.vault.verifyTrees!({ whole: 'yes' } as never), /verifyTrees takes `whole`/);
});

test('review r4: a check that lands between the signer remembering a pair and the database holding it is checked again, not called a deletion', async () => {
  const w = await instance();
  for (const [role, input] of [['viewer', {}], ['developer', { whole: true }]] as const) {
    assert.ok((await w.grant(BO, role)).ok);
    // The newest pair's row, gone for a moment: the signer remembers it, the database has it a tick later.
    const putBack = await newestRow();
    let restored: Promise<unknown> = Promise.resolve();
    const back = setTimeout(() => restored = putBack(), 200);
    try {
      const checked = await w.verify(input);
      await restored;
      clean(checked);
    } finally {
      clearTimeout(back);
    }
  }
});

test('a retention change in the log is the log\'s own: not replayed, and the uses below its cut not walked', async () => {
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
  clean(await w.whole());
  clean(await w.verify());
});

test('review r9: a floor raised on the newest pair\'s row hides no entry above it: every read is from the floor the pair signed', async () => {
  const w = await instance();
  const outcome = await w.use();
  assert.ok(outcome.ok);
  await run(db.owner, sql`UPDATE log_uses SET mac = ${randomBytes(16)} WHERE number = ${BigInt(outcome.number)}`);
  // The writer raises the row's floor past every use's time: its notes, and the signer's memory, unchanged.
  await run(db.owner, sql`UPDATE log_checkpoints SET at_floor = ${Date.now() + 3_600_000} WHERE upto = (SELECT max(upto) FROM log_checkpoints)`);
  for (const checked of [await w.verify(), await w.whole()]) {
    assert.ok(checked.problems.includes(`${outcome.number}: its MAC does not hold`), checked.problems.join('\n'));
  }
});

test('review r14: a whole walk weighed past its bound is refused before it reads anything; a page\'s check never is', async () => {
  const w = await instance({ whole: 50 });
  for (let i = 0; i < 4; i += 1) assert.ok((await w.use(await w.key())).ok);
  // The log's first entry forged: not read, so not said, by a walk refused before it starts.
  const [first] = await rows<{ number: string | number }>(db.owner, sql`SELECT number FROM log_changes ORDER BY number LIMIT 1`);
  await run(db.owner, sql`UPDATE log_changes SET mac = ${randomBytes(16)} WHERE number = ${BigInt(first!.number)}`);
  const refused = await w.whole();
  assert.deepEqual([refused.ok, refused.problems, refused.sealed, refused.checkpoint], [false, [], 0, null]);
  assert.match(refused.tooLarge ?? '', /^0\.15's log holds more than this vault walks in one call: .*, some [\d,]+ entries' worth of work, past its 50\. .*walk the log whole on Node/);
  // A page's check is never weighed: it reads a tick's worth.
  assert.ok((await w.verify()).kept);
});

test('review r14: the weight counts every unit of the walk: its entries and pairs, the rows it audits, its replay\'s sealing', async () => {
  const w = await instance();
  const weight = async () => weightOf(await store.walkWork(db.vault, -1n));
  const at = await weight();
  // Exactly the weight: walked whole; a unit less: refused.
  clean(checkedOf(await (await w.reopened({ whole: Math.ceil(at) })).verifyTrees!({ whole: true })));
  assert.notEqual(checkedOf(await (await w.reopened({ whole: Math.ceil(at) - 1 })).verifyTrees!({ whole: true })).tooLarge, null);
  // Rows no change made, from before the cutover: weighed one each, though no entry counts them.
  const { credentials } = tablesOf(db.owner);
  await db.owner.insert(credentials).values(Array.from({ length: 100 }, () => ({
    id: randomUUID(), kind: 'cli', authMac: Buffer.alloc(32), tokenHash: randomBytes(32), tokenHint: 'hint', generation: 0, principal: ADA, createdBy: ROOT, expiresAt: new Date(Date.now() + 86_400_000), scope: null,
  })));
  assert.equal(await weight(), at + 100);
  // The replay's sealing grows with an object's changes: forty more of one member weigh their square.
  const counted = await store.walkWork(db.vault, -1n);
  for (let i = 0; i < 20; i += 1) {
    assert.ok((await w.grant(BO, 'viewer')).ok);
    assert.ok((await w.grant(BO, null)).ok);
  }
  const after = await store.walkWork(db.vault, -1n);
  assert.ok(after.replay - counted.replay >= 40 * 40, JSON.stringify({ counted, after }));
});

test('review r14: requests are swept by entries taken, never by what the map holds', () => {
  const requests = new Requests(3);
  const entry = (at: number, id: number): LogEntry => ({ tree: 'uses', number: BigInt(id), at, columns: [BigInt(at), BigInt(id)] });
  // Each entry past the last by more than the window kept: every sweep leaves the map one entry, a third of the mark.
  for (let i = 1; i <= 9; i += 1) assert.ok(requests.once(entry(i * 3 * FRESH_MS, i)));
  assert.equal(requests.sweeps, 3);
  // Within the window, a copy is still a replay.
  assert.equal(requests.once(entry(9 * 3 * FRESH_MS, 9)), false);
});

test('review r15: grants are grouped in linear time: 50,000 of one member\'s, from before the cutover, audited at once', async () => {
  const w = await instance();
  assert.ok((await w.grant(BO, 'viewer')).ok);
  // Rows no change made: the audit names them, and must reach them in time proportional to their number.
  const { vaultGrants } = tablesOf(db.owner);
  for (let done = 0; done < 50_000; done += 2_000) {
    await db.owner.insert(vaultGrants).values(Array.from({ length: 2_000 }, (_, i) => ({
      principal: BO, projectId: null, environmentId: null, environmentSlug: `s${done + i}`, role: 'viewer', expiresAt: null, grantedAt: 0, grantedBy: ROOT,
    })));
  }
  const cpu = process.cpuUsage();
  const checked = await w.whole();
  const spent = process.cpuUsage(cpu);
  assert.ok(checked.problems.length > 0, 'the rows are not the log\'s');
  // Quadratic, the grouping alone copied 1.25 billion entries; linear, the whole walk takes about a second of CPU.
  assert.ok((spent.user + spent.system) / 1000 < 5_000, `${(spent.user + spent.system) / 1000} ms`);
});
