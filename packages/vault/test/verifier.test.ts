// 0.15's verifier (docs/design/0.15-plan.md, PR 8; verifier.ts): the trees, every entry's MAC and request, the replay
// and the row audit, over a vault that keeps 0.15's log under a real checkpointer, on both engines. Changes are the
// vault's own (admit, setAccess) and the cutover's genesis; uses go through the use path. Each tampering case is one the
// plan names: a row put back, an entry deleted before and after its seal, numbers swapped inside the window.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { encrypt, freshDek } from '@coffre/core/envelope';
import { decodePair } from '@coffre/core/merkle';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { TreeVerification, UseOutcome } from '@coffre/core/vault';
import { tablesOf, type Database } from '@coffre/db';
import { eq, sql } from 'drizzle-orm';

import { genesisCall, type ChangeKeys } from '../src/changes.ts';
import type { SealThrough } from '../src/checkpointer.ts';
import type { ResolvedVaultConfig } from '../src/config.ts';
import { noEdits, ROLES_REF, sealKey, type Input, type Ref } from '../src/inputs.ts';
import { openLocalVault } from '../src/local.ts';
import { entryMac, logMacKey } from '../src/log-entry.ts';
import { openLogCheckpointer } from '../src/log-checkpointer.ts';
import { logStore } from '../src/log-store.ts';
import { credentialObject, environmentObject, secretObject } from '../src/objects.ts';
import * as store from '../src/store.ts';
import { newRequestId } from '../src/use.ts';
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
  for (const table of ['log_uses', 'log_bulk', 'log_checkpoints', 'log_tiles', 'log_replays']) await run(db.owner, sql.raw(`DELETE FROM ${table}`));
  await run(db.owner, sql`UPDATE log_fence SET at_floor = ${Date.now() - 60_000}`);
  if (ENGINE === 'postgres') {
    const today = new Date().toISOString().slice(0, 10);
    await run(db.owner, sql`SELECT make_day(${today}::date - 1), make_day(${today}::date), make_day(${today}::date + 1)`);
  }
});

type Checked = Extract<TreeVerification, { kept: true }>;

/**
 * A vault keeping 0.15's log, each change sealed by a checkpointer of its
 * own before it answers, unless `hold` keeps the next ones in the window
 * (sealed at the next `tick`). A member, Ada, with a grant on `dev`; Bo, a service account, granted by `grant`, her
 * credential and a key there, each sealed; `walks.verify` entries a walk.
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
  const heldOutside = async () => (memory.record === null ? [] : [decodePair(memory.record)!]);
  const control = { hold: false, before: null as null | ((number: bigint) => Promise<void>) };
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
  await genesis({ kind: 'environment', id: where.dev }, environmentObject({ id: where.dev, projectId: where.project, slug: 'dev', owner: null, parentId: null, protected: false, archived: false }));
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
      id: ref.secretId, projectId: where.project, environmentId: where.dev, source: null,
      version: { id: version, sensitive: false, plain: false, kekProvider: wrapped.kekProvider, kekId: wrapped.kekId, kekVersion: wrapped.kekVersion, wrappedDek: Buffer.from(wrapped.bytes).toString('base64') },
    }));
    return ref.secretId;
  };
  const secret = await key();

  /** A use of `secretId` on Ada's session, now. */
  const use = async (secretId = secret): Promise<UseOutcome> => {
    const at = Date.now();
    return vault.use({ credential, secretId, place: null, purpose: 'run', requestId: newRequestId(), at, deadline: at + 3000 });
  };
  const verify = async (from?: string): Promise<Checked> => {
    const checked = await vault.verifyTrees!(from === undefined ? {} : { from });
    assert.ok(checked.kept);
    return checked;
  };
  const grant = (principal: string, role: string | null, environmentId = where.dev) =>
    vault.setAccess({ actor: ROOT, principal, ...(role === null ? {} : { admit: true }), changes: [{ projectId: where.project, environmentId, role, expiresAt: null }] });
  return { vault, cp, control, config, seed, keys, ...where, credential, secret, key, use, verify, grant, genesis };
}

/** A walk that found nothing, and reached the present. */
function clean(checked: Checked): void {
  assert.deepEqual(checked.problems, []);
  assert.ok(checked.ok && checked.done, JSON.stringify(checked));
}

test('a log the vault wrote verifies: both trees, every entry, the replay, every row; with 0.14\'s alone there is none', async () => {
  const w = await instance();
  for (let i = 0; i < 3; i += 1) assert.ok((await w.use()).ok);
  assert.ok((await w.grant(BO, 'viewer')).ok);
  await w.cp.tick();
  // One use above the newest pair: walked unsealed, and the rows already hold what it moved.
  assert.ok((await w.use(await w.key())).ok);
  const checked = await w.verify();
  clean(checked);
  assert.equal(checked.from, null);
  assert.equal(checked.unsealed, 1);
  assert.ok(checked.sealed >= 9, `${checked.sealed} sealed`);
  assert.equal(checked.checkpoint?.upto, w.cp.pair.pair.upto.toString());

  const old = await openLocalVault(db.vault, w.config, {}, async () => {}, hot);
  assert.deepEqual(await old.verifyTrees!({}), { kept: false });
});

test('R25: a check goes on from the replay the last walk kept, reading only the entries since; the checkpoint job keeps it moving', async () => {
  const w = await instance();
  for (let i = 0; i < 4; i += 1) await w.use();
  // Too few entries to be worth keeping: the next check reads them again.
  assert.equal((await w.verify()).from, null);
  assert.equal((await rows(db.owner, sql`SELECT 1 FROM log_replays`)).length, 0);
  // The checkpoint job's walk keeps what it replayed, however little.
  await w.vault.checkpoint();
  const [kept] = await rows<{ upto: string | number }>(db.owner, sql`SELECT upto FROM log_replays`);
  assert.ok(kept !== undefined, 'kept');
  await w.use();
  await w.cp.tick();
  const checked = await w.verify();
  clean(checked);
  assert.equal(checked.from, String(kept.upto));
  assert.equal(checked.sealed, 1, 'only the use since');
});

test('a walk from the first entry goes a stretch at a time, each ending at a pair, and the last reaches the present', async () => {
  const w = await instance({ verify: 3 });
  for (let i = 0; i < 4; i += 1) {
    await w.use();
    await w.use();
    await w.cp.tick();
  }
  const stretches: Checked[] = [];
  for (let from: string | null = 'start'; from !== null; ) {
    const checked = await w.verify(from);
    assert.deepEqual(checked.problems, []);
    stretches.push(checked);
    from = checked.next;
    assert.ok(stretches.length < 50, 'it ends');
  }
  assert.ok(stretches.length > 2, `${stretches.length} stretches`);
  assert.ok(stretches.at(-1)!.done);
  assert.ok(stretches.slice(0, -1).every((s) => !s.done && s.next !== null));
  // Each stretch starts where the one before ended.
  for (const [i, s] of stretches.slice(1).entries()) assert.equal(s.from, stretches[i]!.next);
  // A stretch named by a pair whose replay nobody kept is refused, not walked from nothing.
  const lost = await w.verify('1');
  assert.ok(!lost.ok && /no replay is kept at 1/.test(lost.problems.join()));
});

test('a row put back from before a revoke is named: its seal is an older change\'s', async () => {
  const w = await instance();
  assert.ok((await w.grant(BO, 'viewer')).ok);
  const [before] = await rows<{ seal: Buffer }>(db.owner, sql`SELECT seal FROM vault_members WHERE principal = ${BO}`);
  const grants = await rows<Record<string, unknown>>(db.owner, sql`SELECT * FROM vault_grants WHERE principal = ${BO}`);
  assert.ok((await w.grant(BO, null)).ok);
  clean(await w.verify());
  // The writer puts the member's row and grant back as they were before the revoke: sealed by the vault, once.
  await run(db.owner, sql`UPDATE vault_members SET seal = ${before!.seal} WHERE principal = ${BO}`);
  const { vaultGrants } = tablesOf(db.owner);
  await db.owner.insert(vaultGrants).values(grants.map((g) => ({
    principal: g.principal as string, projectId: g.project_id as string | null, environmentId: g.environment_id as string | null, environmentSlug: g.environment_slug as string | null,
    role: g.role as string, expiresAt: g.expires_at === null ? null : Number(g.expires_at), grantedAt: Number(g.granted_at), grantedBy: g.granted_by as string,
  })));
  const checked = await w.verify();
  assert.ok(!checked.ok);
  assert.deepEqual(checked.problems, [`the principal ${BO}: its rows carry another change's seal than the newest: put back, or written around the vault`]);
});

test('a row written with no change, and a key\'s seal replaced, are named', async () => {
  const w = await instance();
  const { credentials } = tablesOf(db.owner);
  await db.owner.update(credentials).set({ expiresAt: new Date(Date.now() + 7 * 86_400_000) }).where(eq(credentials.id, w.credential));
  const other = await w.key();
  await run(db.owner, sql`UPDATE secrets SET seal = ${randomBytes(16)} WHERE id = ${other}`);
  const checked = await w.verify();
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
  const checked = await w.verify();
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
  const checked = await w.verify();
  assert.ok(!checked.ok);
  // Its row carries the deleted entry's seal; the log's newest change of Bo is the admission before it.
  assert.deepEqual(checked.problems, [`the principal ${BO}: its rows carry another change's seal than the newest: put back, or written around the vault`]);
});

test('a use\'s entry deleted before its seal leaves its bulk row with no use the log has: the bulk audit names it', async () => {
  const w = await instance();
  const outcome = await w.use(await w.key());
  assert.ok(outcome.ok);
  await run(db.owner, sql`DELETE FROM log_uses WHERE number = ${BigInt(outcome.number)}`);
  await w.cp.tick();
  const checked = await w.verify();
  assert.ok(!checked.ok);
  assert.ok(checked.problems.some((p) => p.startsWith(`the bulk cap of ${ADA}: its row for `) && p.endsWith(', the log none')), checked.problems.join('\n'));
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
  const checked = await w.verify();
  assert.ok(!checked.ok);
  assert.ok(checked.problems.some((p) => p.startsWith(`${b!.number}: its seal is not the vault's over principal ${BO}`)), checked.problems.join('\n'));
});

test('a kept replay the vault did not write is named and passed over, never gone on from, and the job\'s next replay forgets it', async () => {
  const w = await instance();
  await w.vault.checkpoint();
  const [kept] = await rows<{ upto: string | number }>(db.owner, sql`SELECT upto FROM log_replays`);
  // A writer edits the replay, hoping the check goes on from it, and plants one at a pair to come, hoping to stop every
  // check after (review r3).
  await run(db.owner, sql`UPDATE log_replays SET state = replace(state, '"developer"', '"viewer"')`);
  await run(db.owner, sql`INSERT INTO log_replays (upto, at, state, mac) VALUES (900000000, 0, '{}', ${randomBytes(32)})`);
  const named = (upto: string | number) => `the replay kept at ${upto} is not the vault's over the checkpoint there: passed over`;
  const checked = await w.verify();
  assert.deepEqual(checked.problems, [named(900000000), named(kept!.upto)]);
  assert.equal(checked.from, null, 'from the first entry, the only start left');
  assert.ok(checked.done);
  // Asked for by its pair, it is refused; the walk from the first entry does not read it.
  assert.match((await w.verify(String(kept!.upto))).problems.join(), /is not the vault's over the checkpoint there: walk again/);
  clean(await w.verify('start'));
  // The job keeps a replay of its own, and forgets the two: the checks after go on from it, as before.
  await w.vault.checkpoint();
  const after = await w.verify();
  clean(after);
  assert.notEqual(after.from, null);
  assert.equal((await rows(db.owner, sql`SELECT 1 FROM log_replays WHERE upto = 900000000`)).length, 0);
});

test('a forged use is named at its entry, and so are the indexes that keep requests unique, gone', async () => {
  const w = await instance();
  const outcome = await w.use();
  assert.ok(outcome.ok);
  await run(db.owner, sql`UPDATE log_uses SET mac = ${randomBytes(16)} WHERE number = ${BigInt(outcome.number)}`);
  const checked = await w.verify();
  // Not the vault's, so not replayed: the bulk row it moved is one the log does not.
  assert.equal(checked.problems[0], `${outcome.number}: its MAC does not hold`);
  assert.match(checked.problems[1]!, new RegExp(`^the bulk cap of ${ADA}: its row for .* says \\d+, the log none$`));
  // A copy of an entry passes the walk's own check across two stretches; the database refuses it, while its index stands:
  // gone, or one of its name over other columns (review r2).
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
  assert.ok(!(await w.verify()).problems.includes(gone));
});

test('review r1: grants come back from the rows in any order, and a member revoked and granted again still verifies', async () => {
  const w = await instance();
  assert.ok((await w.grant(BO, 'viewer')).ok);
  assert.ok((await w.grant(BO, 'viewer', w.prod)).ok);
  assert.ok((await w.grant(BO, null)).ok);
  // The grant lands in the slot the revoke freed, ahead of the one it kept: the replay has them the other way round.
  assert.ok((await w.grant(BO, 'developer')).ok);
  clean(await w.verify());
});

test('review r2: a page\'s check says what the checkpoint job\'s audit of every row found, and when; on a quiet log too, until it is put right', async () => {
  const w = await instance();
  await w.vault.checkpoint();
  const kept = await w.verify();
  clean(kept);
  assert.notEqual(kept.from, null, 'from the replay the job kept');
  assert.ok(kept.audited !== null);
  // A writer changes a credential, and nothing is sealed after: no new pair to keep a replay at.
  const { credentials } = tablesOf(db.owner);
  const [{ expiresAt }] = await db.owner.select({ expiresAt: credentials.expiresAt }).from(credentials).where(eq(credentials.id, w.credential));
  await db.owner.update(credentials).set({ expiresAt: new Date(Date.now() + 7 * 86_400_000) }).where(eq(credentials.id, w.credential));
  // A page's check reads no row: it says the last audit's verdict, and when that was.
  assert.equal((await w.verify()).audited, kept.audited);
  // The job's audit reads them all, and keeps what it found in place of the replay it kept at the same pair.
  await w.vault.checkpoint();
  const named = `the credential ${w.credential}: its rows are not the object the log makes`;
  const after = await w.verify();
  assert.deepEqual(after.problems, [named]);
  assert.ok(after.audited! > kept.audited!);
  assert.deepEqual((await w.verify()).problems, [named], 'every check after');
  // Put back as it was, the job's next audit clears it, on the same quiet log.
  await db.owner.update(credentials).set({ expiresAt }).where(eq(credentials.id, w.credential));
  await w.vault.checkpoint();
  clean(await w.verify());
});

test('review r2: a roles row that reads as no object is named, not thrown on', async () => {
  const w = await instance();
  await run(db.owner, sql`UPDATE log_config SET value = '"not an object"' WHERE name = 'roles'`);
  assert.deepEqual((await w.verify('start')).problems, ['the roles instance: its rows do not read as an object']);
});

test('review r1: a database rolled back whole to an earlier pair, its kept replays with it, is named against the signer\'s memory', async () => {
  const w = await instance();
  await w.vault.checkpoint();
  const [earlier] = await rows<{ upto: string | number }>(db.owner, sql`SELECT max(upto) AS upto FROM log_checkpoints`);
  assert.ok((await w.grant(BO, 'viewer')).ok);
  const signed = w.cp.pair.pair.upto;
  // Every row the grant and its seal left, gone: its entries, the pairs above, Bo.
  await run(db.owner, sql`DELETE FROM log_checkpoints WHERE upto > ${BigInt(earlier!.upto)}`);
  await run(db.owner, sql`DELETE FROM log_changes WHERE number > ${BigInt(earlier!.upto)}`);
  await run(db.owner, sql`DELETE FROM vault_grants WHERE principal = ${BO}`);
  await run(db.owner, sql`DELETE FROM vault_members WHERE principal = ${BO}`);
  const checked = await w.verify();
  assert.ok(!checked.ok);
  assert.ok(checked.problems.includes(`the database ends up to ${earlier!.upto}; a pair held outside seals up to ${signed}: entries or checkpoints were deleted`), checked.problems.join('\n'));
});

test('review r1: an object whose rows are gone is named from the replay; a pair past the log\'s numbers is refused', async () => {
  const w = await instance();
  const { credentials } = tablesOf(db.owner);
  await db.owner.delete(credentials).where(eq(credentials.id, w.credential));
  assert.deepEqual((await w.verify()).problems, [`the credential ${w.credential}: the log holds it, its rows do not`]);
  await assert.rejects(w.vault.verifyTrees!({ from: '9223372036854775808' }), /goes on from `start` or a pair's number/);
});
