import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';

import { deriveLogKey, type StoredEntry } from '@coffre/core/audit';
import { verifyCheckpoint, type Vault } from '@coffre/core/vault';
import { createDatabase } from '@coffre/db';
import { appendEntries } from '@coffre/db/log';
import { asc, eq, gte } from 'drizzle-orm';

import { memoryAnchor, sealAnchor, type AnchorStore, type AuditAnchor } from '../src/anchor.ts';
import { appendAudit, appLogKey, CHAIN_WALK } from '../src/db/audit.ts';
import { latestCheckpoint } from '../src/db/queries.ts';
import { acceptLoss, auditReadiness, HEARTBEAT_STALE_AFTER_SECONDS, walkAuditBacklog, writeAuditHeartbeat, type HeartbeatLogger } from './watch-fixture.ts';
import { openTestDatabase, resetDatabase, testAnchor, testVault } from './api-fixture.ts';
import { auditChainHead, auditLog } from './db/tables.ts';
import { withLogUnlocked } from './db/engine.ts';

const db = await openTestDatabase();
// A log nobody has signed in to: the vault's entries are its checkpoints, and the one that makes the Owner its deployment names.
const vault = testVault([]);
// A vault whose scrub rehashes one entry a checkpoint: an edit in place behind its newest checkpoint stays unfound by
// it for these tests, as within its two laps it does on a long log, and only the app's walk can find it.
const slow = testVault([], {}, undefined, { scrub: 1 });
const chainKey = Buffer.alloc(32, 1);
let anchor: AnchorStore;
after(() => db.close());
beforeEach(async () => {
  await resetDatabase(db.owner);
  anchor = testAnchor();
});

const quiet: HeartbeatLogger = { warn: (_: unknown, message: string) => assert.fail(`a clean beat warned: ${message}`) };
const warned = () => {
  const said: string[] = [];
  return { said, log: { warn: (_: unknown, message: string) => void said.push(message) } };
};
const beat = (v: Vault = vault, log: HeartbeatLogger = quiet) => writeAuditHeartbeat(db.runtime, chainKey, v, anchor, log);
const ready = (v: Vault = vault) => auditReadiness(db.runtime, v, chainKey, anchor);
const anchored = async () => (await anchor.read())!;

function entries() {
  return db.owner.select().from(auditLog).orderBy(asc(auditLog.seq)) as Promise<StoredEntry[]>;
}

/** An entry of the app's, as any request writes one. */
function append(action = 'secret.read') {
  return db.runtime.transaction((tx) => appendAudit(tx, chainKey, [{ actorType: 'system', actorId: 'test', action, decision: 'allow' }]));
}

/** More than a walk of the app's entries, appended at once, as a busy log or a stopped scheduler leaves them. */
async function backlog(count = CHAIN_WALK + 500) {
  for (let left = count; left > 0; left -= 1000) {
    const batch = Array.from({ length: Math.min(1000, left) }, () => ({ actor: 'system:load', action: 'secret.read', decision: 'allow' as const, metadata: '{}' }));
    await db.owner.transaction((tx) => appendEntries(tx, appLogKey(chainKey), batch));
  }
}

/** Sets columns of entry `seq` as whoever writes the database would, its hash and MAC left as they were. */
function overwrite(seq: bigint, columns: { action?: string; metadata?: string; author?: string }) {
  return withLogUnlocked(db.owner, (owner) => owner.update(auditLog).set(columns).where(eq(auditLog.seq, seq)));
}

/** The log cut from entry `from` on, the head row made to match: what deleting the newest entries looks like. */
async function truncate(from: bigint) {
  const rows = await entries();
  const before = rows.find((row) => row.seq === from - 1n)!;
  await withLogUnlocked(db.owner, async (owner) => {
    // A checkpoint names the entry it signs as related: SQLite holds each delete to that key, in turn.
    await owner.update(auditLog).set({ relatedSeq: null }).where(gte(auditLog.seq, from));
    await owner.delete(auditLog).where(gte(auditLog.seq, from));
    await owner.update(auditChainHead).set({ nextSeq: from, headHash: before.hash });
  });
  return rows.filter((row) => row.seq >= from);
}

test('a beat is an app entry the vault checkpoints, and the anchor keeps that checkpoint, verified', async () => {
  assert.equal(await beat(), true);
  const logged = await entries();
  // The first beat finds the store empty, walks the log whole, and says so.
  assert.deepEqual(logged.map((row) => [row.author, row.action]), [['app', 'audit.heartbeat'], ['vault', 'audit.checkpoint'], ['app', 'audit.reanchor']]);
  const { checkpoint, verified, finding } = await anchored();
  const { seq, hash, signedAt, keyId, signature } = (await latestCheckpoint(db.owner))!;
  assert.deepEqual(checkpoint, { seq, hash, signedAt, keyId, signature });
  assert.deepEqual(verified, { seq: 0, hash: logged[0]!.hash.toString('hex') });
  assert.equal(finding, null);
  const { publicKey } = (await vault.about()).checkpointKeys[checkpoint!.keyId]!;
  assert.equal(await verifyCheckpoint(checkpoint!, publicKey), true);
  const readiness = await ready();
  assert.deepEqual({ ...readiness, heartbeatAgeSeconds: null }, { ok: true, heartbeatAgeSeconds: null, checkpointed: true, broken: false, anchored: true });
  assert.ok(readiness.heartbeatAgeSeconds! < 60);
});

test('each beat moves the anchor on to the newest checkpoint', async () => {
  await beat();
  await append();
  await beat();
  const { checkpoint, verified } = await anchored();
  assert.equal(checkpoint!.seq, (await latestCheckpoint(db.owner))!.seq);
  assert.deepEqual(verified, { seq: checkpoint!.seq, hash: checkpoint!.hash });
  assert.equal((await ready()).ok, true);
});

test('a cut tail is red at once, and the beats find it until the entries are back (tail truncation)', async () => {
  await beat();
  await append();
  await beat();
  const { checkpoint } = await anchored();
  // Everything from the anchored entry on deleted, and the head row put back to match: a log that verifies, shorter.
  const cut = await truncate(BigInt(checkpoint!.seq));
  const readiness = await ready();
  assert.deepEqual([readiness.ok, readiness.checkpointed, readiness.broken], [false, false, true]);
  // The vault finds it first here, its own newest checkpoint cut; a vault that signs the shorter log, the app's walk.
  assert.equal(await beat(vault, warned().log), false);
  const found = await anchored();
  assert.deepEqual([found.finding?.by, found.checkpoint], ['vault', checkpoint], 'the anchor moved back');
  // Requests go on: the log grows past the cut, with another entry where the anchored one was.
  assert.equal(await beat(vault, warned().log), false);
  assert.equal((await ready()).ok, false);

  // Restored from a backup: the entries as they were, the ones written since lost with the cut.
  await withLogUnlocked(db.owner, async (owner) => {
    await owner.update(auditLog).set({ relatedSeq: null }).where(gte(auditLog.seq, BigInt(checkpoint!.seq)));
    await owner.delete(auditLog).where(gte(auditLog.seq, BigInt(checkpoint!.seq)));
    for (const row of cut) await owner.insert(auditLog).values(row);
    await owner.update(auditChainHead).set({ nextSeq: cut.at(-1)!.seq + 1n, headHash: cut.at(-1)!.hash });
  });
  // The app and the vault started again after the restore, as an operator does: each remembers the head it wrote last.
  assert.equal(await writeAuditHeartbeat(db.runtime, Buffer.from(chainKey), testVault([], {}, { kek: vault.kek }), anchor, quiet), true);
  assert.equal((await anchored()).finding, null);
  assert.equal((await ready()).ok, true);
});

test('an entry edited deep behind the anchor is the vault\'s scrub\'s to find, and stands until it is put back (deep edit)', async () => {
  await beat();
  for (let i = 0; i < 5; i++) await append();
  await beat();
  await beat();
  // Entry 2, far behind every checkpoint, its stored hash left as it was: no walk from the anchor reads it again.
  const [, , deep] = await entries();
  await overwrite(deep!.seq, { metadata: '{"edited":true}' });
  const { said, log } = warned();
  assert.equal(await beat(vault, log), false);
  assert.ok(said.includes('audit checkpoint failed'), said.join('; '));
  assert.deepEqual([(await anchored()).finding?.by, (await ready()).ok], ['vault', false]);
  // Put back, the refusal stands until the scrub has gone over it again and the vault signs: within a lap.
  await overwrite(deep!.seq, { metadata: deep!.metadata });
  let signed = false;
  for (let i = 0; i < 3 && !signed; i++) signed = await beat(vault, warned().log);
  assert.ok(signed, 'the vault never signed the repaired log');
  assert.equal((await ready()).ok, true);
});

/**
 * An app entry edited in place after the vault signed it, which only the
 * app's walk then finds: the slow vault's scrub does not reach it.
 */
async function appFinding() {
  await beat(slow);
  await append();
  const x = (await entries()).at(-1)!;
  assert.ok((await slow.checkpoint()).ok);
  await overwrite(x.seq, { metadata: '{"edited":true}' });
  const { said, log } = warned();
  assert.equal(await beat(slow, log), false);
  assert.deepEqual(said, ['the audit log does not verify from the anchor']);
  const { finding } = await anchored();
  assert.deepEqual([finding?.seq, finding?.by, finding?.reason], [Number(x.seq), 'app', 'hash does not match the entry']);
  return x;
}

test('an app entry the walk finds edited stands, checked alone each beat, until it is put back', async () => {
  const x = await appFinding();
  const before = await anchored();
  // A day of requests and beats: each beat checks that entry alone, and the anchor stays where it was.
  for (let i = 0; i < 3; i++) {
    for (let j = 0; j < 50; j++) await append();
    assert.equal(await beat(slow, warned().log), false);
    assert.equal((await ready(slow)).ok, false);
  }
  const standing = await anchored();
  assert.deepEqual([standing.verified, standing.finding], [before.verified, before.finding]);
  await overwrite(x.seq, { metadata: x.metadata });
  // Put back, it clears, and the walk goes on from where the anchor was, over it and on.
  assert.equal(await beat(slow), true);
  assert.equal((await anchored()).finding, null);
  assert.equal((await ready(slow)).ok, true);
});

test('a finding cleared walks on from the anchor, and finds what else was changed behind it', async () => {
  const x = await appFinding();
  await append();
  const y = (await entries()).at(-1)!;
  assert.ok((await slow.checkpoint()).ok);
  // Another entry changed while the first stood, past it, which the check of the first alone does not read.
  await overwrite(y.seq, { metadata: '{"edited":true}' });
  await overwrite(x.seq, { metadata: x.metadata });
  assert.equal(await beat(slow, warned().log), false);
  assert.equal((await anchored()).finding?.seq, Number(y.seq));
  assert.equal((await ready(slow)).ok, false);
});

test('heartbeat rows hidden, forged or deleted change nothing: readiness reads none of them', async () => {
  await appFinding();
  const beats = (await entries()).filter((row) => row.action === 'audit.heartbeat');
  // Every beat row made to say nothing, and a newer one in the app's name under another key claiming a clean walk.
  for (const row of beats) await overwrite(row.seq, { action: 'secret.read', metadata: '{}' });
  await db.owner.transaction((tx) => appendEntries(tx, deriveLogKey('app', Buffer.alloc(32, 9)), [
    { actor: 'system:coffre-scheduler', action: 'audit.heartbeat', decision: 'allow', metadata: JSON.stringify({ verified: { seq: 99 } }) },
  ]));
  assert.ok((await slow.checkpoint()).ok);
  const readiness = await ready(slow);
  assert.deepEqual([readiness.ok, readiness.broken], [false, true]);
  assert.equal(await beat(slow, warned().log), false);
  assert.equal((await ready(slow)).ok, false);
});

test('a row of the app\'s relabelled as the vault\'s and chained again behind the anchor is red at once (T102)', async () => {
  await beat();
  await append();
  await beat();
  // The relabel changes the entry's hash; chained again from there, the anchored entry's hash changes too.
  const rows = await entries();
  const target = rows.find((row) => row.action === 'secret.read')!;
  const { checkpoint } = await anchored();
  await withLogUnlocked(db.owner, async (owner) => {
    await owner.update(auditLog).set({ author: 'vault' }).where(eq(auditLog.seq, target.seq));
    await owner.update(auditLog).set({ hash: Buffer.alloc(32, 3) }).where(eq(auditLog.seq, BigInt(checkpoint!.seq)));
  });
  const readiness = await ready();
  assert.deepEqual([readiness.ok, readiness.broken], [false, true]);
});

test('an empty store is re-anchored by a walk of the whole log, green meanwhile, then logged and alerted once', async () => {
  // More than a walk of the log, which the vault and the beats have caught up with.
  await backlog(CHAIN_WALK + 500);
  for (let i = 0; i < 3; i++) await beat();
  assert.equal((await ready()).ok, true);
  // The store emptied: its Durable Object deleted, or its file gone with a container.
  anchor = memoryAnchor();
  const alerts: string[] = [];
  assert.equal(await writeAuditHeartbeat(db.runtime, chainKey, vault, anchor, quiet, (text) => alerts.push(text)), true, 'a backlog is no failure');
  // An empty store is no evidence of tampering: green while the walk goes on, between beats.
  const walking = await anchored();
  assert.ok(walking.reanchor !== null && walking.verified!.seq < walking.checkpoint!.seq);
  assert.equal((await ready()).ok, true);
  assert.equal(alerts.length, 0);
  while (await walkAuditBacklog(db.runtime, chainKey, vault, anchor, (text) => alerts.push(text)));
  const done = await anchored();
  assert.deepEqual([done.reanchor, done.verified?.seq], [null, done.checkpoint!.seq]);
  // The first beat's re-anchoring, then this one's.
  const logged = (await entries()).filter((row) => row.action === 'audit.reanchor');
  assert.deepEqual(logged.map((row) => JSON.parse(row.metadata).at).at(-1), done.checkpoint!.seq);
  assert.equal(logged.length, 2);
  assert.equal(alerts.length, 1);
  assert.match(alerts[0]!, /store was empty.*re-anchored at entry/);
  assert.equal((await ready()).ok, true);
});

test('a tail cut with no backup stands red until an Owner accepts the loss; tampering after is found as before', async () => {
  await beat();
  for (let i = 0; i < 3; i++) await append();
  await beat();
  const { checkpoint } = await anchored();
  // Entries from 2 on cut, and the log grown again by processes started since, which remember no head of it.
  await truncate(2n);
  const restarted = Buffer.from(chainKey);
  // Its scrub one entry a call, as `slow`'s: the edit below is the app's walk's to find.
  const again = testVault([], {}, { kek: vault.kek }, { scrub: 1 });
  const after = (log = quiet) => writeAuditHeartbeat(db.runtime, restarted, again, anchor, log);
  assert.equal(await after(warned().log), false);
  const { finding } = await anchored();
  assert.deepEqual([finding?.by, finding?.seq], ['app', checkpoint!.seq]);
  // It stands, beat after beat: nothing puts the cut entries back.
  assert.equal(await after(warned().log), false);
  assert.equal((await auditReadiness(db.runtime, again, restarted, anchor)).ok, false);

  const owner = { actorType: 'user' as const, actorId: 'root@acme.example' };
  // A range that does not hold the entry the finding names is refused.
  await assert.rejects(acceptLoss(db.runtime, restarted, again, anchor, owner, { from: 2, to: checkpoint!.seq - 1 }), /do not hold entry/);
  const alerts: string[] = [];
  await acceptLoss(db.runtime, restarted, again, anchor, owner, { from: 2, to: checkpoint!.seq }, (text) => alerts.push(text));
  assert.equal(alerts.length, 1);
  // The finding, and its acceptance, stay in the log.
  const logged = (await entries()).filter((row) => ['audit.finding', 'audit.loss_accepted'].includes(row.action));
  assert.deepEqual(logged.map((row) => [row.action, row.actor]), [['audit.finding', 'system:coffre-scheduler'], ['audit.loss_accepted', 'user:root@acme.example']]);
  assert.deepEqual(JSON.parse(logged[1]!.metadata).finding, finding);
  assert.equal(await after(), true);
  assert.equal((await auditReadiness(db.runtime, again, restarted, anchor)).ok, true);

  // Tampering after it is found as before.
  await db.runtime.transaction((tx) => appendAudit(tx, restarted, [{ actorType: 'system', actorId: 'test', action: 'secret.read', decision: 'allow' }]));
  const x = (await entries()).at(-1)!;
  assert.ok((await again.checkpoint()).ok);
  await overwrite(x.seq, { metadata: '{"edited":true}' });
  assert.equal(await after(warned().log), false);
  assert.equal((await anchored()).finding?.seq, Number(x.seq));
});

test('an acceptance a beat overtakes goes over the same finding sealed again, and says so in the log when the finding changed', async () => {
  await beat();
  for (let i = 0; i < 3; i++) await append();
  await beat();
  const { checkpoint } = await anchored();
  await truncate(2n);
  const restarted = Buffer.from(chainKey);
  const again = testVault([], {}, { kek: vault.kek }, { scrub: 1 });
  const after = () => writeAuditHeartbeat(db.runtime, restarted, again, anchor, warned().log);
  assert.equal(await after(), false);
  const owner = { actorType: 'user' as const, actorId: 'root@acme.example' };
  const range = { from: 2, to: checkpoint!.seq };
  // A store whose next write first lets `meanwhile` write, as a beat that runs between the acceptance's read and its write.
  const racing = (meanwhile: () => Promise<unknown>): AnchorStore => {
    let raced = false;
    return {
      read: () => anchor.read(),
      write: async (prev, next) => {
        if (!raced) {
          raced = true;
          await meanwhile();
        }
        return anchor.write(prev, next);
      },
    };
  };
  const actions = async () => (await entries()).filter((row) => row.action.startsWith('audit.loss_')).map((row) => row.action);

  // The finding changed meanwhile: nothing moves, and the log says the acceptance was not applied.
  const standing = await anchored();
  const changed = (): Promise<unknown> =>
    anchor.write(standing, sealAnchor(restarted, { ...standing, finding: { ...standing.finding!, reason: 'something else' }, at: Date.now() }));
  await assert.rejects(acceptLoss(db.runtime, restarted, again, racing(changed), owner, range), /the acceptance was not applied/);
  const moved = await anchored();
  assert.deepEqual([moved.finding!.reason, moved.epoch], ['something else', standing.epoch]);
  assert.deepEqual(await actions(), ['audit.loss_accepted', 'audit.loss_unapplied']);
  const [unapplied] = (await entries()).filter((row) => row.action === 'audit.loss_unapplied');
  assert.equal(unapplied!.actor, 'user:root@acme.example');
  assert.match(JSON.parse(unapplied!.metadata).reason, /changed while the loss was accepted/);

  // A beat that seals the same finding again, with its own time: the acceptance goes over it.
  await acceptLoss(db.runtime, restarted, again, racing(after), owner, range);
  const accepted = await anchored();
  assert.deepEqual([accepted.finding, accepted.epoch], [null, standing.epoch + 1]);
  assert.deepEqual(await actions(), ['audit.loss_accepted', 'audit.loss_unapplied', 'audit.loss_accepted']);
  assert.equal(await after(), true);
});

test('the first beat on a log walks it whole, as far as the vault signed, and logs its re-anchoring', async () => {
  await backlog();
  // The vault signs as far as one walk of its own goes, and the app verifies that far: the beat is past it.
  assert.equal(await beat(), true, 'a backlog is no failure');
  const first = await anchored();
  assert.equal(first.verified!.seq, CHAIN_WALK - 1);
  // Re-anchored through what the vault signed: the rest is a backlog like any other.
  assert.deepEqual([first.checkpoint!.seq, first.finding, first.reanchor], [CHAIN_WALK - 1, null, null]);
  assert.deepEqual((await entries()).filter((row) => row.action === 'audit.reanchor').map((row) => JSON.parse(row.metadata).at), [CHAIN_WALK - 1]);
  // Checkpointed short of the beat: red on that until the vault catches up.
  assert.equal((await ready()).checkpointed, false);
  assert.equal(await beat(), true);
  assert.equal((await ready()).ok, true);
});

test('the first beat finds a log that does not verify, and anchors nothing it did not verify', async () => {
  await backlog(20);
  await overwrite(5n, { metadata: '{"edited":true}' });
  assert.equal(await beat(vault, warned().log), false);
  // The vault's own walk from the first entry finds it first.
  assert.deepEqual([(await anchored()).finding?.by, (await anchored()).verified], ['vault', null]);
  assert.equal((await ready()).ok, false);
});

test('an anchor is never moved back: the store refuses an older one (anchor rollback)', async () => {
  await beat();
  const older = await anchored();
  await beat();
  const newer = await anchored();
  // Whoever can call the store, putting back the record it held a beat ago.
  assert.equal(await anchor.write(newer, older), false);
  assert.equal(await anchor.write(older, newer), false, 'the compare-and-set took a record no longer stored');
  // Sealed by the app's key, as a bug could: still older than what is stored.
  assert.equal(await anchor.write(newer, sealAnchor(chainKey, { ...older, at: Date.now() })), false);
  assert.deepEqual(await anchored(), newer);
});

test('a log cut back below the anchor, and grown again, never gets its shorter prefix anchored', async () => {
  await beat();
  for (let i = 0; i < 3; i++) await append();
  await beat();
  const { checkpoint } = await anchored();
  // Cut to just after the first beat's checkpoint, and grown again by requests in a new isolate, which remembers no
  // head of the log it wrote (db log.ts, `LogRewound`): the vault signs that log afresh.
  await truncate(2n);
  const fresh = Buffer.from(chainKey);
  for (let i = 0; i < 3; i++) await db.runtime.transaction((tx) => appendAudit(tx, fresh, [{ actorType: 'system', actorId: 'test', action: 'secret.read', decision: 'allow' }]));
  // And a vault started again, with the same keys and no memory of the head it signed either.
  assert.equal(await writeAuditHeartbeat(db.runtime, fresh, testVault([], {}, { kek: vault.kek }), anchor, warned().log), false);
  const after = await anchored();
  assert.deepEqual([after.checkpoint, after.finding?.seq], [checkpoint, checkpoint!.seq]);
  assert.equal((await ready()).ok, false);
});

test('a vault that refuses or cannot be asked turns readiness red now, until it signs again', async (t) => {
  await beat();
  const down = t.mock.method(vault, 'checkpoint', async () => {
    throw new Error('the vault is down');
  });
  const { said, log } = warned();
  assert.equal(await beat(vault, log), false);
  assert.ok(said.includes('audit checkpoint failed'));
  const { finding } = await anchored();
  assert.deepEqual([finding?.by, finding?.seq, finding?.reason], ['vault', null, 'the vault could not checkpoint the log: the vault is down']);
  assert.equal((await ready()).ok, false);
  down.mock.restore();
  assert.equal(await beat(), true);
  assert.equal((await ready()).ok, true);
});

test('a log that takes no writes is red at once: every checkpoint deleted, the newest among them', async () => {
  await beat();
  await append();
  await beat();
  await withLogUnlocked(db.owner, async (owner) => {
    await owner.update(auditLog).set({ relatedSeq: null }).where(eq(auditLog.action, 'audit.checkpoint'));
    await owner.delete(auditLog).where(eq(auditLog.action, 'audit.checkpoint'));
  });
  // The head row names an entry the log no longer ends with: the beat's own append refuses.
  const { said, log } = warned();
  assert.equal(await beat(vault, log), false);
  // The vault refuses the log too; nor can the finding be logged: the anchor alone keeps it.
  assert.deepEqual(said, ['audit heartbeat failed to write', 'audit checkpoint failed', 'what the audit anchor found could not be logged']);
  const { finding } = await anchored();
  assert.deepEqual([finding?.by, finding?.seq, finding?.reason.startsWith('the log takes no writes')], ['app', null, true]);
  assert.deepEqual([(await ready()).ok, (await ready()).broken], [false, true]);
});

test('a store that cannot be reached fails the beat and readiness closed', async () => {
  await beat();
  anchor = { read: async () => Promise.reject(new Error('the Durable Object is unavailable')), write: async () => Promise.reject(new Error('unavailable')) };
  const { said, log } = warned();
  assert.equal(await beat(vault, log), false);
  assert.deepEqual(said, ['the audit anchor could not be read: the Durable Object is unavailable']);
  // Told apart from no anchor at all, and the cause in the process's log, not the answer.
  assert.deepEqual(await ready(), { ok: false, heartbeatAgeSeconds: null, checkpointed: false, broken: false, anchored: false, error: 'the audit anchor, the log or the vault could not be read' });
  // The vault went on signing: its checkpoint covers the beat all the same.
  assert.equal((await entries()).at(-1)!.action, 'audit.checkpoint');
});

test('readiness believes only an anchor the app wrote, and a beat leaves one it did not alone', async () => {
  await beat();
  const own = await anchored();
  // Someone who can write the store, but holds no app key, writes a record of their own.
  const forged: AuditAnchor = { ...own, finding: null, at: Date.now(), mac: Buffer.alloc(32, 7).toString('hex') };
  assert.equal(await anchor.write(own, forged), true);
  assert.deepEqual(await ready(), { ok: false, heartbeatAgeSeconds: null, checkpointed: false, broken: false, anchored: false });
  const { said, log } = warned();
  assert.equal(await beat(vault, log), false);
  assert.ok(said[0]!.startsWith('the audit anchor is not one the app wrote'));
  assert.deepEqual(await anchor.read(), forged);
});

test('an anchor sealed under the app key before a change of APP_KEY is not the app\'s: red, named, and left alone', async () => {
  await beat();
  const sealed = await anchored();
  assert.equal(sealed.keyId, appLogKey(chainKey).keyId);
  // The deployment's auditChainKey changed, and nothing re-seals the anchor yet.
  const changed = Buffer.alloc(32, 9);
  assert.equal((await auditReadiness(db.runtime, vault, changed, anchor)).anchored, false);
  const { said, log } = warned();
  assert.equal(await writeAuditHeartbeat(db.runtime, changed, vault, anchor, log), false);
  assert.ok(said.includes(`the audit anchor is sealed under ${sealed.keyId}, not the app's key ${appLogKey(changed).keyId}: auditChainKey changed, and nothing re-seals it yet. Empty its store, and the next beat re-anchors`), said.join('\n'));
  assert.deepEqual(await anchor.read(), sealed);
});

test('a beat that a walk between beats wrote the anchor before goes on from that walk, and writes its own', async () => {
  // More than a walk of the log, which the vault and the beats have caught up with; then the store emptied, and a
  // beat that leaves the re-anchoring's walk to go on.
  await backlog(CHAIN_WALK + 500);
  for (let i = 0; i < 3; i++) await beat();
  anchor = memoryAnchor();
  assert.equal(await beat(), true, 'a backlog is no failure');
  const before = await anchored();
  assert.ok(before.verified!.seq < before.checkpoint!.seq);
  // The next beat pauses as it opens its walk; a walk between beats, the Durable Object's alarm, writes meanwhile.
  let reached!: () => void;
  const paused = new Promise<void>((resolve) => (reached = resolve));
  let go!: () => void;
  const released = new Promise<void>((resolve) => (go = resolve));
  let n = 0;
  const pausing = new Proxy(db.runtime, {
    get(target, key, receiver) {
      const value = Reflect.get(target, key, receiver) as unknown;
      if (key !== 'transaction' || typeof value !== 'function') return value;
      return async (...args: unknown[]) => {
        if (++n === 2) {
          reached();
          await released;
        }
        return (value as (...a: unknown[]) => Promise<unknown>).apply(target, args);
      };
    },
  });
  const next = writeAuditHeartbeat(pausing, chainKey, vault, anchor, quiet);
  await paused;
  await walkAuditBacklog(db.runtime, chainKey, vault, anchor);
  const walked = await anchored();
  assert.ok(walked.verified!.seq > before.verified!.seq);
  assert.deepEqual([walked.beat, walked.at, walked.checkpoint], [before.beat, before.at, before.checkpoint]);
  go();
  assert.equal(await next, true);
  // The beat's own record: its row, its checkpoint, its time, and the walk's progress kept.
  const after = await anchored();
  assert.ok(after.beat! > before.beat!);
  assert.ok(after.checkpoint!.seq > before.checkpoint!.seq);
  assert.ok(after.verified!.seq > walked.verified!.seq);
  assert.equal(after.finding, null);
  assert.equal((await ready()).ok, true);
});

test('readiness counts a checkpoint under a key the vault replaced only over a prefix before the rotation', async () => {
  await beat();
  const { checkpoint } = await anchored();
  const { publicKey } = (await vault.about()).checkpointKeys[checkpoint!.keyId]!;
  // The vault as after a rotation at entry `until`: the key that signed this checkpoint is one it replaced.
  const rotatedAt = (until: number) =>
    ({ about: async () => ({ checkpointKeys: { [checkpoint!.keyId]: { publicKey, until } }, rootAdmins: [] }) }) as unknown as Vault;
  assert.equal((await ready(rotatedAt(checkpoint!.seq + 1))).ok, true);
  assert.equal((await ready(rotatedAt(checkpoint!.seq))).checkpointed, false);
});

test('readiness accepts a recent anchor and rejects a stale one', async () => {
  await beat();
  const aged = async (seconds: number) => {
    const prev = await anchored();
    assert.ok(await anchor.write(prev, sealAnchor(chainKey, { ...prev, at: prev.at - seconds * 1000 })));
  };
  // A Cron run that fires a few seconds late is not a logging failure.
  await aged(307);
  assert.equal((await ready()).ok, true);
  await aged(HEARTBEAT_STALE_AFTER_SECONDS);
  const stale = await ready();
  assert.deepEqual([stale.ok, stale.checkpointed], [false, true]);
  assert.ok(stale.heartbeatAgeSeconds! > HEARTBEAT_STALE_AFTER_SECONDS);
});

test('readiness rejects a database without the expected Drizzle schema prefix', async () => {
  // The migrations count, in Drizzle's array row mode: none applied.
  const query = async () => ({ rows: [[0]], fields: [] });
  const empty = createDatabase({ query, connect: async () => ({ query, release: () => {} }) } as never);
  assert.equal((await auditReadiness(empty, vault, chainKey, anchor)).ok, false);
});

test('two beats at once: the one that anchors second loses the compare-and-set, and finds nothing', async () => {
  await beat();
  await append();
  // Beat A pauses as it opens its walk; beat B runs whole; then A goes on.
  let reached!: () => void;
  const paused = new Promise<void>((resolve) => (reached = resolve));
  let go!: () => void;
  const released = new Promise<void>((resolve) => (go = resolve));
  let n = 0;
  const pausing = new Proxy(db.runtime, {
    get(target, key, receiver) {
      const value = Reflect.get(target, key, receiver) as unknown;
      if (key !== 'transaction' || typeof value !== 'function') return value;
      return async (...args: unknown[]) => {
        // The beat's append, then its walk, which reads in a snapshot.
        if (++n === 2) {
          reached();
          await released;
        }
        return (value as (...a: unknown[]) => Promise<unknown>).apply(target, args);
      };
    },
  });
  const { said, log } = warned();
  const a = writeAuditHeartbeat(pausing, chainKey, vault, anchor, log);
  await paused;
  assert.equal(await beat(), true);
  const b = await anchored();
  go();
  assert.equal(await a, false);
  assert.deepEqual(said, ['another beat wrote the audit anchor first: the next goes on from it']);
  assert.deepEqual(await anchored(), b);
  assert.equal((await ready()).ok, true);
});
