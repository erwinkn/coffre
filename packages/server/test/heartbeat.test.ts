import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';

import { deriveLogKey, entryHash, sealEntry, type StoredEntry } from '@coffre/core/audit';
import { verifyCheckpoint, type Vault } from '@coffre/core/vault';
import { createDatabase } from '@coffre/db';
import { appendEntries } from '@coffre/db/log';
import { asc, desc, eq } from 'drizzle-orm';

import { appendAudit, appLogKey, resumePoint } from '../src/db/audit.ts';
import { latestCheckpoint } from '../src/db/queries.ts';
import { auditReadiness, HEARTBEAT_STALE_AFTER_SECONDS, writeAuditHeartbeat } from '../src/heartbeat.ts';
import { openTestDatabase, resetDatabase, testVault } from './api-fixture.ts';
import { auditChainHead, auditLog } from './db/tables.ts';
import { withLogUnlocked } from './db/engine.ts';

const db = await openTestDatabase();
// A log nobody has signed in to: the vault's entries are its checkpoints, and the one that makes the Owner its deployment names.
const vault = testVault([]);
const chainKey = Buffer.alloc(32, 1);
after(() => db.close());
beforeEach(() => resetDatabase(db.owner));

const quiet = { warn: () => assert.fail('successful heartbeat must not warn') };

function entries() {
  return db.owner.select().from(auditLog).orderBy(asc(auditLog.seq));
}

/** Moves the newest beat, the log's last entry, `seconds` into the past. Readiness reads its date. */
async function beatAgo(seconds: number) {
  const [beat] = (await db.owner.select().from(auditLog).orderBy(desc(auditLog.seq)).limit(1)) as StoredEntry[];
  assert.equal(beat!.action, 'audit.heartbeat');
  // Sealed again under the app's key, as if the app had written it then: readiness believes only the app's beats.
  const aged = { ...beat!, occurredAt: Date.now() - seconds * 1000 };
  const { mac, hash } = sealEntry(appLogKey(chainKey), aged.prevHash, aged);
  await withLogUnlocked(db.owner, async (owner) => {
    await owner.update(auditLog).set({ occurredAt: aged.occurredAt, mac, hash }).where(eq(auditLog.seq, beat!.seq));
    await owner.update(auditChainHead).set({ headHash: hash });
  });
}

test('a beat is an app entry, and the vault checkpoints it in an entry of its own', async () => {
  assert.equal(await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet), true);

  const logged = await entries();
  assert.deepEqual(logged.map((row) => [row.author, row.actor, row.action]), [
    ['app', 'system:coffre-scheduler', 'audit.heartbeat'],
    ['vault', 'system:coffre-scheduler', 'audit.checkpoint'],
  ]);
  // The checkpoint signs everything before it: here, the beat.
  const [checkpoint, { checkpointKeys }] = await Promise.all([latestCheckpoint(db.owner), vault.about()]);
  const { publicKey } = checkpointKeys[checkpoint!.keyId]!;
  assert.equal(checkpoint?.seq, 0);
  assert.equal(checkpoint?.hash, logged[0].hash.toString('hex'));
  assert.deepEqual(JSON.parse(logged[1].metadata), checkpoint);
  assert.equal(await verifyCheckpoint(checkpoint!, publicKey), true);

  const ready = await auditReadiness(db.runtime, vault, chainKey);
  assert.equal(ready.ok, true);
  assert.equal(ready.checkpointed, true);
  assert.ok(ready.heartbeatAgeSeconds! < 60);
});

test('each checkpoint extends the last, and nothing new signs nothing new', async () => {
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  // Beat, checkpoint, beat, the vault's word that it had no root admins to
  // convert (its first call over a log with an entry of its own), checkpoint:
  // the second covers the first, the second beat and that word.
  assert.equal((await latestCheckpoint(db.owner))?.seq, 3);

  const again = await vault.checkpoint();
  assert.ok(again.ok);
  assert.equal(again.checkpoint.seq, 3);
  assert.equal((await entries()).length, 5);
});

test('a rewritten entry is never signed over, and readiness goes red', async () => {
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  // Someone with the database rewrites the entry the last checkpoint signed.
  const signed = (await latestCheckpoint(db.owner))!.seq;
  await withLogUnlocked(db.owner, (owner) => owner.update(auditLog).set({ hash: Buffer.alloc(32, 9) }).where(eq(auditLog.seq, BigInt(signed))));

  let warned: unknown = null;
  const written = await writeAuditHeartbeat(db.runtime, chainKey, vault, {
    warn: (value: unknown) => {
      warned = value;
    },
  });
  assert.equal(written, false);
  assert.deepEqual(warned, { code: 'log_broken' });
  assert.equal((await latestCheckpoint(db.owner))?.seq, signed);
  // The refusal is in the log too.
  const refused = (await entries()).find((row) => row.decision === 'deny' && row.action === 'audit.checkpoint');
  assert.equal(refused?.code, 'log_broken');

  const ready = await auditReadiness(db.runtime, vault, chainKey);
  assert.equal(ready.ok, false);
  assert.equal(ready.checkpointed, false);
});

test('a beat the vault did not checkpoint leaves readiness red', async (t) => {
  t.mock.method(vault, 'checkpoint', async () => {
    throw new Error('the vault is down');
  });
  let warning = '';
  const written = await writeAuditHeartbeat(db.runtime, chainKey, vault, {
    warn: (_value: unknown, message: string) => {
      warning = message;
    },
  });
  assert.equal(written, false);
  assert.equal(warning, 'audit checkpoint failed');
  assert.deepEqual((await entries()).map((row) => row.action), ['audit.heartbeat']);
  const ready = await auditReadiness(db.runtime, vault, chainKey);
  assert.equal(ready.ok, false);
  assert.equal(ready.checkpointed, false);
});

test('readiness trusts only a checkpoint the vault signed', async () => {
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  assert.equal((await auditReadiness(db.runtime, vault, chainKey)).ok, true);
  // A checkpoint entry with another signature, as anyone who can write the database could make.
  const [, signed] = await entries();
  const forged = { ...JSON.parse(signed.metadata), signature: Buffer.alloc(64, 7).toString('base64') };
  await withLogUnlocked(db.owner, (owner) =>
    owner.update(auditLog).set({ metadata: JSON.stringify(forged) }).where(eq(auditLog.seq, signed.seq)),
  );
  const ready = await auditReadiness(db.runtime, vault, chainKey);
  assert.equal(ready.ok, false);
  assert.equal(ready.checkpointed, false);
});

test('readiness counts a checkpoint under a key the vault replaced only over a prefix before the rotation', async () => {
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  const checkpoint = (await latestCheckpoint(db.owner))!;
  const { publicKey } = (await vault.about()).checkpointKeys[checkpoint.keyId]!;
  // The vault as after a rotation at entry `until`: the key that signed this checkpoint is one it replaced.
  const rotatedAt = (until: number) =>
    ({ verifyLog: vault.verifyLog, about: async () => ({ checkpointKeys: { [checkpoint.keyId]: { publicKey, until } }, rootAdmins: [] }) }) as unknown as Vault;
  assert.equal((await auditReadiness(db.runtime, rotatedAt(checkpoint.seq + 1), chainKey)).ok, true);
  assert.equal((await auditReadiness(db.runtime, rotatedAt(checkpoint.seq), chainKey)).checkpointed, false);
});

test('an empty log has nothing to checkpoint, and logs nothing for it', async () => {
  const refused = await vault.checkpoint();
  assert.ok(!refused.ok);
  assert.equal(refused.refusal.code, 'invalid');
  assert.deepEqual(await entries(), []);
  assert.equal(await latestCheckpoint(db.owner), null);
  assert.deepEqual(await auditReadiness(db.runtime, vault, chainKey), { ok: false, heartbeatAgeSeconds: null, checkpointed: false, broken: false });
});

test('readiness accepts a recent beat and rejects a stale one', async (t) => {
  /** A beat written `seconds` ago, then checkpointed: the vault signs it as it stands. */
  const beat = async (seconds: number) => {
    const checkpoint = t.mock.method(vault, 'checkpoint', async () => ({ ok: true }));
    await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
    checkpoint.mock.restore();
    await beatAgo(seconds);
    assert.ok((await vault.checkpoint()).ok);
  };
  await beat(12);
  const recent = await auditReadiness(db.runtime, vault, chainKey);
  assert.equal(recent.ok, true);
  assert.ok(Math.abs(recent.heartbeatAgeSeconds! - 12) < 5);

  // A Cron run that fires a few seconds late is not a logging failure.
  await beat(307);
  assert.equal((await auditReadiness(db.runtime, vault, chainKey)).ok, true);

  await beat(HEARTBEAT_STALE_AFTER_SECONDS + 60);
  const stale = await auditReadiness(db.runtime, vault, chainKey);
  assert.equal(stale.ok, false);
  assert.equal(stale.checkpointed, true);
  assert.ok(stale.heartbeatAgeSeconds! > HEARTBEAT_STALE_AFTER_SECONDS);
});

test('a checkpoint before the newest beat does not cover it', async () => {
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  await db.runtime.transaction((tx) =>
    appendAudit(tx, chainKey, [{ actorType: 'system', actorId: 'coffre-scheduler', action: 'audit.heartbeat', decision: 'allow' }]),
  );
  const ready = await auditReadiness(db.runtime, vault, chainKey);
  assert.equal(ready.ok, false);
  assert.equal(ready.checkpointed, false);
});

test('readiness rejects a database without the expected Drizzle schema prefix', async () => {
  // The migrations count, in Drizzle's array row mode: none applied.
  const query = async () => ({ rows: [[0]], fields: [] });
  const empty = createDatabase({ query, connect: async () => ({ query, release: () => {} }) } as never);
  assert.deepEqual(await auditReadiness(empty, vault, chainKey), { ok: false, heartbeatAgeSeconds: null, checkpointed: false, broken: false });
});

test('readiness believes only a beat the app wrote', async () => {
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  assert.equal((await auditReadiness(db.runtime, vault, chainKey)).ok, true);
  // A newer beat in the app's name under another key, as whoever can append rows could write one to hide what the last found.
  await db.owner.transaction((tx) => appendEntries(tx, deriveLogKey('app', Buffer.alloc(32, 9)), [
    { actor: 'system:coffre-scheduler', action: 'audit.heartbeat', decision: 'allow', metadata: '{"source":"scheduled"}' },
  ]));
  assert.ok((await vault.checkpoint()).ok);
  const ready = await auditReadiness(db.runtime, vault, chainKey);
  assert.deepEqual([ready.ok, ready.checkpointed, ready.broken], [false, true, true]);
});

/**
 * `db.runtime`, with `around` run before and after each transaction a beat opens: its reads in snapshots, then its
 * append, the one it opens without (`write`).
 */
function stepping(around: (step: { n: number; write: boolean }, phase: 'before' | 'after') => Promise<void>) {
  let n = 0;
  return new Proxy(db.runtime, {
    get(target, key, receiver) {
      const value = Reflect.get(target, key, receiver) as unknown;
      if (key !== 'transaction' || typeof value !== 'function') return value;
      return async (...args: unknown[]) => {
        const step = { n: ++n, write: args.length < 2 };
        await around(step, 'before');
        const result = await (value as (...a: unknown[]) => Promise<unknown>).apply(target, args);
        await around(step, 'after');
        return result;
      };
    },
  });
}

async function beats() {
  return (await entries()).filter((row) => row.action === 'audit.heartbeat');
}

const said = (row: { metadata: string }) => JSON.parse(row.metadata) as { verified?: { seq: number }; broken?: { seq: number } };

/** Sets a column of entry `seq` as whoever writes the database would, its hash and MAC left as they were. */
function overwrite(seq: bigint, columns: { action?: string; metadata?: string }) {
  return withLogUnlocked(db.owner, (owner) => owner.update(auditLog).set(columns).where(eq(auditLog.seq, seq)));
}

// A vault whose scrub rehashes one entry a checkpoint: an edit in place behind its newest checkpoint stays unfound by it
// for these tests, as within its two laps it does on a long log, and only the heartbeat's walk can find it.
const slow = testVault([], {}, undefined, { scrub: 1 });

/**
 * Two heartbeats at once, as on two instances: beat A walks past entry X,
 * clean, and waits to append; X is edited in place; beat F walks from
 * before X, finds it, and commits; then A commits, clean, the newest beat.
 * Returns X and F's row.
 */
async function overtaken() {
  await writeAuditHeartbeat(db.runtime, chainKey, slow, quiet);
  await writeAuditHeartbeat(db.runtime, chainKey, slow, quiet);
  await db.runtime.transaction((tx) => appendAudit(tx, chainKey, [{ actorType: 'system', actorId: 'coffre-scheduler', action: 'secret.read', decision: 'allow' }]));
  const x = (await entries()).at(-1)!.seq;
  // The checkpoint signs X before the edit, which its scrub then reaches only laps later.
  assert.ok((await slow.checkpoint()).ok);
  let reached!: () => void;
  const walked = new Promise<void>((resolve) => (reached = resolve));
  let go!: () => void;
  const released = new Promise<void>((resolve) => (go = resolve));
  const a = writeAuditHeartbeat(stepping(async ({ write }, phase) => {
    if (write && phase === 'before') {
      reached();
      await released;
    }
  }), chainKey, slow, quiet);
  await walked;
  await overwrite(x, { metadata: '{"edited":true}' });
  await writeAuditHeartbeat(db.runtime, chainKey, slow, { warn: () => undefined });
  const finder = (await beats()).at(-1)!;
  assert.equal(said(finder).broken?.seq, Number(x));
  go();
  await a;
  assert.equal(said((await beats()).at(-1)!).broken, undefined, 'A walked before the edit, and says the chain verified');
  return { x, finder };
}

test('a beat that walked before a finding, and committed after it, moves no walk past it (formal/Audit.tla, NoResumePastFinding)', async () => {
  const { x, finder } = await overtaken();
  // The next beat resumes no further than where F's walk began, and finds X again.
  assert.deepEqual(await db.runtime.transaction((tx) => resumePoint(tx, chainKey)), { seq: BigInt(said(finder).verified!.seq), hash: Buffer.from(JSON.parse(finder.metadata).verified.hash, 'hex') });
  await writeAuditHeartbeat(db.runtime, chainKey, slow, { warn: () => undefined });
  assert.equal(said((await beats()).at(-1)!).broken?.seq, Number(x));
  assert.equal((await auditReadiness(db.runtime, slow, chainKey)).ok, false);
});

test('readiness runs the next beat\'s walk: red while a finding stands behind the newest beat (formal/Audit.tla, ReadinessWalks)', async () => {
  const { x } = await overtaken();
  // A is the newest beat, clean and checkpointed; F's finding still stands.
  const ready = await auditReadiness(db.runtime, slow, chainKey);
  assert.deepEqual([ready.ok, ready.checkpointed, ready.broken], [false, true, true]);
  // The edit put back, the walk passes, and readiness is green before any beat says so.
  await overwrite(x, { metadata: '{}' });
  assert.equal((await auditReadiness(db.runtime, slow, chainKey)).ok, true);
});

test('a finder hidden as readiness is asked is walked over, not passed over (formal/Audit.tla, ReadinessWalks)', async () => {
  await writeAuditHeartbeat(db.runtime, chainKey, slow, quiet);
  await db.runtime.transaction((tx) => appendAudit(tx, chainKey, [{ actorType: 'system', actorId: 'coffre-scheduler', action: 'secret.read', decision: 'allow' }]));
  const x = (await entries()).at(-1)!.seq;
  assert.ok((await slow.checkpoint()).ok);
  await overwrite(x, { metadata: '{"edited":true}' });
  await writeAuditHeartbeat(db.runtime, chainKey, slow, { warn: () => undefined });
  const finder = (await beats()).at(-1)!;
  assert.equal(said(finder).broken?.seq, Number(x));
  // No beat at all now: the newest is the clean one before it, which the finder's checkpoint covers.
  await overwrite(finder.seq, { action: 'audit.hidden' });
  const ready = await auditReadiness(db.runtime, slow, chainKey);
  assert.deepEqual([ready.ok, ready.checkpointed, ready.broken], [false, true, true]);
});

test('a finder hidden while the next beat reads where to resume, and put back before it walks, is found: one snapshot (formal/Audit.tla, OneSnapshot)', async () => {
  const { x, finder } = await overtaken();
  // Beat C: F's row is no beat at all as C's first snapshot begins, and back as it was once it ends.
  await writeAuditHeartbeat(stepping(async ({ n }, phase) => {
    if (n === 1) await overwrite(finder.seq, { action: phase === 'before' ? 'audit.hidden' : 'audit.heartbeat' });
  }), chainKey, slow, { warn: () => undefined });
  // C's walk read F's row hidden, and found it changed; the next walks from where F's began, and finds X.
  assert.equal(said((await beats()).at(-1)!).broken?.seq, Number(finder.seq));
  await writeAuditHeartbeat(db.runtime, chainKey, slow, { warn: () => undefined });
  assert.equal(said((await beats()).at(-1)!).broken?.seq, Number(x));
  assert.equal((await auditReadiness(db.runtime, slow, chainKey)).ok, false);
});

test('a beat counts only by its MAC, and only for a point before its own row (formal/Audit.tla, CursorByMac)', async () => {
  await writeAuditHeartbeat(db.runtime, chainKey, slow, quiet);
  await db.runtime.transaction((tx) => appendAudit(tx, chainKey, [{ actorType: 'system', actorId: 'coffre-scheduler', action: 'secret.read', decision: 'allow' }]));
  const x = (await entries()).at(-1)!.seq;
  assert.ok((await slow.checkpoint()).ok);
  await overwrite(x, { metadata: '{"edited":true}' });
  await writeAuditHeartbeat(db.runtime, chainKey, slow, { warn: () => undefined });
  const finder = (await beats()).at(-1)!;
  assert.equal(said(finder).broken?.seq, Number(x));
  // F's row rewritten to say it verified through itself, clean: anyone who writes rows can, but not under the app's key.
  await overwrite(finder.seq, { metadata: JSON.stringify({ source: 'scheduled', verified: { seq: Number(finder.seq), hash: finder.hash.toString('hex') } }) });
  await writeAuditHeartbeat(db.runtime, chainKey, slow, { warn: () => undefined });
  assert.equal(said((await beats()).at(-1)!).broken?.seq, Number(x));
  assert.equal((await auditReadiness(db.runtime, slow, chainKey)).ok, false);
});

/**
 * Beat X walks past entry x, clean, and waits to append; x is edited; beat F walks from before x, finds it, and waits
 * too; X commits first, with its checkpoint, then F, with its checkpoint unless `checkpointsF` is false.
 */
async function finderAfterOvertaker({ checkpointsF }: { checkpointsF: boolean }) {
  await writeAuditHeartbeat(db.runtime, chainKey, slow, quiet);
  await writeAuditHeartbeat(db.runtime, chainKey, slow, quiet);
  await db.runtime.transaction((tx) => appendAudit(tx, chainKey, [{ actorType: 'system', actorId: 'coffre-scheduler', action: 'secret.read', decision: 'allow' }]));
  const x = (await entries()).at(-1)!.seq;
  assert.ok((await slow.checkpoint()).ok);
  const pause = () => {
    let reached!: () => void;
    let go!: () => void;
    const at = new Promise<void>((resolve) => (reached = resolve));
    const released = new Promise<void>((resolve) => (go = resolve));
    const paused = stepping(async ({ write }, phase) => {
      if (write && phase === 'before') {
        reached();
        await released;
      }
    });
    return { db: paused, at, go };
  };
  const px = pause();
  const beatX = writeAuditHeartbeat(px.db, chainKey, slow, quiet);
  await px.at;
  await overwrite(x, { metadata: '{"edited":true}' });
  const pf = pause();
  const vaultF = checkpointsF ? slow : { ...slow, checkpoint: async () => ({ ok: true as const, checkpoint: null as never }) };
  const beatF = writeAuditHeartbeat(pf.db, chainKey, vaultF, { warn: () => undefined });
  await pf.at;
  px.go();
  await beatX;
  pf.go();
  await beatF;
  const finder = (await beats()).at(-1)!;
  assert.equal(said(finder).broken?.seq, Number(x));
  assert.equal((await auditReadiness(db.runtime, slow, chainKey)).ok, false);
  return { x, finder };
}

/**
 * Entry `seq` made one of the vault's, its hash recomputed, and the rows after it, all the vault's, chained to it
 * again, the head row too: to the app's walk, a chain whole, and no beat.
 */
async function makeVaults(seq: bigint) {
  const [row, ...after] = (await entries()).filter((entry) => entry.seq >= seq) as StoredEntry[];
  assert.ok(after.every((entry) => entry.author === 'vault'));
  let prevHash = entryHash(row!.prevHash, { ...row!, author: 'vault' }, row!.mac);
  await withLogUnlocked(db.owner, async (owner) => {
    await owner.update(auditLog).set({ author: 'vault', hash: prevHash }).where(eq(auditLog.seq, seq));
    for (const entry of after) {
      const next = entryHash(prevHash, entry, entry.mac);
      await owner.update(auditLog).set({ prevHash, hash: next }).where(eq(auditLog.seq, entry.seq));
      prevHash = next;
    }
    await owner.update(auditChainHead).set({ headHash: prevHash });
  });
}

test('a finder made one of the vault\'s rows after its checkpoint signed it leaves readiness red (formal/Audit.tla, ReadinessAsksVault)', async () => {
  const { finder } = await finderAfterOvertaker({ checkpointsF: true });
  await makeVaults(finder.seq);
  assert.equal((await auditReadiness(db.runtime, slow, chainKey)).ok, false);
});

test('a finder made one of the vault\'s rows before its checkpoint ran leaves readiness red, through the refusal and writes after it (formal/Audit.tla, ReadinessAsksVault)', async () => {
  const { finder } = await finderAfterOvertaker({ checkpointsF: false });
  await makeVaults(finder.seq);
  // The vault refuses, by its MAC of the row; the app writes on, its head still ahead of the one it remembers.
  const refused = await slow.checkpoint();
  assert.ok(!refused.ok);
  await db.runtime.transaction((tx) => appendAudit(tx, chainKey, [{ actorType: 'system', actorId: 'coffre-scheduler', action: 'secret.read', decision: 'allow' }]));
  const ready = await auditReadiness(db.runtime, slow, chainKey);
  assert.deepEqual([ready.ok, ready.checkpointed, ready.broken], [false, true, true]);
});

test('a beat that could not walk is no point to resume from: the next goes on from the one before', async () => {
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  await writeAuditHeartbeat(db.runtime, chainKey, vault, quiet);
  const before = await db.runtime.transaction((tx) => resumePoint(tx, chainKey));
  assert.ok(before.seq >= 0n);
  // Its first transaction fails, as a dropped connection would: it says so, and where it began it cannot say.
  await writeAuditHeartbeat(stepping(async ({ n }, phase) => {
    if (n === 1 && phase === 'before') throw new Error('connection lost');
  }), chainKey, vault, { warn: () => undefined });
  const failed = (await beats()).at(-1)!;
  assert.deepEqual([said(failed).verified, (JSON.parse(failed.metadata) as { unverified?: string }).unverified], [undefined, 'connection lost']);
  assert.deepEqual(await db.runtime.transaction((tx) => resumePoint(tx, chainKey)), before);
});

test('beats the app wrote since are no finding, however many instances beat at once', async () => {
  await writeAuditHeartbeat(db.runtime, chainKey, slow, quiet);
  // Thirteen instances, each beating on its own timer, all in phase: more than the hour of beats a resume reads back.
  for (let i = 0; i < 13; i++) await writeAuditHeartbeat(db.runtime, chainKey, slow, quiet);
  const newest = (await beats()).at(-1)!;
  assert.equal((await db.runtime.transaction((tx) => resumePoint(tx, chainKey))).seq, BigInt(said(newest).verified!.seq));
  assert.equal((await auditReadiness(db.runtime, slow, chainKey)).ok, true);
});
