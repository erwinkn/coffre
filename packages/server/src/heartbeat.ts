import { verifyCheckpoint, type LogHead, type Vault } from '@coffre/core/vault';
import type { Database, Queryable } from '@coffre/db';
import { SNAPSHOT } from '@coffre/db/dialect';
import { migrated } from '@coffre/db/schema-version';

import { appendAudit, appLogKey, CHAIN_START, resumePoint, walkChain, type ChainPoint } from './db/audit.ts';
import { latestTallied, readiness } from './db/queries.ts';

export type HeartbeatLogger = {
  warn: (obj: unknown, msg: string) => void;
};

/**
 * Logging-failure detection, and the app's half of the log's checkpoints.
 *
 * CDR (EU) 2024/1774 Art 12(2)(e) requires "measures to detect a failure of
 * logging systems". This is not box-ticking: Infisical's audit queue returned
 * early and dropped every entry, silently, and nobody noticed until someone
 * went looking for logs that were never there.
 *
 * The scheduled job first verifies the chain from where the last beat left
 * off (`resumePoint`): every link and hash, and the app's own entries by
 * its key, which only the app holds. Then it appends an `audit.heartbeat`
 * entry that says how far that got (`verified`), or, if it found the chain
 * broken, where it began and what it found, and asks the vault to checkpoint the log,
 * which signs every entry up to the newest, the beat included, in an
 * `audit.checkpoint` entry of its own. A verification starts from both:
 * the app's MACs from the newest beat's `verified`, the vault's from its
 * newest checkpoint (`verifyAudit`). A walk that finds a fault leaves
 * `verified` where it began, so the next verification finds it again.
 *
 * `/readyz` passes only while the newest beat is recent and a checkpoint
 * covers it: a log that stopped taking writes, or a vault that stopped
 * signing, turns it red within one missed beat, which a monitor turns into
 * a page.
 */
export async function writeAuditHeartbeat(
  db: Database,
  chainKey: Buffer,
  vault: Vault,
  log: HeartbeatLogger,
): Promise<boolean> {
  let verified: ChainPoint = CHAIN_START;
  // What the walk found, or why it could not run: either keeps readiness red until a walk passes.
  let broken: { seq: number; reason: string } | null = null;
  let unverified: string | null = null;
  try {
    // Where to resume, and the walk from there, in one snapshot: every beat row past that point is one the walk
    // reads, so a finder's row hidden while this reads where to resume, and put back before it walks, is not
    // passed over (formal/Audit.tla, `OneSnapshot`).
    verified = await db.transaction(async (tx) => {
      const from = await resumePoint(tx, chainKey);
      verified = from;
      const walked = await walkChain(tx, chainKey, from);
      // Short of the head, it says how far it got, and is no verdict on the rest: the next beat goes on.
      if (walked.ok && !walked.done) unverified = `verified through entry ${walked.at.seq}, a walk a beat: the rest goes on next time`;
      if (walked.ok) return walked.at;
      broken = { seq: Number(walked.failedAtSeq), reason: walked.reason };
      log.warn({ failedAtSeq: broken.seq, reason: walked.reason }, 'the audit log does not verify from the last heartbeat');
      return from;
    }, SNAPSHOT);
  } catch (error) {
    // The beat is the signal that logging works: it is written all the same, saying where this walk would have begun.
    unverified = (error as Error).message;
    log.warn({ err: unverified }, 'the audit log could not be verified from the last heartbeat');
  }
  try {
    await db.transaction((tx) =>
      appendAudit(tx, chainKey, [
        {
          actorType: 'system',
          actorId: 'coffre-scheduler',
          action: 'audit.heartbeat',
          decision: 'allow',
          metadata: {
            source: 'scheduled',
            ...(verified.seq < 0n ? {} : { verified: { seq: Number(verified.seq), hash: verified.hash.toString('hex') } }),
            // What the walk found, which readiness shows: the vault's checkpoint signs over the app's entries without their MACs.
            ...(broken === null ? {} : { broken }),
            ...(unverified === null ? {} : { unverified }),
          },
        },
      ]),
    );
  } catch (error) {
    // A heartbeat that cannot write is itself the signal.
    log.warn({ err: (error as Error).message }, 'audit heartbeat failed to write');
    return false;
  }
  try {
    const signed = await vault.checkpoint();
    if (signed.ok && signed.warning !== undefined) log.warn({ warning: signed.warning }, 'the vault checkpointed the audit log, with a warning');
    if (signed.ok) return true;
    log.warn({ code: signed.refusal.code }, 'the vault refused to checkpoint the audit log');
    return false;
  } catch (error) {
    log.warn({ err: (error as Error).message }, 'audit checkpoint failed');
    return false;
  }
}

/**
 * How old the last heartbeat may be before readiness fails. Cron beats every
 * five minutes, so this allows one late or skipped run, plus a minute of
 * scheduling slack, before a monitor sees a failure.
 */
export const HEARTBEAT_STALE_AFTER_SECONDS = 11 * 60;

export type Readiness = {
  ok: boolean;
  /** The newest heartbeat's age by the database's clock, or null before the first. */
  heartbeatAgeSeconds: number | null;
  /** Whether a checkpoint the vault signed covers that heartbeat. */
  checkpointed: boolean;
  /**
   * Whether that heartbeat's walk of the chain found it broken, or could not
   * run: an entry in the app's name it did not write is one the vault signs
   * over, since it cannot check the app's MACs. The audit page says where.
   * So too a heartbeat in the app's name the app did not write, and a walk
   * run now, from where the next beat would resume, that finds a fault or
   * cannot reach the head.
   */
  broken: boolean;
};

/**
 * Readiness: the database migrated, the newest heartbeat under
 * `HEARTBEAT_STALE_AFTER_SECONDS` old, its walk of the chain whole, and a
 * checkpoint after it whose signature is the vault's; and the log verified
 * now, as a verification does (`verifyAudit`): the app's walk from where
 * the next beat would resume, or the newest checkpoint's prefix if that is
 * further back, to the head, then the vault's of its own entries over the
 * same stretch. That is the entries since the newest beat's walk began, as
 * a beat's own walk is. The app's finds a beat row hidden or changed
 * since, and a finding of a beat that committed before the newest but
 * walked after it; the vault's, a row made one of its own, which the app
 * cannot check, and a checkpoint it refused since. A heartbeat alone, a checkpoint with no
 * heartbeat, or a refused checkpoint all leave it red, and so does a fresh
 * database until the first pair. Liveness deliberately does not call this:
 * a database incident should mark the service unavailable, not trigger a
 * restart loop.
 */
export async function auditReadiness(db: Database, vault: Vault, chainKey: Buffer): Promise<Readiness> {
  const unready: Readiness = { ok: false, heartbeatAgeSeconds: null, checkpointed: false, broken: false };
  try {
    if (!(await migrated(db))) return unready;
    // In one snapshot: read apart, a beat and a checkpoint that were never the newest together could answer green
    // (formal/Audit.tla, `ReadinessInOneSnapshot`), as a beat that stopped short commits between them.
    // So is the app's walk (`ReadinessWalks`), run only when the beat says the chain verified.
    const { beat, checkpoint, walked } = await db.transaction(async (tx) => {
      const rows = await readiness(tx, appLogKey(chainKey));
      const said = rows.beat === null ? null : (JSON.parse(rows.beat.metadata) as { broken?: unknown; unverified?: unknown } | null);
      const clean = rows.beat !== null && rows.beat.authentic && said?.broken === undefined && said?.unverified === undefined;
      return { ...rows, walked: clean ? await walkToHead(tx, chainKey) : null };
    }, SNAPSHOT);
    if (beat === null) return unready;
    // The vault's entries over the same stretch, by its key (`ReadinessAsksVault`), outside the app's transaction.
    const vouched = walked !== null && (await vault.verifyLog(walked)).ok;
    // Asked each time: after a rotation, the key the vault signed with until then counts only for what came before.
    const key = checkpoint === null ? undefined : (await vault.about()).checkpointKeys[checkpoint.keyId];
    const checkpointed =
      checkpoint !== null &&
      key !== undefined &&
      (key.until === null || checkpoint.seq < key.until) &&
      BigInt(checkpoint.seq) >= beat.seq &&
      (await verifyCheckpoint(checkpoint, key.publicKey));
    const fresh = Number.isFinite(beat.ageSeconds) && beat.ageSeconds <= HEARTBEAT_STALE_AFTER_SECONDS;
    const broken = !vouched;
    return { ok: fresh && checkpointed && !broken, heartbeatAgeSeconds: beat.ageSeconds, checkpointed, broken };
  } catch {
    return unready;
  }
}

/**
 * The app's half of readiness's verification, in the caller's snapshot: the
 * walk from where the next beat would resume, or the newest checkpoint's
 * prefix if that is further back, so that the vault may leave the links to
 * it from there, to the head; and what to ask the vault, or null if the
 * walk found a fault or could not reach the head.
 */
async function walkToHead(tx: Queryable, chainKey: Buffer): Promise<{ upTo: LogHead | null; from: number | 'start' } | null> {
  const [resume, tallied] = await Promise.all([resumePoint(tx, chainKey), latestTallied(tx)]);
  if (tallied !== null && tallied.checkpoint === null) return null;
  const signed = tallied === null ? CHAIN_START : { seq: BigInt(tallied.checkpoint!.seq), hash: Buffer.from(tallied.checkpoint!.hash, 'hex') };
  const walked = await walkChain(tx, chainKey, resume.seq <= signed.seq ? resume : signed);
  if (!walked.ok || !walked.done) return null;
  return {
    upTo: walked.at.seq < 0n ? null : { seq: Number(walked.at.seq), hash: walked.at.hash.toString('hex') },
    from: tallied === null ? 'start' : Number(tallied.entry),
  };
}
