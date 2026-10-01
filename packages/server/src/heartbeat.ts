import type { Checkpoint, Vault } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { auditHeartbeat } from '@coffre/db/schema';
import { requiredMigrations } from '@coffre/db/schema-version';

import { appendAudit } from './db/audit.ts';
import { appliedMigrations, auditHead, auditRange, heartbeat, latestAudit, update } from './db/queries.ts';

export type HeartbeatLogger = {
  warn: (obj: unknown, msg: string) => void;
};

class MissingSingleton extends Error {}

/**
 * Logging-failure detection.
 *
 * CDR (EU) 2024/1774 Art 12(2)(e) requires "measures to detect a failure of
 * logging systems". This is not box-ticking: Infisical's audit queue returned
 * early and dropped every entry, silently, and nobody noticed until someone
 * went looking for logs that were never there.
 *
 * The scheduled Worker writes a row and records the current chain head. A
 * monitor alerts when `last_beat_at` goes stale, which turns "the audit log
 * stopped receiving writes" into a paging event rather than an audit finding.
 * `/readyz` surfaces it too.
 *
 * The signal advances only after the vault signs the head and the app
 * commits its record of that checkpoint; see `checkpointAudit`.
 */
export async function writeAuditHeartbeat(
  db: Database,
  chainKey: Buffer,
  vault: Vault,
  log: HeartbeatLogger,
): Promise<boolean> {
  const beat = await writeBeat(db, chainKey, log);
  if (!beat) return false;
  try {
    if (!(await checkpointAudit(db, chainKey, vault, log))) return false;
    if ((await update(db, auditHeartbeat, { onlyRow: true }, beat)) === 0) {
      log.warn({}, 'audit heartbeat singleton is missing');
      return false;
    }
    return true;
  } catch (error) {
    log.warn({ err: (error as Error).message }, 'audit checkpoint failed');
    return false;
  }
}

async function writeBeat(
  db: Database,
  chainKey: Buffer,
  log: HeartbeatLogger,
): Promise<{ lastBeatAt: Date; lastSeq: bigint } | null> {
  try {
    return await db.transaction(async (tx) => {
      if ((await heartbeat(tx)) === null) throw new MissingSingleton();
      const { nextSeq, occurredAt } = await appendAudit(tx, chainKey, [
        {
          actorType: 'system',
          actorId: 'coffre-scheduler',
          action: 'audit.heartbeat',
          decision: 'allow',
          metadata: { source: 'scheduled' },
        },
      ]);
      // The entry's own timestamp, which is the database clock.
      return { lastBeatAt: new Date(occurredAt), lastSeq: nextSeq };
    });
  } catch (error) {
    if (error instanceof MissingSingleton) {
      // Rolled back, entry and all: a beat nobody can see is not a beat.
      log.warn({}, 'audit heartbeat singleton is missing');
      return null;
    }
    // A heartbeat that cannot write is itself the signal.
    log.warn({ err: (error as Error).message }, 'audit heartbeat failed to write');
    return null;
  }
}

/**
 * Have the vault sign the app log's head, with its own log's, and record
 * what it signed as an `audit.checkpoint` entry. Each log is then anchored
 * in the other's store:
 *
 * - The vault signs a head only if the app's log still holds, at the last
 *   checkpoint's seq, the hash it signed then. A log rewritten behind a
 *   checkpoint and chained again, which the chain key alone cannot catch, is
 *   refused here and fails `GET /api/audit/verification`.
 * - The vault signs only while its own log still holds the head it signed
 *   last, and the app keeps each head it signed. A vault log rewritten, or a
 *   vault store put back to an older copy, no longer matches that record.
 *
 * Two heartbeats racing look like a rewrite to the one that loses, so a
 * refusal is tried once more against the new checkpoint.
 */
export async function checkpointAudit(
  db: Database,
  chainKey: Buffer,
  vault: Vault,
  log: HeartbeatLogger,
): Promise<boolean> {
  for (let attempt = 0; ; attempt++) {
    const [head, recorded, { checkpoint: latest }] = await Promise.all([
      auditHead(db),
      recordedCheckpoint(db),
      vault.latestCheckpoint(),
    ]);
    if (head === null || head.nextSeq === 0n) return true;
    if (recorded !== null && !recorded.ok) {
      log.warn({ seq: recorded.seq }, 'the checkpoint the audit log recorded is not one');
      return false;
    }
    const behind = vaultBehind(latest, recorded?.checkpoint ?? null);
    if (behind !== null) {
      log.warn({ recorded: recorded?.checkpoint.seq, latest: latest?.seq ?? null }, behind);
      return false;
    }
    let previous = null;
    if (latest !== null) {
      const [row] = await auditRange(db, BigInt(latest.seq), 1);
      // Gone, it cannot match: the vault refuses, and logs it.
      previous = { seq: latest.seq, hash: row?.seq === BigInt(latest.seq) ? row.hash.toString('hex') : '' };
    }
    const signed = await vault.checkpoint({
      seq: Number(head.nextSeq - 1n),
      headHash: head.headHash.toString('hex'),
      previous,
    });
    if (signed.ok) {
      if (signed.checkpoint.seq !== recorded?.checkpoint.seq) {
        await db.transaction((tx) =>
          appendAudit(tx, chainKey, [
            {
              actorType: 'system',
              actorId: 'coffre-scheduler',
              action: CHECKPOINT_ACTION,
              decision: 'allow',
              metadata: signed.checkpoint,
            },
          ]),
        );
      }
      return true;
    }
    if (attempt === 1) {
      log.warn({ code: signed.refusal.code }, 'the vault refused to checkpoint the audit log');
      return false;
    }
  }
}

/** The action of the entry that records a checkpoint; its metadata is the checkpoint. */
export const CHECKPOINT_ACTION = 'audit.checkpoint';

/**
 * The checkpoint the app recorded last, from the entry that holds it, or
 * null before the first. Not `ok` when that entry does not hold one.
 */
async function recordedCheckpoint(db: Database) {
  const row = await latestAudit(db, CHECKPOINT_ACTION);
  return row === null ? null : readCheckpoint(row.seq, row.metadata);
}

/** A checkpoint recorded at `seq`, from its entry's metadata. */
export function readCheckpoint(
  seq: bigint,
  metadata: string,
): { ok: true; seq: bigint; checkpoint: Checkpoint } | { ok: false; seq: bigint } {
  const value = JSON.parse(metadata) as Partial<Checkpoint>;
  const ok =
    Number.isSafeInteger(value.seq) &&
    typeof value.headHash === 'string' &&
    Number.isSafeInteger(value.vault?.seq) &&
    typeof value.vault?.hash === 'string' &&
    typeof value.signedAt === 'string' &&
    typeof value.keyId === 'string' &&
    typeof value.signature === 'string';
  return ok ? { ok, seq, checkpoint: value as Checkpoint } : { ok, seq };
}

/**
 * Why the vault's latest checkpoint is behind the one the app recorded last,
 * or null when it is that one or a later one. The vault only moves forward,
 * so behind means its store was put back to an older copy, or emptied.
 */
export function vaultBehind(latest: Checkpoint | null, recorded: Checkpoint | null): string | null {
  if (recorded === null) return null;
  if (latest === null) {
    return `the vault has no checkpoint, but the audit log recorded one at seq ${recorded.seq}: its store was emptied`;
  }
  if (latest.seq < recorded.seq || (latest.seq === recorded.seq && latest.signature !== recorded.signature)) {
    return `the vault's latest checkpoint, at seq ${latest.seq}, is behind the one the audit log recorded at seq ${recorded.seq}: its store was put back to an older copy`;
  }
  return null;
}

/**
 * How stale the heartbeat is, in seconds. Used by /readyz. Both ends are the
 * database's clock, so a skewed application server cannot hide a stale beat.
 */
export async function heartbeatAgeSeconds(db: Database): Promise<number | null> {
  const row = await heartbeat(db);
  if (row === null) return null;
  return (Date.parse(row.now) - row.lastBeatAt.getTime()) / 1000;
}

/**
 * How old the last heartbeat may be before readiness fails. Cron beats every
 * five minutes, so this allows one late or skipped run, plus a minute of
 * scheduling slack, before a monitor sees a failure.
 */
export const HEARTBEAT_STALE_AFTER_SECONDS = 11 * 60;

export type Readiness =
  | { ok: true; auditHeartbeatAgeSeconds: number }
  | { ok: false; auditHeartbeatAgeSeconds: number | null };

/**
 * Readiness includes database access and a recent successful audit heartbeat.
 * Liveness deliberately does not call this: a database incident should mark
 * the service unavailable, not trigger a runtime restart loop.
 */
export async function auditReadiness(
  db: Database,
): Promise<Readiness> {
  try {
    if ((await appliedMigrations(db)) < requiredMigrations(db)) {
      return { ok: false, auditHeartbeatAgeSeconds: null };
    }
    const age = await heartbeatAgeSeconds(db);
    if (age === null || !Number.isFinite(age) || age > HEARTBEAT_STALE_AFTER_SECONDS) {
      return { ok: false, auditHeartbeatAgeSeconds: age };
    }
    return { ok: true, auditHeartbeatAgeSeconds: age };
  } catch {
    return { ok: false, auditHeartbeatAgeSeconds: null };
  }
}
