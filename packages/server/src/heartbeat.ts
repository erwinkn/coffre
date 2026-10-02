import { verifyCheckpoint, type Vault } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { requiredMigrations } from '@coffre/db/schema-version';

import { appendAudit } from './db/audit.ts';
import { appliedMigrations, readiness } from './db/queries.ts';

export type HeartbeatLogger = {
  warn: (obj: unknown, msg: string) => void;
};

/**
 * Logging-failure detection.
 *
 * CDR (EU) 2024/1774 Art 12(2)(e) requires "measures to detect a failure of
 * logging systems". This is not box-ticking: Infisical's audit queue returned
 * early and dropped every entry, silently, and nobody noticed until someone
 * went looking for logs that were never there.
 *
 * The scheduled job appends an `audit.heartbeat` entry, then asks the vault
 * to checkpoint the log, which signs every entry up to the newest, the beat
 * included, in an `audit.checkpoint` entry of its own. `/readyz` passes only
 * while the newest beat is recent and a checkpoint covers it: a log that
 * stopped taking writes, or a vault that stopped signing, turns it red
 * within one missed beat, which a monitor turns into a page.
 */
export async function writeAuditHeartbeat(
  db: Database,
  chainKey: Buffer,
  vault: Vault,
  log: HeartbeatLogger,
): Promise<boolean> {
  try {
    await db.transaction((tx) =>
      appendAudit(tx, chainKey, [
        {
          actorType: 'system',
          actorId: 'coffre-scheduler',
          action: 'audit.heartbeat',
          decision: 'allow',
          metadata: { source: 'scheduled' },
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
};

/**
 * Readiness: the database migrated, the newest heartbeat under
 * `HEARTBEAT_STALE_AFTER_SECONDS` old, and a checkpoint after it whose
 * signature is the vault's. A heartbeat alone, a checkpoint with no
 * heartbeat, or a refused checkpoint all leave it red, and so does a fresh
 * database until the first pair. Liveness deliberately does not call this:
 * a database incident should mark the service unavailable, not trigger a
 * restart loop.
 */
export async function auditReadiness(db: Database, vault: Vault): Promise<Readiness> {
  const unready: Readiness = { ok: false, heartbeatAgeSeconds: null, checkpointed: false };
  try {
    if ((await appliedMigrations(db)) < requiredMigrations(db)) return unready;
    const { beat, checkpoint } = await readiness(db);
    if (beat === null) return unready;
    // Asked each time: after a rotation, the key the vault signed with until then counts only for what came before.
    const key = checkpoint === null ? undefined : (await vault.about()).checkpointKeys[checkpoint.keyId];
    const checkpointed =
      checkpoint !== null &&
      key !== undefined &&
      (key.until === null || checkpoint.seq < key.until) &&
      BigInt(checkpoint.seq) >= beat.seq &&
      (await verifyCheckpoint(checkpoint, key.publicKey));
    const fresh = Number.isFinite(beat.ageSeconds) && beat.ageSeconds <= HEARTBEAT_STALE_AFTER_SECONDS;
    return { ok: fresh && checkpointed, heartbeatAgeSeconds: beat.ageSeconds, checkpointed };
  } catch {
    return unready;
  }
}
