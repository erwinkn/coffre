// The audit watch's beat and readiness as the scheduled run and `/readyz`
// call them (app.ts), over a context of the test's own: one per call, as
// one per run.
import type { Vault } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { migrated } from '@coffre/db/schema-version';

import type { AnchorStore } from '../src/anchor.ts';
import { acceptLoss as accept, beat, readiness, walkOn, type Readiness } from '../src/plugins/audit-watch.ts';
import { watchContext, type WatchActor } from '../src/watch.ts';

export { HEARTBEAT_STALE_AFTER_SECONDS } from '../src/plugins/audit-watch.ts';

export type HeartbeatLogger = { warn: (obj: unknown, msg: string) => void };

/** A beat, its alerts handed to `alert`. */
export function writeAuditHeartbeat(db: Database, chainKey: Buffer, vault: Vault, anchors: AnchorStore, log: HeartbeatLogger, alert?: (text: string) => void): Promise<boolean> {
  return beat(watchContext({ db, chainKey, vault, warn: log.warn, alert }), anchors);
}

/** What `/readyz` answers with the watch: nothing of it below the migrations. */
export async function auditReadiness(db: Database, vault: Vault, chainKey: Buffer, anchors: AnchorStore): Promise<Readiness> {
  if (!(await migrated(db).catch(() => false))) return { ok: false, heartbeatAgeSeconds: null, checkpointed: false, broken: false, anchored: false };
  return readiness(watchContext({ db, chainKey, vault }), anchors);
}

/** One walk of a backlog between beats. */
export function walkAuditBacklog(db: Database, chainKey: Buffer, vault: Vault, anchors: AnchorStore, alert?: (text: string) => void): Promise<boolean> {
  return walkOn(watchContext({ db, chainKey, vault, alert, warn: () => {} }), anchors);
}

/** An Owner's acceptance of lost entries, in `actor`'s name. */
export function acceptLoss(db: Database, chainKey: Buffer, vault: Vault, anchors: AnchorStore, actor: WatchActor, range: { from: number; to: number }, alert?: (text: string) => void) {
  return accept(watchContext({ db, chainKey, vault, actor, alert }), anchors, range);
}
