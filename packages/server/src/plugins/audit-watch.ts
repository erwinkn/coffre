// The audit watch (docs/design/plugins.md, "Watching the log"): a plugin of
// coffre's own that watches the audit log on the scheduled run and keeps
// what it verified outside the database, where whoever writes the
// database cannot change it (`auditWatch`). Without it, coffre's log is as
// tamper-evident as ever, its chain and the vault's checkpoints, but
// tampering is found only when someone verifies the log; `/readyz` says
// only that the database is migrated.
//
//   plugins: [auditWatch({ anchor: durableAnchor(env.ANCHOR) })]   // Workers
//   plugins: [auditWatch({ anchor: fileAnchor('/var/lib/coffre/anchor.json') })]   // Node
//
// It reaches the log and the vault through a watch context's capabilities
// (watch.ts), never a client of either.
import { verifyCheckpoint, type Checkpoint, type LogHead } from '@coffre/core/vault';

import type { AnchorFields, AnchorFinding, AnchorStore, AuditAnchor } from '../anchor.ts';
import type { CoffrePlugin } from '../plugins.ts';
import { Refusal, watcher, WATCH, type WatchContext } from '../watch.ts';

export type AuditWatchOptions = {
  /** Where the anchor lives: `durableAnchor(env.ANCHOR)` on Workers, `fileAnchor(path)` on one Node process, or any `AnchorStore`. */
  anchor: AnchorStore;
};

/** The audit watch, over the anchor's store. */
export function auditWatch(options: AuditWatchOptions): CoffrePlugin {
  const { anchor } = options;
  if (anchor === undefined || typeof anchor.read !== 'function' || typeof anchor.write !== 'function') {
    throw new Error('auditWatch: anchor is an AnchorStore, such as durableAnchor(env.ANCHOR) or fileAnchor(path)');
  }
  const hooks = watcher({
    scheduled: (ctx) => beat(ctx, anchor),
    readiness: (ctx) => readiness(ctx, anchor),
    // Nothing an anchor vouches for while there is none of the app's, or while it walks the log whole to re-anchor.
    verified: async (ctx) => {
      const held = await anchor.read();
      return held !== null && ctx.own(held) && held.reanchor === null ? held.verified : undefined;
    },
    walkOn: (ctx, store) => walkOn(ctx, store ?? anchor),
    acceptLoss: (ctx, range) => acceptLoss(ctx, anchor, range),
  });
  return { name: 'audit-watch', [WATCH]: hooks } as CoffrePlugin;
}

/** An anchor's fields, but for what each write sets itself: when, and by which beat. */
type Fields = Omit<AnchorFields, 'at' | 'beat'>;

/** What a beat that finds the store empty starts from: nothing verified, nothing found, the whole log to walk. */
const unanchored = (since: number): Fields => ({ checkpoint: null, verified: null, finding: null, reanchor: { since }, epoch: 0 });

/**
 * A beat: logging-failure detection, and the app's half of the log's
 * checkpoints. CDR (EU) 2024/1774 Art 12(2)(e) requires "measures to
 * detect a failure of logging systems". This is not box-ticking:
 * Infisical's audit queue returned early and dropped every entry,
 * silently, and nobody noticed until someone went looking.
 *
 * It appends an `audit.heartbeat` entry, the signal that the log takes
 * writes, and asks the vault to checkpoint the log, which signs every
 * entry up to the newest, the beat included, its own entries checked by
 * its MAC. Then it walks the chain from where the anchor says the app
 * verified to, toward the prefix the vault just signed: every link and
 * hash, the app's own entries by its key, and the hash the vault signed at
 * the end. The anchor keeps the outcome: the newest checkpoint, how far
 * the app verified, and what a walk found.
 *
 * A finding stands until the entry it names verifies again: each beat
 * checks that entry alone, and once it does, walks on from where the
 * anchor was. A vault that refused to sign, or could not be asked, and a
 * log that took no write, stand until a beat verifies. Each finding, and
 * its clearing, is logged. A backlog is walked `CHAIN_WALK` entries a beat,
 * and between beats (`walkOn`).
 *
 * An empty store, the first beat's or one lost since, is re-anchored by
 * the same path: the whole log walked, a walk at a time, readiness green
 * meanwhile, since an empty store is no evidence of tampering; then an
 * `audit.reanchor` entry, and an alert. A cut made before the store was
 * emptied goes unseen: the alert says when to look.
 *
 * Whether nothing is wrong: false on a finding, an anchor it could not
 * write, or a store it could not use; a backlog still to walk is not.
 */
export async function beat(ctx: WatchContext, anchors: AnchorStore): Promise<boolean> {
  // Read before the vault signs: a beat that runs beside this one and anchors a later checkpoint first wins the
  // compare-and-set, rather than this one finding the checkpoint it got shorter than the anchor's.
  let prev: AuditAnchor | null = null;
  let unusable: string | null = null;
  try {
    prev = await anchors.read();
    if (prev !== null && !ctx.own(prev)) unusable = foreign(ctx, prev);
  } catch (error) {
    unusable = `the audit anchor could not be read: ${(error as Error).message}`;
  }
  let beat: number | null = null;
  let unwritten: string | null = null;
  try {
    beat = await ctx.log.append('audit.heartbeat', { source: 'scheduled' });
  } catch (error) {
    // A heartbeat that cannot write is itself the signal.
    unwritten = (error as Error).message;
    ctx.warn({ err: unwritten }, 'audit heartbeat failed to write');
  }
  // The vault checkpoints whatever becomes of the beat and the anchor: its own walk, its refusal and its rehash of
  // the past go on.
  const signed: Signed = await ctx.vault.checkpoint().then(
    (outcome) => (outcome.ok ? outcome : { ok: false as const, reason: `the vault refused to checkpoint the log: ${outcome.refusal.message}` }),
    (error: Error) => ({ ok: false as const, reason: `the vault could not checkpoint the log: ${error.message}` }),
  );
  if (signed.ok && signed.warning !== undefined) ctx.warn({ warning: signed.warning }, 'the vault checkpointed the audit log, with a warning');
  if (!signed.ok) ctx.warn({ reason: signed.reason }, 'audit checkpoint failed');
  if (unusable !== null) {
    ctx.warn({}, unusable);
    return false;
  }
  for (let lost = 0; ; lost++) {
    const base = prev ?? unanchored(Date.now());
    const next = await outcome(ctx, base, signed, unwritten);
    const written = await commit(ctx, anchors, prev, base, { ...next, beat, at: Date.now() });
    // Short of the checkpoint, or the checkpoint short of this beat, as a vault signing a backlog a walk a call is,
    // is no failure: the next walk goes on, and readiness says how far.
    if (written !== 'lost') return written === 'written' && next.finding === null;
    // A walk between beats (`walkOn`) moved only how far the app verified, toward the same checkpoint: this beat goes
    // on from there, as if it had read it first. Another beat's anchor, a later checkpoint's, is the next beat's to
    // go on from, and this one writes nothing.
    const now = await anchors.read().catch(() => null);
    if (lost === WRITES_LOST || prev === null || now === null || !ctx.own(now) || now.epoch !== prev.epoch || !samePoint(now.checkpoint, prev.checkpoint)) {
      ctx.warn({}, 'another beat wrote the audit anchor first: the next goes on from it');
      return false;
    }
    prev = now;
  }
}

/** The vault's checkpoint as a beat asked it: signed, or why not. */
type Signed = { ok: true; checkpoint: Checkpoint; warning?: string } | { ok: false; reason: string };

/** How many times a beat writes again over a walk between beats that wrote first. */
const WRITES_LOST = 3;

/** Why a record in the store is not the app's: another key's, or no key's. */
function foreign(ctx: WatchContext, anchor: AuditAnchor): string {
  const sealed = typeof anchor.keyId === 'string' ? anchor.keyId : null;
  return sealed !== null && sealed !== ctx.keyId
    ? `the audit anchor is sealed under ${sealed}, not the app's key ${ctx.keyId}: auditChainKey changed, and nothing re-seals it yet. Empty its store, and the next beat re-anchors`
    : 'the audit anchor is not one the app wrote: once it is understood, empty its store, and the next beat re-anchors';
}

function samePoint(a: LogHead | null, b: LogHead | null): boolean {
  return a?.seq === b?.seq && a?.hash === b?.hash;
}

/**
 * What a beat leaves in the anchor, from `base`: what keeps it from
 * verifying stands, and readiness is red now, a finding of the app's walk
 * until its entry verifies again, anything else until a beat verifies;
 * otherwise the walk toward the checkpoint signed.
 */
async function outcome(ctx: WatchContext, base: Fields, signed: Signed, unwritten: string | null): Promise<Fields> {
  const standing = base.finding?.by === 'app' && base.finding.seq !== null ? base.finding : null;
  const fails = (by: AnchorFinding['by'], reason: string): Fields => ({ ...base, finding: standing ?? sameOr(base.finding, { seq: null, reason, by, since: Date.now() }) });
  if (unwritten !== null) return fails('app', `the log takes no writes: ${unwritten}`);
  if (!signed.ok) return fails('vault', signed.reason);
  if (standing !== null && !(await repaired(ctx, standing.seq!, base))) return { ...base, finding: standing };
  try {
    return await advance(ctx, base, signed.checkpoint);
  } catch (error) {
    ctx.warn({ err: (error as Error).message }, 'the audit log could not be verified from the anchor');
    return fails('app', `the log could not be walked: ${(error as Error).message}`);
  }
}

/**
 * One walk of the backlog between beats, toward the anchor's own
 * checkpoint: what a Durable Object's alarm runs on Workers, and Node's
 * scheduled job, a walk after another. Whether there is more to walk.
 * The anchor's age is the newest beat's: a walk is no beat.
 */
export async function walkOn(ctx: WatchContext, anchors: AnchorStore): Promise<boolean> {
  const prev = await anchors.read();
  if (prev === null || !ctx.own(prev) || !walking(prev)) return false;
  const next = await advance(ctx, prev, prev.checkpoint!);
  const fields = { ...next, beat: prev.beat, at: prev.at };
  return (await commit(ctx, anchors, prev, prev, fields)) === 'written' && walking(fields);
}

/** Whether an anchor has a backlog to walk: a checkpoint it has not verified through, and nothing found. */
export function walking(anchor: Omit<AnchorFields, 'at' | 'beat'>): boolean {
  return anchor.checkpoint !== null && anchor.finding === null && anchor.verified?.seq !== anchor.checkpoint.seq;
}

/**
 * One walk from where the anchor says the app verified to, toward the
 * prefix `target` signed, the anchor's own checkpoint first, which the log
 * must still hold by its hash, as a cut or a rewrite before it changes it:
 * the anchor as it then stands. A re-anchoring ends once the walk reaches
 * the checkpoint.
 */
async function advance(ctx: WatchContext, anchor: Fields, target: Checkpoint): Promise<Fields> {
  const found = (seq: number, reason: string): Fields => ({ ...anchor, finding: sameOr(anchor.finding, { seq, reason, by: 'app', since: Date.now() }) });
  const held = anchor.checkpoint;
  if (held !== null && target.seq < held.seq) return found(held.seq, 'the vault signed a prefix shorter than the anchor holds: the log was cut');
  const walked = await ctx.log.walk({ held: held === null ? [] : [held], from: anchor.verified, to: target.seq });
  if (!walked.ok) {
    ctx.warn({ failedAtSeq: walked.failedAtSeq, reason: walked.reason }, 'the audit log does not verify from the anchor');
    return found(walked.failedAtSeq, walked.reason);
  }
  // The vault signed the hash the app computes there, or one of them reads another log.
  if (walked.done && walked.at?.hash !== target.hash) return found(target.seq, 'not the prefix the vault signed');
  return { ...anchor, checkpoint: target, verified: walked.at, finding: null, reanchor: walked.done ? null : anchor.reanchor };
}

/**
 * The anchor written over the record read, and what changed since `base`,
 * what the write started from, logged: a finding made or cleared, and a
 * re-anchoring done, which alerts too. `lost` when the store holds
 * another record than `prev`, `failed` when it could not be used.
 */
async function commit(ctx: WatchContext, anchors: AnchorStore, prev: AuditAnchor | null, base: Fields, fields: AnchorFields): Promise<'written' | 'lost' | 'failed'> {
  const written = await anchors.write(prev, ctx.seal(fields)).catch((error: Error) => {
    ctx.warn({ err: error.message }, 'the audit anchor could not be written');
    return null;
  });
  if (written !== true) return written === false ? 'lost' : 'failed';
  const was = base.finding;
  const since = base.reanchor?.since;
  const reanchored = since !== undefined && fields.reanchor === null && fields.finding === null && fields.checkpoint !== null;
  const logged: [Parameters<WatchContext['log']['append']>[0], Record<string, unknown>][] = [];
  if (fields.finding !== null && fields.finding !== was) logged.push(['audit.finding', { ...fields.finding }]);
  if (was !== null && fields.finding === null) logged.push(['audit.finding_cleared', { finding: was }]);
  if (reanchored) logged.push(['audit.reanchor', { at: fields.checkpoint!.seq, since: new Date(since!).toISOString(), reason: 'the store was empty' }]);
  for (const [action, metadata] of logged) {
    await ctx.log.append(action, metadata).catch((error: Error) => ctx.warn({ err: error.message }, 'what the audit anchor found could not be logged'));
  }
  if (reanchored) {
    ctx.alert(`the audit anchor's store was empty: the log was walked whole and re-anchored at entry ${fields.checkpoint!.seq}. A cut made before the store emptied would go unseen: check the log's newest entries against your own records.`);
  }
  return 'written';
}

/** The finding that stands, if it is this one again: its first sighting stays the one logged. */
function sameOr(was: AnchorFinding | null, found: AnchorFinding): AnchorFinding {
  return was !== null && was.by === found.by && was.seq === found.seq && was.reason === found.reason ? was : found;
}

/**
 * Whether the entry a finding names verifies again, alone: a point the
 * anchor holds by its hash, any other entry by its link to the one before,
 * its hash, and the app's MAC if it is the app's. Two reads, however long
 * it stood.
 */
async function repaired(ctx: WatchContext, seq: number, anchor: Fields): Promise<boolean> {
  const point = [anchor.verified, anchor.checkpoint].find((held) => held?.seq === seq);
  if (point !== undefined) return (await ctx.log.hashAt(seq)) === point!.hash;
  return (await ctx.log.check(seq, 'log'))?.ok === true;
}

/**
 * How old the anchor may be before readiness fails. Cron beats every five
 * minutes, so this allows one late or skipped run, plus a minute of
 * scheduling slack, before a monitor sees a failure.
 */
export const HEARTBEAT_STALE_AFTER_SECONDS = 11 * 60;

export type Readiness = {
  ok: boolean;
  /** The anchor's age, by the app's clock: when a beat last wrote it. Null with no anchor. */
  heartbeatAgeSeconds: number | null;
  /**
   * Whether the anchor's checkpoint is the vault's, covers the beat that
   * wrote it, the log still holds its prefix, and the app verified through
   * it, or is walking the log whole to re-anchor it.
   */
  checkpointed: boolean;
  /** Whether a finding stands, or the log no longer holds the anchor's prefix. */
  broken: boolean;
  /** Whether there is an anchor the app wrote: none before the first beat, or until the next once its store emptied. */
  anchored: boolean;
  /** Set when the anchor's store, the log or the vault could not be read, which the process's log says more of. */
  error?: string;
};

/**
 * Readiness: the anchor the app's, under `HEARTBEAT_STALE_AFTER_SECONDS`
 * old, with no finding, caught up to its checkpoint or walking the log to
 * re-anchor it, its checkpoint the vault's and its prefix one the log
 * still holds. A constant: one read of the anchor, one of the log, one
 * signature. The entries since the newest beat are the next beat's to
 * walk. Core asks it only of a migrated database.
 */
export async function readiness(ctx: WatchContext, anchors: AnchorStore): Promise<Readiness> {
  const unready: Readiness = { ok: false, heartbeatAgeSeconds: null, checkpointed: false, broken: false, anchored: false };
  try {
    const anchor = await anchors.read();
    if (anchor === null || !ctx.own(anchor)) return unready;
    const { checkpoint, verified, finding, beat } = anchor;
    const heartbeatAgeSeconds = (Date.now() - anchor.at) / 1000;
    const holds = checkpoint === null || (await ctx.log.hashAt(checkpoint.seq)) === checkpoint.hash;
    // Asked each time: after a rotation, the key the vault signed with until then counts only for what came before.
    const key = checkpoint === null ? undefined : (await ctx.vault.checkpointKeys())[checkpoint.keyId];
    const through = anchor.reanchor !== null || (verified?.seq === checkpoint?.seq && verified?.hash === checkpoint?.hash);
    const checkpointed =
      checkpoint !== null &&
      holds &&
      through &&
      beat !== null &&
      checkpoint.seq >= beat &&
      key !== undefined &&
      (key.until === null || checkpoint.seq < key.until) &&
      (await verifyCheckpoint(checkpoint, key.publicKey));
    const broken = finding !== null || !holds;
    const fresh = Number.isFinite(heartbeatAgeSeconds) && heartbeatAgeSeconds <= HEARTBEAT_STALE_AFTER_SECONDS;
    return { ok: fresh && checkpointed && !broken, heartbeatAgeSeconds, checkpointed, broken, anchored: true };
  } catch (error) {
    ctx.warn({ err: (error as Error).message }, 'readiness could not read the audit anchor, the log or the vault');
    return { ...unready, error: 'the audit anchor, the log or the vault could not be read' };
  }
}

/**
 * An Owner's acceptance that entries `from` to `to` are lost for good, a
 * tail cut with no backup among them: the one case a finding cannot clear
 * by itself. The range must hold what the standing finding names. Logged
 * first, in their name (the context's actor), with the range and the
 * finding, which stays in the log as it was found; then the anchor moved
 * past the range, in a new epoch, and an alert. The next beat walks on
 * from the entry after the range, checked alone, or, with none, from the
 * one before it; whatever the range holds now is never walked. Tampering
 * anywhere else is found as before. A refusal throws a `Refusal`. Should
 * the anchor change meanwhile to anything but the same finding sealed
 * again, an `audit.loss_unapplied` entry says the acceptance did not take.
 */
export async function acceptLoss(ctx: WatchContext, anchors: AnchorStore, range: { from: number; to: number }): Promise<{ resumes: number | null }> {
  const { from, to } = range;
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || from < 0 || to < from) throw new Refusal('a range is two entries, the first no later than the last');
  const prev = await anchors.read();
  if (prev === null || !ctx.own(prev)) throw new Refusal("there is no anchor of the app's to move: the next beat re-anchors");
  const { finding } = prev;
  if (finding === null || finding.by !== 'app' || finding.seq === null) throw new Refusal('no finding of entries stands: there is nothing to accept');
  if (finding.seq < from || finding.seq > to) throw new Refusal(`entries ${from} to ${to} do not hold entry ${finding.seq}, which the finding names`);
  const resumes = await pastRange(ctx, from, to);
  const accepted = await ctx.log.append('audit.loss_accepted', {
    from,
    to,
    finding,
    anchor: { checkpoint: prev.checkpoint?.seq ?? null, verified: prev.verified?.seq ?? null },
    resumes: resumes?.seq ?? null,
  });
  // A beat meanwhile seals the same finding again, with its own time: the acceptance goes over its record, as long
  // as that is the finding accepted, in the same epoch. Anything else, and the log says it was not applied.
  let stored = prev;
  for (let lost = 0; ; lost++) {
    const next = ctx.seal({ checkpoint: null, verified: resumes, finding: null, beat: stored.beat, reanchor: null, epoch: prev.epoch + 1, at: stored.at });
    const written = await anchors.write(stored, next).catch((error: Error) => error);
    if (written === true) break;
    const now = written === false ? await anchors.read().catch(() => null) : null;
    if (lost < WRITES_LOST && now !== null && ctx.own(now) && now.epoch === prev.epoch && JSON.stringify(now.finding) === JSON.stringify(finding)) {
      stored = now;
      continue;
    }
    const why = written === false ? 'the audit anchor changed while the loss was accepted' : `the audit anchor could not be written: ${written.message}`;
    await ctx.log.append('audit.loss_unapplied', { accepted, from, to, reason: why }).catch((error: Error) => ctx.warn({ err: error.message }, 'an acceptance not applied could not be logged'));
    throw new Error(`${why}, and the acceptance was not applied: look at the anchor's finding again, and accept again if it still stands`);
  }
  ctx.alert(`an Owner accepted the loss of audit entries ${from} to ${to}: ${finding.reason} (entry ${finding.seq}). The anchor goes on past them.`);
  return { resumes: resumes?.seq ?? null };
}

/**
 * Where the walk goes on past a lost range: the entry after it, checked
 * alone, its hash, MAC and number, its link taken as given; with none,
 * the entry before the range, as the log holds it; or the start.
 */
async function pastRange(ctx: WatchContext, from: number, to: number): Promise<LogHead | null> {
  const after = await ctx.log.check(to + 1, 'own');
  if (after !== null) {
    if (!after.ok) throw new Refusal(`entry ${to + 1}, after the range, does not verify: ${after.reason}`);
    return { seq: to + 1, hash: after.hash };
  }
  if (from === 0) return null;
  const hash = await ctx.log.hashAt(from - 1);
  if (hash === null) throw new Refusal(`entry ${from - 1}, before the range, is not in the log either: accept a range that starts at the first entry missing`);
  return { seq: from - 1, hash };
}
