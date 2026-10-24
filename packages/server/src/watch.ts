// What a plugin that watches the audit log reaches (docs/design/plugins.md,
// "Watching the log"): capabilities, never a database or a vault client.
// It walks the chain as core walks it, and reads one entry's hash or one
// entry checked alone; asks the vault to sign the log, and for the keys its
// signatures verify under; appends entries of its own kinds; raises an
// alert; and MACs and checks a record of its own under a key core derives.
// Core's chain key and the vault's keys stay core's.
//
// Only coffre's own plugins carry a `Watcher`: core takes one only if
// coffre's own code made it (`watcher`), whatever a plugin object says, so
// a third-party plugin keeps routes and the API as a caller (R9).
import { verifyEntries } from '@coffre/core/audit';
import type { Checkpoint, CheckpointKey, LogHead, Outcome, Vault } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { SNAPSHOT } from '@coffre/db/dialect';

import { anchorIsOwn, anchorKeyId, sealAnchor, type AnchorFields, type AnchorStore, type AuditAnchor } from './anchor.ts';
import { appendAudit, appLogKey, CHAIN_START, walkChain, type AuditEntry } from './db/audit.ts';
import { auditHashAt, auditRange } from './db/queries.ts';

/** The key a watcher's hooks hang from on its plugin. */
export const WATCH: unique symbol = Symbol('coffre.watch');

/** The entries a watcher may append, each the system's or, for an Owner's action, theirs. */
export type WatchAction = 'audit.heartbeat' | 'audit.finding' | 'audit.finding_cleared' | 'audit.reanchor' | 'audit.loss_accepted' | 'audit.loss_unapplied';

/** Who an entry a watcher appends is in the name of: the scheduler's, or the Owner whose request it answers. */
export type WatchActor = Pick<AuditEntry, 'actorType' | 'actorId' | 'requestId' | 'sourceIp'>;

export type WatchContext = {
  log: {
    /**
     * In one read-only snapshot: each of `held` still at its hash, then the
     * chain walked from `from` (null: before the first entry) toward entry
     * `to`, at most `CHAIN_WALK` entries, every link and hash and the app's
     * MACs (`walkChain`). Where it got to and whether that is `to`; or the
     * first fault, `held` ones first, the held point's seq for one.
     */
    walk(input: { held: readonly LogHead[]; from: LogHead | null; to: number }): Promise<
      { ok: true; at: LogHead | null; done: boolean } | { ok: false; failedAtSeq: number; reason: string }
    >;
    /** Entry `seq`'s hash, hex, or null for none. */
    hashAt(seq: number): Promise<string | null>;
    /**
     * Entry `seq` checked alone: its hash, number and the app's MAC if it is
     * the app's, linked to the entry before as the log holds it
     * (`link: 'log'`) or to the hash it names (`'own'`). Null for none.
     */
    check(seq: number, link: 'log' | 'own'): Promise<{ ok: boolean; hash: string; reason?: string } | null>;
    /** One entry of the watcher's, in a transaction of its own: its seq. */
    append(action: WatchAction, metadata: Record<string, unknown>): Promise<number>;
  };
  vault: {
    /** The vault's checkpoint of the log, asked once a scheduled run however many ask. */
    checkpoint(): Promise<Outcome<{ checkpoint: Checkpoint; warning?: string }>>;
    /** The keys checkpoints verify under, asked each time: a rotation changes them. */
    checkpointKeys(): Promise<Record<string, CheckpointKey>>;
  };
  /** The deployment's alert channel, a workload's alerts' (alerts.ts, `auditAlerter`). */
  alert(text: string): void;
  /** The process's log. */
  warn(obj: unknown, msg: string): void;
  /**
   * A record of the watcher's, MACed under a key core derives from
   * `auditChainKey` and named by that key's id, `keyId`; and whether one is.
   */
  seal(fields: AnchorFields): AuditAnchor;
  own(anchor: AuditAnchor): boolean;
  keyId: string;
};

/** What a watcher does, beside its plugin's routes. Each hook gets its own context, and its own store. */
export type Watcher = {
  /** Its part of the scheduled run, before core asks the vault to checkpoint: false fails the run. */
  scheduled(ctx: WatchContext): Promise<boolean>;
  /** What `/readyz` says of it: `ok` joins the answer's, and the rest is shown beside it. */
  readiness(ctx: WatchContext): Promise<{ ok: boolean } & Record<string, unknown>>;
  /**
   * Where the app last verified the log through, for the audit page's check
   * to start from: null, the start; undefined, nowhere it vouches for, and
   * the check starts from the newest checkpoint, as without a watch.
   */
  verified(ctx: WatchContext): Promise<LogHead | null | undefined>;
  /**
   * More of a backlog walked, between scheduled runs, over `store` when
   * given (a Durable Object's own storage, in its alarm): whether there is
   * more to walk.
   */
  walkOn(ctx: WatchContext, store?: AnchorStore): Promise<boolean>;
  /** An Owner's acceptance of lost entries, `actor`'s, in their request's context. A refusal throws a `Refusal`. */
  acceptLoss(ctx: WatchContext, range: { from: number; to: number }): Promise<{ resumes: number | null }>;
};

/** What a watcher refuses a request for, which the API answers 400 with: never anything else it throws. */
export class Refusal extends Error {}

const made = new WeakSet<Watcher>();

/** A watcher coffre's own plugin makes: the only kind `watcherOf` returns. */
export function watcher(hooks: Watcher): Watcher {
  made.add(hooks);
  return hooks;
}

/** The watcher a plugin carries, if coffre made it. */
export function watcherOf(plugin: object): Watcher | undefined {
  const hooks = (plugin as { [WATCH]?: Watcher })[WATCH];
  return hooks !== undefined && made.has(hooks) ? hooks : undefined;
}

/** What a watch context is made from: a runtime's, or a test's. */
export type WatchDeps = {
  db: Database;
  chainKey: Buffer;
  vault: Pick<Vault, 'checkpoint' | 'about'>;
  alert?: (text: string) => void;
  warn?: (obj: unknown, msg: string) => void;
  /** In whose name it appends: the scheduler's unless an Owner's request says. */
  actor?: WatchActor;
};

const SCHEDULER: WatchActor = { actorType: 'system', actorId: 'coffre-scheduler' };

/** A watch context over `deps`: one per scheduled run, request or alarm. */
export function watchContext(deps: WatchDeps): WatchContext {
  const { db, chainKey, vault } = deps;
  let signed: ReturnType<Vault['checkpoint']> | undefined;
  return {
    log: {
      walk: ({ held, from, to }) =>
        db.transaction(async (tx) => {
          for (const head of held) {
            if ((await auditHashAt(tx, BigInt(head.seq))) !== head.hash) return { ok: false as const, failedAtSeq: head.seq, reason: 'changed or cut since the anchor held it' };
          }
          const start = from === null ? CHAIN_START : { seq: BigInt(from.seq), hash: Buffer.from(from.hash, 'hex') };
          const walked = await walkChain(tx, chainKey, start, { to: BigInt(to) });
          if (!walked.ok) return { ok: false as const, failedAtSeq: Number(walked.failedAtSeq), reason: walked.reason };
          const at = walked.at.seq < 0n ? null : { seq: Number(walked.at.seq), hash: walked.at.hash.toString('hex') };
          return { ok: true as const, at, done: walked.done };
        }, SNAPSHOT),
      hashAt: (seq) => auditHashAt(db, BigInt(seq)),
      check: async (seq, link) => {
        const [row] = await auditRange(db, BigInt(seq), 1);
        if (row === undefined || row.seq !== BigInt(seq)) return null;
        const before = link === 'own' ? row.prevHash.toString('hex') : seq === 0 ? CHAIN_START.hash.toString('hex') : await auditHashAt(db, BigInt(seq) - 1n);
        if (before === null) return { ok: false, hash: row.hash.toString('hex'), reason: `entry ${seq - 1}, before it, is not in the log` };
        const alone = verifyEntries([row], { startSeq: row.seq, startPrevHash: Buffer.from(before, 'hex'), keys: [appLogKey(chainKey)], chainOnly: ['vault'] });
        return alone.ok ? { ok: true, hash: row.hash.toString('hex') } : { ok: false, hash: row.hash.toString('hex'), reason: alone.reason };
      },
      append: async (action, metadata) => {
        const appended = await db.transaction((tx) => appendAudit(tx, chainKey, [{ ...(deps.actor ?? SCHEDULER), action, decision: 'allow', metadata }]));
        return Number(appended.seqStart);
      },
    },
    vault: {
      checkpoint: () => (signed ??= vault.checkpoint()),
      checkpointKeys: async () => (await vault.about()).checkpointKeys,
    },
    alert: deps.alert ?? (() => {}),
    warn: deps.warn ?? ((obj, msg) => console.warn(msg, obj)),
    seal: (fields) => sealAnchor(chainKey, fields),
    own: (anchor) => anchorIsOwn(chainKey, anchor),
    keyId: anchorKeyId(chainKey),
  };
}
