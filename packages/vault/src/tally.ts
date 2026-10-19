import { createHash } from 'node:crypto';

import type { StoredEntry } from '@coffre/core/audit';
import type { AccessFault, Checkpoint, LogHead } from '@coffre/core/vault';

import { KeyAccounting, type AccountingState } from './accounting.ts';
import { forward } from './log.ts';
import { apply, placeKey, type LoggedMember, type Replayed } from './replay.ts';
import { ACCESS_ACTIONS, type GrantRow } from './store.ts';

/**
 * What a walk of the vault's entries from the first has gathered by some
 * entry: all a walk from there needs to go on as if it had started at the
 * first. A checkpoint keeps the tally of the prefix it signs, so that the
 * next checkpoint, and every verification, start from it and read only the
 * entries since (docs/architecture.md, "The tally").
 *
 * - `entries`: the vault's entries so far;
 * - `keys`: the vault's log keys, in the order its entries moved through
 *   them, which only moves forward (`forward` in log.ts);
 * - `accounting`: the key batches still under way, and the first fault in
 *   their entries;
 * - `access`: who the log says is a member, what each holds, and each one's
 *   newest access entry, which their row must name;
 * - `replayFault`: the first access entry about someone never admitted.
 *
 * The faults are kept, once found, as a walk from the first entry would
 * find them again each time.
 */
export type Tally = {
  entries: number;
  keys: string[];
  accounting: AccountingState;
  access: AccessTally;
  replayFault: AccessFault | null;
};

/** Members and grants as the log says they are, and each member's newest access entry, as plain JSON. */
export type AccessTally = {
  members: (Omit<LoggedMember, 'accessSeq'> & { accessSeq: number })[];
  grants: GrantRow[];
  newest: [principal: string, seq: number][];
};

/**
 * A tally as a checkpoint's entry holds it. Members and grants change far
 * less often than every five minutes, so `access` is written whole only
 * when it changed since the tally resumed from; otherwise the entry names
 * the checkpoint entry that holds it (`at`). Either way with its digest.
 */
export type StoredTally = Omit<Tally, 'access'> & { access: { digest: string } & ({ at: number } | AccessTally) };

/** A checkpoint as the vault's entry holds it: the signed prefix, its tally, and where the next one's rehash of the past goes on (`scrub`), null for the first entry. */
export type TalliedCheckpoint = Checkpoint & { tally: StoredTally; scrub: LogHead | null };

/** Before the first entry. */
export const EMPTY_TALLY: Tally = {
  entries: 0,
  keys: [],
  accounting: { intents: [], fault: null },
  access: { members: [], grants: [], newest: [] },
  replayFault: null,
};

/** The digest of what `access` says, over its canonical form. */
export function accessDigest(access: AccessTally): string {
  return createHash('sha256').update(canonical(access)).digest('hex');
}

/**
 * Whether two tallies say the same, whatever order their maps were built
 * in. A fault is the same where it was found: the words for it may change
 * from one release to the next.
 */
export function sameTally(a: Tally, b: Tally): boolean {
  return tallyKey(a, accessDigest(a.access)) === tallyKey(b, accessDigest(b.access));
}

/** What `sameTally` compares: the members and grants by their digest, which a stretch passing many checkpoints computes once a change. */
function tallyKey({ accounting, entries, keys, replayFault }: Omit<Tally, 'access'>, digest: string): string {
  return canonical({ entries, keys, replayFault, accounting: { ...accounting, fault: accounting.fault?.failedAtSeq ?? null }, access: digest });
}

/**
 * A tally a walk must come to: the one a checkpoint keeps, `entry`, of the
 * prefix through `through`; or why that checkpoint's tally cannot be read.
 */
export type Expected = { entry: bigint; through: bigint; tally: Tally; digest: string } | { entry: bigint; through: bigint; unreadable: string };

/**
 * The vault's entries walked, oldest first, each after its MAC was checked,
 * gathered into what the checks after the walk need: the tally it started
 * from, carried on.
 */
export class Walk {
  readonly accounting: KeyAccounting;
  readonly replayed: Replayed;
  /** Each member's newest allowed access entry, by seq. */
  readonly newestAccess: Map<string, bigint>;
  /** The first access entry the replay could not apply. */
  replayFault: AccessFault | null;
  /** The vault's entries so far, those before the walk included. */
  entries: number;
  /** The vault's log keys, as the log moved through them. */
  keys: readonly string[];
  /** The checkpoints walked, each to be checked against its signature and the prefix it signed once the walk ends. */
  readonly checkpoints: { entry: { seq: bigint; keyId: string; relatedSeq: bigint | null }; checkpoint: Checkpoint }[] = [];

  /** The tallies the walk must come to as it passes them, oldest first (`expect`). */
  #expected: Expected[] = [];
  /** The first it did not come to, and why. */
  mismatch: { entry: bigint; reason: string } | null = null;
  /** The digest of the members and grants as the walk has them, until an access entry changes them. */
  #digest: string | null = null;

  #accessDigest(): string {
    return (this.#digest ??= accessDigest(this.tally().access));
  }

  /** The tally but for its members and grants, which `#accessDigest` stands for. */
  #unaccessed(): Omit<Tally, 'access'> {
    return { entries: this.entries, keys: [...this.keys], accounting: this.accounting.state(), replayFault: this.replayFault };
  }

  constructor(from: Tally) {
    this.accounting = new KeyAccounting(from.accounting);
    this.replayed = {
      members: new Map(from.access.members.map((member) => [member.principal, { ...member, accessSeq: BigInt(member.accessSeq) }])),
      held: new Map(),
    };
    for (const grant of from.access.grants) {
      const held = this.replayed.held.get(grant.principal) ?? new Map<string, GrantRow>();
      this.replayed.held.set(grant.principal, held);
      held.set(placeKey(grant), { ...grant });
    }
    this.newestAccess = new Map(from.access.newest.map(([principal, seq]) => [principal, BigInt(seq)]));
    this.replayFault = from.replayFault;
    this.entries = from.entries;
    this.keys = from.keys;
  }

  /**
   * Hold the walk to these tallies, each as the walk stands once it has
   * read every entry through the prefix's end: before the vault's next
   * entry, since only the vault's change a tally, or at `finish`.
   */
  expect(expected: readonly Expected[]): void {
    this.#expected = [...expected].sort((a, b) => (a.through < b.through ? -1 : 1));
  }

  /** The tallies expected through `through`, held to the walk. */
  finish(through: bigint): void {
    this.#reach(through + 1n);
  }

  #reach(before: bigint): void {
    while (this.#expected.length > 0 && this.#expected[0]!.through < before) {
      const expected = this.#expected.shift()!;
      if (this.mismatch !== null) continue;
      if ('unreadable' in expected) this.mismatch = { entry: expected.entry, reason: expected.unreadable };
      else if (tallyKey(this.#unaccessed(), this.#accessDigest()) !== tallyKey(expected.tally, expected.digest)) {
        this.mismatch = { entry: expected.entry, reason: 'the tally this checkpoint keeps does not follow from the log before it' };
      }
    }
  }

  /**
   * One of the vault's entries, its MAC checked, in the log's order: a
   * fault when it is under a key the vault had moved past (`forward`).
   */
  add(entry: StoredEntry, current: string): { failedAtSeq: bigint; reason: string } | null {
    this.#reach(entry.seq);
    const moved = forward([entry], this.keys, current);
    if ('failedAtSeq' in moved) return moved;
    this.keys = moved.keys;
    this.entries += 1;
    this.accounting.add(entry);
    if (entry.decision !== 'allow') return null;
    if (ACCESS.has(entry.action)) {
      this.#digest = null;
      this.replayFault ??= apply(this.replayed, entry);
      if (entry.subjectPrincipal !== null) this.newestAccess.set(entry.subjectPrincipal, entry.seq);
    } else if (entry.action === CHECKPOINT) {
      this.checkpoints.push({ entry: { seq: entry.seq, keyId: entry.keyId, relatedSeq: entry.relatedSeq }, checkpoint: JSON.parse(entry.metadata) as Checkpoint });
    }
    return null;
  }

  /** Where the walk stands, to resume from. */
  tally(): Tally {
    const byPrincipal = <T>(entries: Iterable<[string, T]>) => [...entries].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return {
      entries: this.entries,
      keys: [...this.keys],
      accounting: this.accounting.state(),
      access: {
        members: byPrincipal(this.replayed.members).map(([, member]) => ({ ...member, accessSeq: Number(member.accessSeq) })),
        grants: byPrincipal(this.replayed.held).flatMap(([, held]) => byPrincipal(held).map(([, grant]) => grant)),
        newest: byPrincipal(this.newestAccess).map(([principal, seq]) => [principal, Number(seq)]),
      },
      replayFault: this.replayFault,
    };
  }
}

/** The action of the vault's entry that signs a prefix of the log. */
export const CHECKPOINT = 'audit.checkpoint';

const ACCESS = new Set<string>(ACCESS_ACTIONS);

/** JSON with every object's keys sorted: one text for one value, however it was built. */
function canonical(value: unknown): string {
  return JSON.stringify(value, (_, inner: unknown) =>
    inner !== null && typeof inner === 'object' && !Array.isArray(inner)
      ? Object.fromEntries(Object.entries(inner).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : inner);
}
