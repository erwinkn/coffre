import { payloadOf } from './changes.ts';
import { canonical, logObject, refOf, type LogKeyInput, type SettingsInput } from './inputs.ts';

/**
 * The changes the vault's upgrade step writes, once, on its first call after 0.16's migration. This file pins what each
 * change is, for the step and for each reader of them (the audit projector, the audit page's check, the app). In order:
 *
 *   1. the anchor: the old chain's final seq and hash, which `audit_log` answers to from then on
 *        request 'upgrade-0.16:anchor', object log_object('log', 'anchor'), no seal
 *   2. the settings' first change: their row as the migration filled it, sealed
 *        request 'upgrade-0.16:settings', object log_object('settings', 'instance'), the row's seal
 *   3. each key's first change, in key id order: its row, sealed
 *        request 'upgrade-0.16:log-key:app:3f0c9a1e5b7d2468', object log_object('log-key', 'app:3f0c…'), the row's seal
 *   4. 'upgrade done', after the cursor is signed at the anchor: the door opens on it
 *        request 'upgrade-0.16:done', object log_object('log', 'upgrade-0.16'), no seal
 *
 * Each request id is made from what the change is about, never drawn, so a step that dies halfway is rerun and finds
 * what is done (`log_changes.request_id` is unique): 2 and 3 are compare-and-sets on the row's null seal, as
 * `change_input`'s genesis is. The actor is the vault's own. Anchor and done are the log's own changes, of no object
 * a decision reads, as a cutover's and a rotation's are: they belong with the replay's `LOGS_OWN` once the step
 * writes them.
 *
 * The audit page lists none of the four (the projector answers no event for each, `audit_events` has no row of them):
 * each restates what the frozen log already lists, as its own row (log 14), the settings' newest `settings.change` and
 * each key's `key.rotate`, and the anchor and the done marker are the log's bookkeeping, as a cutover's change is.
 * The changes after them are listed: `settings.change` and `log-key.add` (inputs.ts) as today's entries were.
 */

/** The release this upgrade brings a 0.15.0 database to, in each request id and in the done marker. */
export const UPGRADE_RELEASE = '0.16';

/** Who writes the step's changes. */
export const UPGRADE_ACTOR = 'system:vault';

/** The anchor's object, one ever: the change that names the old chain's final entry. */
export const ANCHOR_OBJECT = logObject('log', 'anchor');

/** The done marker's object, one per upgrade: `log_object('log', 'upgrade-0.16')`. */
export const UPGRADE_OBJECT = logObject('log', `upgrade-${UPGRADE_RELEASE}`);

/** The step's request ids: `upgrade-0.16:<what it is about>`. */
export const UPGRADE_REQUESTS = {
  anchor: `upgrade-${UPGRADE_RELEASE}:anchor`,
  settings: `upgrade-${UPGRADE_RELEASE}:settings`,
  done: `upgrade-${UPGRADE_RELEASE}:done`,
  /** A key's: `upgrade-0.16:log-key:<key id>`. */
  key: (keyId: string) => `upgrade-${UPGRADE_RELEASE}:log-key:${keyId}`,
} as const;

/** A position in the old chain: an entry's seq and its hash (`entryHash`), as the anchor names it. */
export type OldPosition = { seq: bigint; hash: Buffer };

/**
 * Where the checkpoint the step started from was held: `outside`, the watch's store, which
 * the app reads at the door and hands in, and the vault verifies (its own signature, and the log holding that entry at
 * that hash); `log`, the newest checkpoint entry `audit_log` itself holds, when the store is empty or absent. With
 * `log`, nothing outside the database bounded a cut of the old chain's tail before the anchor.
 */
export type AnchorHeld = 'outside' | 'log';

/**
 * The anchor's payload: the old chain's final entry (`anchor`), the newest checkpoint the step checked the tail from
 * (`from`), each its seq in decimal and its hash in hex, as the cutover's names its own, and where that checkpoint was
 * held (`held`). Canonical JSON.
 *
 *   {"anchor":{"hash":"<64 hex>","seq":"440213"},"from":{"hash":"<64 hex>","seq":"440190"},"held":"outside","op":"upgrade.anchor"}
 */
export type AnchorPayload = {
  op: 'upgrade.anchor';
  anchor: { seq: string; hash: string };
  from: { seq: string; hash: string };
  held: AnchorHeld;
};

export function anchorPayload(anchor: OldPosition, from: OldPosition, held: AnchorHeld): string {
  const at = (p: OldPosition) => ({ seq: p.seq.toString(), hash: p.hash.toString('hex') });
  const payload: AnchorPayload = { op: 'upgrade.anchor', anchor: at(anchor), from: at(from), held };
  return canonical(payload);
}

/**
 * The anchor's payload read back, for `check`, which holds the frozen log's last row to `anchor`: its seq and
 * its hash. A parse, not a proof: `check` trusts what it returns only from a row whose MAC holds (`changeHolds`), and
 * answers `broken` for one whose MAC does not, as for a payload that is not exactly an anchor's (null here:
 * `anchorPayload` of what it parses differs). The step writes no anchor on a database whose `audit_log` is empty, one
 * born on 0.16. So, of the four cases: no anchor and no old row is nothing to hold; no anchor and an old row is
 * `broken`; an anchor and no old row is `broken` (the frozen log cut to nothing); an anchor and an old row holds when
 * the last row's seq is the anchor's and its hash, recomputed, is too.
 */
export function parseAnchor(payload: string): { anchor: OldPosition; from: OldPosition; held: AnchorHeld } | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch {
    return null;
  }
  const position = (p: unknown): OldPosition | null => {
    const { seq, hash } = (p ?? {}) as { seq?: unknown; hash?: unknown };
    if (typeof seq !== 'string' || !/^(0|[1-9][0-9]*)$/.test(seq) || typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) return null;
    return { seq: BigInt(seq), hash: Buffer.from(hash, 'hex') };
  };
  const { anchor: a, from: f, held } = (parsed ?? {}) as { anchor?: unknown; from?: unknown; held?: unknown };
  const anchor = position(a);
  const from = position(f);
  if (anchor === null || from === null || (held !== 'outside' && held !== 'log')) return null;
  if (anchorPayload(anchor, from, held) !== payload) return null;
  return { anchor, from, held };
}

/**
 * The first change of the settings or of a key: a genesis of the object the row holds (`settingsObject`,
 * `logKeyObject`), as the cutover's are (`genesisCall`), citing the old entry it came from as `old`, its seq in
 * decimal: the newest allowed `settings.change` of the vault's, or the key's `key.rotate`; none for settings no one
 * changed (the default) and for a key no rotation names. The change's seal is the vault's over the object.
 *
 *   {"op":"genesis","old":"1207","ref":{"id":"instance","kind":"settings"},"value":{"kind":"settings",…}}
 */
export function firstChangePayload(object: SettingsInput | LogKeyInput, old: bigint | null): string {
  return payloadOf(refOf(object), { op: 'genesis', value: object }, old ?? undefined);
}

/** The done marker's payload: which upgrade it ends. Canonical JSON: `{"op":"upgrade.done","release":"0.16"}`. */
export type DonePayload = { op: 'upgrade.done'; release: typeof UPGRADE_RELEASE };

export function donePayload(): string {
  const payload: DonePayload = { op: 'upgrade.done', release: UPGRADE_RELEASE };
  return canonical(payload);
}
