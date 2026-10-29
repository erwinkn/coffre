import type { StoredEntry } from '@coffre/core/audit';
import type { ChainMark, CutoverInput, CutoverOutcome, Vault } from '@coffre/core/vault';
import type { Database, Queryable } from '@coffre/db';

import { hashToken } from '@coffre/core/identity';

import { keeps015 } from './api/changes.ts';
import type { ResolvedConfig } from './config.ts';
import { appVerifier, verifyAppEntries, walkChain, type AppKeys } from './db/audit.ts';
import { appEntries, liveBindings, liveCredentials } from './db/cutover.ts';
import { logged } from './logged.ts';

/**
 * The app's half of 0.15's cutover from 0.14 (docs/design/0.15-plan.md,
 * PR 9; formal/Migration015.tla's VerifyRows and VouchedHeld for the app's
 * rows): what 0.14 accepts that only the app's key says, which the vault,
 * holding no such key, cannot check. Once a configuration knows the log is
 * cut over, nothing; until then, each request's door asks the vault, and
 * if it is not, vouches, under the app's key, for:
 * - 0.14's chain from the newest checkpoint the vault verifies from, every
 *   app entry by its MAC (`walkChain`), to the head as read;
 * - each credential 0.14 accepts: its row's MAC the app's, live, its sign-in
 *   account not unlinked, and no authentic revoke of it (`token.revoke`,
 *   `sign_out`), so that a row put back over a revoke is not vouched for;
 * - each trust binding 0.14 accepts: its MAC, live, no `token.unbind`;
 * - each place 0.14's chain deleted, by an authentic `project.delete` or
 *   `environment.delete`, with the tombstone it gave.
 * The vault holds every row to what was vouched for under its locks, and
 * answers `moved` when 0.14 wrote since: then the app reads again.
 */

/** What the cutover asks of a runtime: its database, its vault, its keys, and what its configuration knows. */
export type CutoverRuntime = {
  db: Database;
  vault: Vault;
  chainKey: Buffer;
  previousChainKeys: readonly Buffer[];
  publicUrl: string;
  /** How people sign in: a browser session is vouched for only while its provider is configured. */
  auth: ResolvedConfig['auth'];
  cutover?: CutoverKnown;
};

/**
 * What a runtime knows of the cutover, for as long as its configuration
 * lives: done, or held, with why not, until a time. Settled values only, as
 * an isolate keeps (AGENTS.md).
 */
export type CutoverKnown = { done: boolean; held?: { why: string; until: number } };

/** Times the app vouches again for what a 0.14 write moved meanwhile, before it leaves it to the next request. */
const TRIES = 3;

/**
 * How long a try holds the door, and a refusal after it: one try at a time
 * in an isolate, and at most one each hold, however many requests come
 * (review, Fable). The answer's `retry-after` is the same.
 */
export const HOLD_MS = 5_000;

/** Why the door is shut while this isolate's try runs. */
export const CUTTING_OVER_NOW = 'another request is cutting over';

/** Why the door is held now, if it is. */
const heldOf = (known: CutoverKnown): string | null => (known.held !== undefined && Date.now() < known.held.until ? known.held.why : null);

/**
 * Null once the log is cut over, or kept by 0.14 alone; otherwise why not,
 * as the door answers it. Each request asks the vault, cheaply, until it is
 * done; once a cutover is due, one request tries it and waits for it, and
 * the others meanwhile answer from the hold, as they do from a refusal or a
 * failure until it lapses.
 */
export async function cutoverReady(runtime: CutoverRuntime): Promise<string | null> {
  const known = runtime.cutover;
  if (known === undefined || known.done) return null;
  const held = heldOf(known);
  if (held !== null) return held;
  let mine: CutoverKnown['held'];
  try {
    const asked = await due(runtime.vault);
    if (asked === null) return finish(known);
    // A request since the first await may have begun a try, or been refused.
    const since = heldOf(known);
    if (since !== null) return since;
    mine = { why: CUTTING_OVER_NOW, until: Date.now() + HOLD_MS };
    known.held = mine;
    const why = await cutOver(runtime, asked);
    return why === null || known.done ? finish(known) : hold(known, mine, why);
  } catch (error) {
    // A failure (a lock that timed out, a database gone) holds the door as a refusal does, and is said here in full.
    console.error("0.15's log could not be cut over from 0.14", logged(error));
    return known.done ? null : hold(known, mine, `the cutover failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** Done, for good: no answer of an older try, come late, takes it back (review r8). */
function finish(known: CutoverKnown): null {
  known.done = true;
  known.held = undefined;
  return null;
}

/** A try's refusal, held, unless another try holds the door since this one's hold lapsed (review r8). */
function hold(known: CutoverKnown, mine: CutoverKnown['held'], why: string): string {
  if (known.held === mine || heldOf(known) === null) known.held = { why, until: Date.now() + HOLD_MS };
  return why;
}

/** The vault's first answer, if a cutover is due: none while 0.14 keeps the log alone, or once it is cut over. */
async function due(vault: Vault): Promise<CutoverOutcome | null> {
  if (vault.cutover === undefined || !(await keeps015(vault))) return null;
  const asked = await vault.cutover();
  return asked.ok && asked.done ? null : asked;
}

async function cutOver(runtime: CutoverRuntime, first: CutoverOutcome): Promise<string | null> {
  const { vault } = runtime;
  for (let tries = 0; tries < TRIES; tries += 1) {
    const asked = tries === 0 ? first : await vault.cutover!();
    if (asked.ok && asked.done) break;
    if (!asked.ok) return asked.why;
    const input = await vouched(runtime.db, runtime, asked.from, runtime.publicUrl, issuersOf(runtime.auth));
    if (typeof input === 'string') return input;
    const outcome = await vault.cutover!(input);
    if (outcome.ok) break;
    if (outcome.refused !== 'moved') return outcome.why;
    if (tries === TRIES - 1) return `0.14's log kept moving while the app vouched for its rows (${outcome.why}): a request tries again once the hold lapses`;
  }
  return null;
}

/**
 * What the app vouches for, from `from` on, or why it does not: a fault of
 * 0.14's chain under the app's key. A binding of 0.14's, which names no
 * instance, as made on `publicUrl` (T160): the audience its runs' tokens
 * name, and a workload's unless its policy names another.
 */
export async function vouched(db: Queryable, keys: AppKeys, from: ChainMark, publicUrl: string, issuers: ReadonlyMap<string, string>): Promise<CutoverInput | string> {
  const walked = await walkChain(db, keys, { seq: BigInt(from.seq), hash: Buffer.from(from.hash, 'hex') }, { limit: Infinity });
  if (!walked.ok) return `0.14's chain does not verify under the app's key at entry ${walked.failedAtSeq}: ${walked.reason}`;
  const verifier = await appVerifier(db, keys);
  const authentic = (entry: StoredEntry) => verifyAppEntries([entry], { startSeq: entry.seq, startPrevHash: entry.prevHash }, verifier).ok;
  // Each entry of the app's that ends or deletes something, by its MAC: one that fails is damaged history, which refuses
  // the cutover, never taken for no end (a credential 0.14 holds revoked would be vouched for: review r4).
  const lifecycle = await appEntries(db, ['project.delete', 'environment.delete', 'token.revoke', 'sign_out', 'account.unlink']);
  const damaged = lifecycle.find((entry) => !authentic(entry));
  if (damaged !== undefined) return `0.14's ${damaged.action} at entry ${damaged.seq} does not carry the app's MAC: its history is damaged`;
  const deleted: CutoverInput['deleted'] = [];
  for (const entry of lifecycle.filter((each) => each.action === 'project.delete' || each.action === 'environment.delete')) {
    const { tombstone } = JSON.parse(entry.metadata) as { tombstone?: unknown };
    const id = entry.action === 'project.delete' ? entry.projectId : entry.environmentId;
    if (typeof tombstone === 'string' && id !== null) deleted.push({ kind: entry.action === 'project.delete' ? 'project' : 'environment', id, tombstone });
  }
  // What the log says ended, each by its authentic entry, whatever the rows say now (a row put back over it, MAC and
  // all, is one 0.14's own check takes): a credential revoked or signed out, a sign-in account unlinked with its sessions.
  const ended = lifecycle.filter((entry) => entry.action === 'token.revoke' || entry.action === 'sign_out' || entry.action === 'account.unlink')
    .map((entry) => ({ action: entry.action, ...(JSON.parse(entry.metadata) as { targetCredentialId?: unknown; identityId?: unknown }) }));
  const revoked = new Set(ended.filter((entry) => entry.action !== 'account.unlink').map((entry) => entry.targetCredentialId));
  const unlinked = new Set(ended.filter((entry) => entry.action === 'account.unlink').map((entry) => entry.identityId));
  return {
    checked: { from, to: { seq: walked.at.seq.toString(), hash: walked.at.hash.toString('hex') } },
    credentials: (await liveCredentials(db, keys.chainKey, issuers)).filter(({ columns, identityId }) => !revoked.has(columns.id) && (identityId === null || !unlinked.has(identityId))).map(({ columns }) => columns),
    bindings: await liveBindings(db, keys.chainKey, publicUrl),
    deleted,
  };
}

/** Each sign-in provider the deployment configures, by its id, the hash of its issuer, as a browser session's account holds it (`#issuerHash`). */
export function issuersOf(auth: ResolvedConfig['auth']): Map<string, string> {
  if (auth.mode !== 'signin') return new Map();
  return new Map(auth.signin.providers.map((provider) => [provider.id, hashToken(provider.issuer).toString('hex')]));
}
