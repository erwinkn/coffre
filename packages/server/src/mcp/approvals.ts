// Approvals (docs/design/mcp.md, section 7; docs/design/0.16.md, "An MCP
// client's changes"): every change an MCP client asks for waits here until its
// person decides it on coffre's own page. The vault writes each: the client's
// ask (`mcp.ask`), a denial or a value shown (`mcp.decide`), and an Approve,
// which is the change itself, made there and then on the person's browser
// session with the connection and the approval named (`via`): the vault marks
// the approval approved in the change's own write. The client never makes the
// change itself, so it happens exactly once, whether or not the client
// returns (D36), and it hears how it ended by the approval's id, a read.
import { createHash } from 'node:crypto';

import { APPROVAL_SECONDS, MAX_ASK_ARGUMENTS, MAX_PENDING } from '@coffre/core/mcp';

import { changed } from '../api/change.ts';
import type { ApiContext } from '../api/context.ts';
import { ApiError, badRequest, conflict, forbidden, notFound, refusal } from '../api/errors.ts';
import { findApproval, pendingAsk, type ApprovalRow, type FoundApproval } from '../db/queries/approvals.ts';
import { clientOf } from '../db/queries/mcp.ts';
import type { Detail, Replaced, Viewing } from './changes.ts';
import { TOOL_BY_NAME, type Tool } from './tools.ts';

export { APPROVAL_SECONDS, MAX_PENDING };
/** How long after it was asked a client may still hear how an approval ended; and how far back its page recalls the same call approved. */
export const OUTCOME_SECONDS = 10 * 60;
/** How long a client's retry waits on its approval before answering that it still waits: well inside every client's timeout. Tests shorten it. */
export const approvalWait = { ms: 25_000 };

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'cancelled' | 'failed' | 'expired';

/** What became of a decided approval: the client's text and result. Never a value. */
export type Outcome = { text: string; result?: Record<string, unknown>; error?: string };

/** What the approval page shows. */
export type ApprovalView = {
  id: string;
  status: ApprovalStatus;
  client: { name: string; host: string | null; registration: 'cimd' | 'dcr' };
  tool: string;
  /** The change in a phrase, from its arguments: what the client said it asks for. */
  summary: string;
  /** What it would do and replace, read as the person, now; empty once decided. */
  details: Detail[];
  /** What the person types besides deciding: the value, for `request_secret_value`. */
  asks: { value: { label: string; note: string } } | null;
  /** A change, or a value shown to the person on Reveal, which never goes to the client. */
  kind: 'change' | 'reveal';
  /** Whether the app holds Reveal values, and so can read any value the person can. */
  reveals: boolean;
  /** Of the tool and its arguments, as rendered: sent back with the decision, so what runs is what was shown. */
  digest: string;
  /** A digest of what the change replaces, as shown: sent back with Approve, which refuses it if it changed since. */
  basis: string | null;
  /** Whether Approve can go ahead: not when coffre could not read what the change replaces. */
  ready: boolean;
  createdAt: string;
  expiresAt: string;
  /** Once decided: what became of it. */
  outcome: Outcome | null;
};

/** What the page shows once the person decided: the outcome, and what only it may show, once. */
export type Decision = { status: ApprovalStatus; outcome: Outcome; shown: Detail[] };

/** What the page sends back: the decision, the digest and basis it showed, and a value typed. */
export type Decide = { approve: boolean; digest: string; basis?: string | null; value?: string };

/** SHA-256 of the canonical JSON of a tool's name and arguments: what a call, and its approval, are. The vault draws the same from `[tool, canonical(args)]`. */
export function callDigest(tool: string, args: unknown): string {
  return createHash('sha256').update(canonical([tool, args])).digest('hex');
}

/** SHA-256 of the canonical JSON of what a change replaces: the page's basis, as long as any other, however much it shows. */
function basisOf(replaced: Replaced): string {
  return createHash('sha256').update(canonical(replaced.state)).digest('hex');
}

/** JSON with every object's keys sorted, so that equal arguments digest equal. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value === 'object' && value !== null) {
    return `{${Object.keys(value)
      .sort()
      .filter((key) => (value as Record<string, unknown>)[key] !== undefined)
      .map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

/** Where an approval stands at `now`: pending past its expiry, it expired. */
export function statusOf(row: ApprovalRow): ApprovalStatus {
  return row.status === 'pending' && row.expiresAt <= row.now ? 'expired' : row.status;
}

/**
 * What became of an approval, from its status alone: the vault writes an
 * approval approved with its change, so approved is made. Null while it waits.
 */
export function outcomeOf(row: ApprovalRow, tool: Tool): Outcome | null {
  const status = statusOf(row);
  if (status === 'pending') return null;
  if (status === 'approved') return tool.change!.done(JSON.parse(row.arguments) as never, row.decidedAt ?? row.now);
  if (status === 'denied') return { text: 'The person denied this on coffre: nothing changed.' };
  return { text: `This approval ${status === 'expired' ? 'expired before the person decided it' : `is ${status}`}: nothing changed.` };
}

/** Where the person decides an approval. */
export const approvalUrl = (publicUrl: string, id: string) => `${publicUrl}/approvals/${id}`;

// --- for /mcp -------------------------------------------------------------------

/** An approval's id, as a call names it: nothing else is read. */
const UUID = /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;

/**
 * A call's arguments as its approval keeps them, canonical JSON, or the 400
 * that says they are too long for one, which the vault would take as a
 * fault: checked before anything is read or asked.
 */
export function askable(args: Record<string, unknown>): string {
  const text = canonical(args);
  if (text.length > MAX_ASK_ARGUMENTS) throw badRequest(`this call's arguments are too long to ask for an approval: ${MAX_ASK_ARGUMENTS} characters as JSON at most, so name fewer places or claims at once`);
  return text;
}

/**
 * The approval for a call that names none, the vault's (`mcp.ask`): a new
 * one, or the one the same call waits on (`joined`); none (`full`) past
 * `MAX_PENDING` waiting.
 */
export async function ask(ctx: ApiContext, connection: string, tool: Tool, args: Record<string, unknown>): Promise<{ id: string; expiresAt: Date; joined: boolean } | { full: true }> {
  const asked = askable(args);
  for (let attempt = 0; ; attempt += 1) {
    const answer = await ctx.vault.change<'mcp.ask'>({ ...ctx.shown, op: 'mcp.ask', tool: tool.name, arguments: asked, place: tool.change!.place(args as never) });
    if (!('refused' in answer)) return { id: answer.answer.approval, expiresAt: new Date(answer.answer.expiresAt), joined: false };
    if (answer.refused === 'full') return { full: true };
    if (answer.refused !== 'pending') throw refusal(answer.refused, tool.name);
    const joined = await pendingAsk(ctx.db, connection, callDigest(tool.name, args));
    if (joined !== null) return { ...joined, joined: true };
    // Decided or expired since the vault read it: asked again, once.
    if (attempt > 0) throw new ApiError('unavailable', 'the same change was asked at the same moment: try again');
  }
}

/**
 * The approval a call names by its id (`requestState`, or its `approval`
 * argument): this connection's, read with its digest. One that is unknown
 * or another connection's is `unknown`, alike; one of this connection's for
 * other arguments is `other_call`. A read: as often as the client likes.
 */
export async function named(ctx: ApiContext, connection: string, id: string, tool: Tool, args: unknown): Promise<FoundApproval | 'unknown' | 'other_call'> {
  const row = UUID.test(id) ? await findApproval(ctx.db, id, OUTCOME_SECONDS) : null;
  if (row === null || row.connectionId !== connection) return 'unknown';
  return row.digest === callDigest(tool.name, args) ? row : 'other_call';
}

/** The approval once it no longer waits for the person, or as it is at `until`: read again every second, in plain queries, holding nothing. */
export async function settle(ctx: ApiContext, row: FoundApproval, until: number): Promise<FoundApproval> {
  while (statusOf(row) === 'pending' && Date.now() + 1000 <= until) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    row = (await findApproval(ctx.db, row.id, OUTCOME_SECONDS))!;
  }
  return row;
}

// --- for coffre's page ----------------------------------------------------------

/** The client a connection's row names, as the page shows it, and the scopes it holds. */
function clientShown(connection: NonNullable<FoundApproval['connection']>) {
  const client = clientOf(connection.client);
  return { name: connection.label ?? 'Unnamed app', host: client?.host ?? null, registration: client?.registration ?? 'cimd', scopes: client?.scopes ?? [] };
}

/** "2 minutes ago", from the database's clock. */
function ago(at: Date, now: Date): string {
  const minutes = Math.floor((now.getTime() - at.getTime()) / 60_000);
  return minutes < 1 ? 'less than a minute ago' : `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
}

/** What the page shows: only to the approval's own person, on their browser session. */
export async function viewApproval(ctx: ApiContext, id: string): Promise<ApprovalView> {
  const { row, tool, client } = await mine(ctx, id);
  const status = statusOf(row);
  const args = JSON.parse(row.arguments) as never;
  const change = tool.change!;
  const viewing: Viewing = { reveals: client.scopes.includes('reveal'), transport: ctx.transport };
  let details: Detail[] = [];
  let basis: string | null = null;
  if (status === 'pending') {
    // Read once: the page shows what the change replaces, and Approve compares its basis with this one.
    // Unread, the rest of the page still shows, and nothing is approved without a basis.
    let replaced: Replaced | null = null;
    let missing: Detail[] = [];
    try {
      replaced = (await change.replaces?.(ctx, args)) ?? null;
    } catch (error) {
      missing = unread(error);
    }
    try {
      details = await change.preview(ctx, args, viewing, replaced?.details ?? missing);
      basis = replaced === null ? null : basisOf(replaced);
    } catch (error) {
      details = unread(error);
    }
    // The same call approved a moment before: a client that lost the approval's id asks again, and the person may not mean it twice.
    if (row.approvedBefore !== null) details.unshift({ label: 'Asked before', value: `You approved this same request ${ago(row.approvedBefore, row.now)}.`, warn: true });
  }
  return {
    id: row.id,
    status,
    client: { name: client.name, host: client.host, registration: client.registration },
    tool: tool.name,
    summary: change.summary(args),
    details,
    asks: change.asks?.(viewing) ?? null,
    kind: change.reveal === true ? 'reveal' : 'change',
    reveals: viewing.reveals,
    digest: row.digest,
    basis,
    ready: change.replaces === undefined || basis !== null,
    createdAt: row.createdAt.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
    outcome: outcomeOf(row, tool),
  };
}

/** What the page says when a read it makes is refused: the rest still shows. */
function unread(error: unknown): Detail[] {
  if (!(error instanceof ApiError)) throw error;
  return [{ label: 'Note', value: `coffre could not read what this replaces: ${error.message}`, warn: true }];
}

/**
 * The person's decision. `digest` and `basis` are the ones the page showed:
 * a change that is not what the person read, or one that would replace
 * something else now, is refused before the vault is asked anything, and
 * the vault holds the decision to the row's digest again.
 *
 * - Deny: `mcp.decide`, the approval written denied.
 * - Approve of a change: the change, on the person's session with the
 *   connection and the approval named (`via`): the vault writes the
 *   approval approved in the change's own write. Refused (another version
 *   set since, a binding or a grant it would end or overwrite that the
 *   page did not show, `stale`, worded as changed since they were asked;
 *   expired; disconnected), nothing is written, and the approval still
 *   waits: the page shows why, and the person reloads it. Nothing retries.
 * - Approve of a value shown: the value first, read as the person's own
 *   reveal, then `mcp.decide`. Should the second be refused (expired, or
 *   decided in another tab meanwhile), the person still sees the value,
 *   theirs to read, and the client hears the approval as it stands.
 */
export async function decide(ctx: ApiContext, id: string, input: Decide): Promise<Decision> {
  const { row, tool, client } = await mine(ctx, id);
  const change = tool.change!;
  const args = JSON.parse(row.arguments) as never;
  // Of the arguments the row holds now, too: what runs is what the page rendered, whatever was written in the row since.
  if (input.digest !== row.digest || row.digest !== callDigest(tool.name, args)) throw conflict('this change is not the one the page showed: open the approval again');
  const status = statusOf(row);
  if (status !== 'pending') throw conflict(`this approval is ${status} already`);
  if (!client.scopes.includes(tool.scope)) throw forbidden(`${client.name} no longer holds the ${tool.scope} scope`);
  const decided = (approve: boolean) => changed(ctx, { op: 'mcp.decide', approval: id, approve, digest: input.digest }, 'this approval');
  if (!input.approve) {
    await decided(false);
    return { status: 'denied', outcome: outcomeOf({ ...row, status: 'denied' }, tool)!, shown: [] };
  }
  if (change.asks !== undefined && (input.value === undefined || input.value === '')) throw badRequest('type the value to set first');

  if (change.reveal === true) {
    const { shown = [] } = await change.apply(ctx, args, {});
    try {
      await decided(true);
    } catch (error) {
      if (!(error instanceof ApiError)) throw error;
      const now = await findApproval(ctx.db, id, OUTCOME_SECONDS);
      return { status: now === null ? 'expired' : statusOf(now), outcome: { text: `Shown to you, but coffre could not record the approval (${error.message}): the app is not told it was shown.`, error: error.code }, shown };
    }
    return { status: 'approved', outcome: change.done(args, new Date()), shown };
  }

  // What it replaces, read again: another version set since the page showed it refuses it. Unread on either side,
  // nothing is approved. The change carries what this read found to the vault, which refuses a write made in between.
  let replaced: Replaced | undefined;
  if (change.replaces !== undefined) {
    if (input.basis === undefined || input.basis === null) throw conflict('coffre could not read what this replaces when the page opened: reload it and try again');
    try {
      replaced = await change.replaces(ctx, args);
    } catch (error) {
      if (!(error instanceof ApiError)) throw error;
      throw new ApiError('unavailable', 'coffre could not read what this replaces just now: try again');
    }
    if (basisOf(replaced) !== input.basis) throw conflict('this changed since you opened it: open the approval again');
  }
  try {
    const { shown = [] } = await change.apply({ ...ctx, via: { connection: row.connectionId, approval: id, digest: input.digest } }, args, { value: input.value, replaced });
    return { status: 'approved', outcome: change.done(args, new Date()), shown };
  } catch (error) {
    // Between Approve's read and the vault's write, what it changes moved: nothing is, and the person decides on it as it is now.
    if (error instanceof ApiError && error.reason === 'stale') throw conflict(STALE);
    throw error;
  }
}

/** What the person reads when the key changed between Approve's read and the vault's write. */
export const STALE = 'this changed since you were asked, so nothing was changed: open the approval again to see it as it is now';

/**
 * An approval, its tool and its client, if the caller is its person on a
 * browser session of theirs, from coffre's own page, and its connection
 * stands. Anyone else is told it is someone else's, and nothing more. The
 * vault holds every decision to the same: this is what the page is told.
 */
async function mine(ctx: ApiContext, id: string): Promise<{ row: FoundApproval; tool: Tool; client: ReturnType<typeof clientShown> }> {
  if (ctx.crossSite) throw new ApiError('cross_origin', "an app's change is decided on coffre's own page");
  const who = await ctx.caller();
  if (who.credential.kind !== 'browser') throw forbidden("an app's change is decided on coffre's page, in the browser you signed in with");
  const row = await findApproval(ctx.db, id, OUTCOME_SECONDS);
  const tool = row === null ? undefined : TOOL_BY_NAME.get(row.tool);
  if (row?.connection == null || tool?.change === undefined) throw notFound('no such approval');
  if (row.connection.principal !== who.principal) throw forbidden('this approval is for someone else');
  const client = clientShown(row.connection);
  if (!row.connection.live) throw conflict(`${client.name} is disconnected: this approval can no longer be decided`);
  return { row, tool, client };
}
