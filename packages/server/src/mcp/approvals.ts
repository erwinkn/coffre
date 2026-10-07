// Approvals (docs/design/mcp.md, section 7): every change an MCP client asks
// for waits here until its person decides it on coffre's own page. The page
// shows what the change would do, read afresh; Approve makes it there and
// then, once, as the person with the connection attached, and stores what
// it answered, without values, for the client to read when it comes back.
// The client never makes the change itself, so it happens exactly once,
// whether or not the client returns (D36).
import { createHash, randomUUID } from 'node:crypto';

import { CoffreError, createClient, type CoffreClient } from '@coffre/client';
import { parseScopes } from '@coffre/core/mcp';
import type { Database } from '@coffre/db';
import { mcpApprovals } from '@coffre/db/schema';

import { allowed, audited, denied, Refusal, withRefusals, type ApiContext, type McpVia } from '../api/context.ts';
import { ApiError, conflict, forbidden, notFound } from '../api/errors.ts';
import { serveApi } from '../api/router.ts';
import { AuthRowTampered } from '../auth-rows.ts';
import type { AuditEntry } from '../db/audit.ts';
import { findApproval, findConnection, insertApproval, openApprovals, unansweredApprovals, update, type ApprovalRow, type ConnectionRow } from '../db/queries.ts';
import { logged } from '../logged.ts';
import type { WorkloadTransport } from '../workloads/transport.ts';
import type { Detail, Viewing } from './changes.ts';
import type { McpConnection } from './service.ts';
import { TOOL_BY_NAME, type Tool } from './tools.ts';

/** How long the person has to decide: Q1's bound, for links as for elicitation. */
export const APPROVAL_SECONDS = 5 * 60;
/** How long after it was asked the client may still read the outcome. */
export const OUTCOME_SECONDS = 10 * 60;
/** Approvals a connection may hold waiting at once: no flood of prompts. */
export const MAX_PENDING = 5;
/** How long Approve may take to make its change: approved and still without an outcome after that, it never got one. */
export const APPLY_SECONDS = 60;

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'cancelled' | 'failed' | 'expired';

/** What a decided change answered: the client's text and result, or why it failed. Never a value. */
export type Outcome = { text: string; result?: Record<string, unknown>; error?: string };

/** The outcome of a change approved whose making never answered: it may or may not have been made. */
export const UNKNOWN_OUTCOME: Outcome = {
  text: 'The person approved this, but coffre does not know whether the change was made: check before asking for it again.',
  error: 'unknown_outcome',
};

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
  /** Of the tool and its arguments: sent back with the decision, so what runs is what was shown. */
  digest: string;
  /** What the change replaces, as shown: sent back with Approve, which refuses it if it changed since. */
  basis: string | null;
  createdAt: string;
  expiresAt: string;
  /** Once decided: what became of it. */
  outcome: Outcome | null;
};

/** What the page shows once the person decided: the outcome, and what only it may show, once. */
export type Decision = { status: ApprovalStatus; outcome: Outcome; shown: Detail[] };

/** SHA-256 of the canonical JSON of a tool's name and arguments: what a call, and its approval, are. */
export function callDigest(tool: string, args: unknown): string {
  return createHash('sha256').update(canonical([tool, args])).digest('hex');
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

/**
 * Where an approval stands at `now`. Pending past its expiry, it expired.
 * Approved, and still without an outcome a minute on, its making died
 * before it answered: it failed, its outcome unknown (`outcomeOf`).
 */
export function statusOf(row: ApprovalRow, now: Date): ApprovalStatus {
  if (row.status === 'pending' && row.expiresAt <= now) return 'expired';
  if (unanswered(row, now)) return 'failed';
  return row.status as ApprovalStatus;
}

function unanswered(row: ApprovalRow, now: Date): boolean {
  return row.status === 'approved' && row.outcome === null && (row.decidedAt?.getTime() ?? 0) + APPLY_SECONDS * 1000 <= now.getTime();
}

/** What became of an approval, once known; `UNKNOWN_OUTCOME` for one approved that never answered. */
export function outcomeOf(row: ApprovalRow, now: Date): Outcome | null {
  if (row.outcome !== null) return JSON.parse(row.outcome) as Outcome;
  return unanswered(row, now) ? UNKNOWN_OUTCOME : null;
}

type ApprovalDeps = { db: Database; chainKey: Buffer; publicUrl: string; transport: WorkloadTransport };

export class McpApprovals {
  readonly #deps: ApprovalDeps;

  constructor(deps: ApprovalDeps) {
    this.#deps = deps;
  }

  /** Where the person decides an approval. */
  url(id: string): string {
    return `${this.#deps.publicUrl}/approvals/${id}`;
  }

  // --- for /mcp -----------------------------------------------------------------

  /**
   * The approval for a call: the one the same call already opened, if its
   * client has not yet heard how it ended, or a new one, logged with
   * `entry`. `joined` says which. Read and written under the log's head,
   * so that identical calls at once open one approval, and no burst of
   * calls gets past `MAX_PENDING`.
   */
  async ask(connection: McpConnection, tool: Tool, args: unknown, entry: (approvalId: string) => AuditEntry): Promise<{ row: ApprovalRow; joined: boolean } | { full: true }> {
    const digest = Buffer.from(callDigest(tool.name, args), 'hex');
    return audited(this.#deps, async (tx, log) => {
      const { rows, now } = await openApprovals(tx, connection.id, new Date(Date.now() - OUTCOME_SECONDS * 1000));
      const same = rows.find((row) => row.digest.equals(digest) && statusOf(row, now) !== 'expired' && row.createdAt.getTime() + OUTCOME_SECONDS * 1000 > now.getTime());
      if (same !== undefined) return { row: same, joined: true };
      if (rows.filter((row) => statusOf(row, now) === 'pending').length >= MAX_PENDING) return { full: true as const };
      const row = {
        id: randomUUID(),
        connectionId: connection.id,
        tool: tool.name,
        arguments: JSON.stringify(args),
        digest,
        status: 'pending',
        outcome: null,
        createdAt: now,
        expiresAt: new Date(now.getTime() + APPROVAL_SECONDS * 1000),
        decidedAt: null,
        reportedAt: null,
      };
      await insertApproval(tx, row);
      log.push(entry(row.id));
      return { row, joined: false };
    });
  }

  async find(id: string): Promise<(ApprovalRow & { now: Date }) | null> {
    return findApproval(this.#deps.db, id);
  }

  /**
   * The approval once it is no longer waiting for the person, or as it is
   * at `until`: read again every second, in plain queries, holding nothing.
   * One approved whose change is still being made counts as waiting.
   */
  async settle(id: string, until: number): Promise<ApprovalRow & { now: Date }> {
    for (;;) {
      const row = (await findApproval(this.#deps.db, id))!;
      const status = statusOf(row, row.now);
      if (!(status === 'pending' || (status === 'approved' && row.outcome === null)) || Date.now() + 1000 > until) return row;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }

  /** The client heard how it ended: the same call asks afresh from now on. */
  async reported(id: string): Promise<void> {
    await update(this.#deps.db, mcpApprovals, { id, reportedAt: null }, { reportedAt: new Date() });
  }

  /** The client declined the prompt: a pending approval is cancelled, logged with `entry`, and then decided. */
  async cancel(id: string, entry: AuditEntry): Promise<void> {
    await audited(this.#deps, async (tx, log) => {
      if ((await update(tx, mcpApprovals, { id, status: 'pending' }, { status: 'cancelled', decidedAt: new Date() })) > 0) log.push(entry);
    });
  }

  // --- for coffre's page ----------------------------------------------------------

  /** What the page shows: only to the approval's own person, at their connection's generation. */
  async view(ctx: ApiContext, id: string): Promise<ApprovalView> {
    const { row, connection, tool } = await withRefusals(ctx, () => this.#mine(ctx, id, 'mcp.view'));
    const status = statusOf(row, row.now);
    const args = JSON.parse(row.arguments) as never;
    const viewing: Viewing = { reveals: parseScopes(connection.scopes).scopes.includes('reveal'), transport: this.#deps.transport };
    let details: Detail[] = [];
    let basis: string | null = null;
    if (status === 'pending') {
      const api = this.#client(ctx);
      try {
        details = await tool.change!.preview(api, args, viewing);
      } catch (error) {
        if (!(error instanceof CoffreError)) throw error;
        details = [{ label: 'Note', value: `coffre could not read what this replaces: ${error.message}` }];
      }
      basis = await this.#basis(api, tool, args);
      // The same call approved before, whose making never answered: approving it again may make it twice.
      const earlier = (await unansweredApprovals(this.#deps.db, row.connectionId, row.digest)).filter((other) => other.id !== row.id);
      if (earlier.length > 0) {
        details.unshift({ label: 'Asked before', value: 'You approved this same change before, and coffre does not know whether it was made: check before approving it again.' });
      }
    }
    return {
      id: row.id,
      status,
      client: { name: connection.clientName, host: connection.clientHost, registration: connection.registration as 'cimd' | 'dcr' },
      tool: tool.name,
      summary: tool.change!.summary(args),
      details,
      asks: tool.change!.asks?.(viewing) ?? null,
      kind: tool.change!.reveal === true ? 'reveal' : 'change',
      reveals: viewing.reveals,
      digest: row.digest.toString('hex'),
      basis,
      createdAt: row.createdAt.toISOString(),
      expiresAt: row.expiresAt.toISOString(),
      outcome: outcomeOf(row, row.now),
    };
  }

  /**
   * The person's decision. Approved, the change is made here, once, as the
   * person through the connection, every check of the API's running again;
   * its outcome is stored for the client. `digest` and `basis` are the
   * ones the page showed: a change that is not what the person read, or
   * that would replace something else now, is refused.
   */
  async decide(ctx: ApiContext, id: string, input: Decide): Promise<Decision> {
    return withRefusals(ctx, () => this.#decide(ctx, id, input));
  }

  async #decide(ctx: ApiContext, id: string, input: Decide): Promise<Decision> {
    const action = input.approve ? 'mcp.approve' : 'mcp.deny';
    const { row, connection, tool } = await this.#mine(ctx, id, action);
    const args = JSON.parse(row.arguments) as unknown;
    const metadata = { approvalId: row.id, connectionId: connection.id, clientId: connection.clientId, clientName: connection.clientName, tool: tool.name, names: tool.names(args as never) };
    const refuse = (error: ApiError, reason: string) => new Refusal(error, denied(ctx, action, reason, { metadata }));
    const digest = callDigest(tool.name, args);
    if (input.digest !== digest || row.digest.toString('hex') !== digest) {
      throw refuse(conflict('this change is not the one the page showed: open the approval again'), 'changed');
    }
    const status = statusOf(row, row.now);
    if (status !== 'pending') throw refuse(conflict(`this approval is ${status} already`), status);
    if (!parseScopes(connection.scopes).scopes.includes(tool.scope)) {
      throw refuse(forbidden(`${connection.clientName} no longer holds the ${tool.scope} scope`), 'insufficient_scope');
    }
    if (input.approve && tool.change!.asks !== undefined && (input.value === undefined || input.value === '')) {
      throw new ApiError('bad_request', 'type the value to set first');
    }
    // What it replaces, read again: another version set, or another role granted, since the page showed it refuses it.
    // The API takes no expected version, so a write in the moment between this read and the change still lands first.
    if (input.approve && (await this.#basis(this.#client(ctx), tool, args)) !== (input.basis ?? null)) {
      throw refuse(conflict('this changed since you opened it: open the approval again'), 'replaced');
    }

    await audited(ctx, async (tx, log) => {
      // Under the log's head, the approval and its connection as they are now: one that expired, or a disconnect, since they were read refuses it.
      const again = (await findApproval(tx, id))!;
      const status = statusOf(again, again.now);
      if (status !== 'pending') throw refuse(conflict(`this approval is ${status} already`), status);
      if (!live(await findConnection(tx, ctx.chainKey, { id: connection.id }).catch(untampered), ctx)) {
        throw refuse(conflict(`${connection.clientName} is disconnected: this approval can no longer be decided`), 'disconnected');
      }
      const moved = await update(tx, mcpApprovals, { id, status: 'pending' }, { status: input.approve ? 'approved' : 'denied', decidedAt: new Date() });
      if (moved === 0) throw refuse(conflict('this approval was decided already'), 'decided');
      log.push(allowed(ctx, action, { metadata }));
    });
    if (!input.approve) {
      const outcome = { text: `The person denied this on coffre: nothing changed.` };
      await update(this.#deps.db, mcpApprovals, { id }, { outcome: JSON.stringify(outcome) });
      return { status: 'denied', outcome, shown: [] };
    }

    // The change, after the decision committed and outside any transaction: the API makes it as it would for the person.
    // A reveal reads the value for the page alone, so its call may reach Reveal values' route whatever the connection holds.
    const scopes = [...parseScopes(connection.scopes).scopes, ...(tool.change!.reveal === true ? (['reveal'] as const) : [])];
    const via: McpVia = { connectionId: connection.id, clientId: connection.clientId, clientName: connection.clientName, scopes, approvalId: row.id };
    try {
      const applied = await tool.change!.apply(this.#client({ ...ctx, via, provenance: connection.id }), args as never, { value: input.value });
      const outcome: Outcome = { text: applied.text, result: applied.result };
      await update(this.#deps.db, mcpApprovals, { id }, { outcome: JSON.stringify(outcome) });
      return { status: 'approved', outcome, shown: applied.shown ?? [] };
    } catch (error) {
      const known = error instanceof CoffreError;
      if (!known) console.error('an approved MCP change failed', logged(error));
      const outcome: Outcome = { text: `coffre could not make the change: ${known ? error.message : 'see the server log'}`, error: known ? error.code : 'internal' };
      await update(this.#deps.db, mcpApprovals, { id }, { status: 'failed', outcome: JSON.stringify(outcome) });
      return { status: 'failed', outcome, shown: [] };
    }
  }

  /**
   * An approval, its connection and its tool, if the caller is its person,
   * at the generation they connected the client in, and the connection is
   * live. Anyone else is told it is someone else's, and nothing more.
   */
  async #mine(ctx: ApiContext, id: string, action: string): Promise<{ row: ApprovalRow & { now: Date }; connection: ConnectionRow; tool: Tool }> {
    const row = await findApproval(this.#deps.db, id);
    if (row === null) throw notFound('no such approval');
    const connection = await findConnection(this.#deps.db, ctx.chainKey, { id: row.connectionId }).catch(untampered);
    const tool = TOOL_BY_NAME.get(row.tool);
    if (connection === null || tool?.change === undefined) throw notFound('no such approval');
    if (ctx.caller.principal.type !== 'user' || connection.principal !== `user:${ctx.caller.principal.id}`) {
      throw new Refusal(forbidden('this approval is for someone else'), denied(ctx, action, 'not_yours', { metadata: { approvalId: id } }));
    }
    if (!live(connection, ctx)) throw conflict(`${connection.clientName} is disconnected: this approval can no longer be decided`);
    return { row, connection, tool };
  }

  /** What a change replaces, as the person reads it now; null for a tool with none, or one they cannot read, on the page as on Approve. */
  async #basis(api: CoffreClient, tool: Tool, args: unknown): Promise<string | null> {
    try {
      return (await tool.change!.basis?.(api, args as never)) ?? null;
    } catch (error) {
      if (!(error instanceof CoffreError)) throw error;
      return null;
    }
  }

  /** The API in process, with this request's caller and connection, and nothing to authenticate again. */
  #client(ctx: ApiContext): CoffreClient {
    return createClient({ url: this.#deps.publicUrl, transport: (request) => serveApi(request, ctx) });
  }
}

/** What the page sends back: the decision, the digest and basis it showed, and a value typed. */
type Decide = { approve: boolean; digest: string; basis?: string | null; value?: string };

/** A connection that failed its MAC is no connection. */
function untampered(error: unknown): null {
  if (!(error instanceof AuthRowTampered)) throw error;
  return null;
}

/** Whether a connection still acts for the caller: live, and at the generation they connected it in. */
function live(connection: (ConnectionRow & { now: Date }) | null, ctx: ApiContext): boolean {
  return connection !== null && connection.revokedAt === null && connection.expiresAt > connection.now && connection.generation === ctx.caller.generation;
}
