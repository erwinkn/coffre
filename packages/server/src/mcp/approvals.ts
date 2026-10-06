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
import { findApproval, findConnection, insertApproval, openApprovals, update, type ApprovalRow, type ConnectionRow } from '../db/queries.ts';
import { logged } from '../logged.ts';
import type { Detail } from './changes.ts';
import type { McpConnection } from './service.ts';
import { TOOL_BY_NAME, type Tool } from './tools.ts';

/** How long the person has to decide: Q1's bound, for links as for elicitation. */
export const APPROVAL_SECONDS = 5 * 60;
/** How long after it was asked the client may still read the outcome. */
export const OUTCOME_SECONDS = 10 * 60;
/** Approvals a connection may hold waiting at once: no flood of prompts. */
export const MAX_PENDING = 5;
/** A value typed on the page, as the API takes one. */
const VALUE_BYTES = 64 * 1024;

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'cancelled' | 'failed' | 'expired';

/** What a decided change answered: the client's text and result, or why it failed. Never a value. */
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
  /** Of the tool and its arguments: sent back with the decision, so what runs is what was shown. */
  digest: string;
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

export function statusOf(row: ApprovalRow, now: Date): ApprovalStatus {
  return row.status === 'pending' && row.expiresAt <= now ? 'expired' : (row.status as ApprovalStatus);
}

export class McpApprovals {
  readonly #deps: { db: Database; publicUrl: string };

  constructor(deps: { db: Database; publicUrl: string }) {
    this.#deps = deps;
  }

  /** Where the person decides an approval. */
  url(id: string): string {
    return `${this.#deps.publicUrl}/approvals/${id}`;
  }

  // --- for /mcp -----------------------------------------------------------------

  /**
   * The approval for a call: the one the same call already opened, if its
   * client has not yet heard how it ended, or a new one. `joined` says which.
   */
  async ask(connection: McpConnection, tool: Tool, args: unknown): Promise<{ row: ApprovalRow; joined: boolean } | { full: true }> {
    const digest = Buffer.from(callDigest(tool.name, args), 'hex');
    const { rows, now } = await openApprovals(this.#deps.db, connection.id);
    const same = rows.find((row) => row.digest.equals(digest) && statusOf(row, now) !== 'expired' && row.createdAt.getTime() + OUTCOME_SECONDS * 1000 > now.getTime());
    if (same !== undefined) return { row: same, joined: true };
    if (rows.filter((row) => statusOf(row, now) === 'pending').length >= MAX_PENDING) return { full: true };
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
    await insertApproval(this.#deps.db, row);
    return { row, joined: false };
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

  /** The client declined or cancelled the prompt: a pending approval is cancelled, and then decided. */
  async cancel(id: string): Promise<void> {
    await update(this.#deps.db, mcpApprovals, { id, status: 'pending' }, { status: 'cancelled', decidedAt: new Date() });
  }

  // --- for coffre's page ----------------------------------------------------------

  /** What the page shows: only to the approval's own person, at their connection's generation. */
  async view(ctx: ApiContext, id: string): Promise<ApprovalView> {
    const { row, connection, tool } = await withRefusals(ctx, () => this.#mine(ctx, id, 'mcp.view'));
    const status = statusOf(row, row.now);
    const args = JSON.parse(row.arguments) as never;
    let details: Detail[] = [];
    if (status === 'pending') {
      try {
        details = await tool.change!.preview(this.#client(ctx), args);
      } catch (error) {
        if (!(error instanceof CoffreError)) throw error;
        details = [{ label: 'Note', value: `coffre could not read what this replaces: ${error.message}` }];
      }
    }
    return {
      id: row.id,
      status,
      client: { name: connection.clientName, host: connection.clientHost, registration: connection.registration as 'cimd' | 'dcr' },
      tool: tool.name,
      summary: tool.change!.summary(args),
      details,
      asks: tool.change!.asks ?? null,
      kind: tool.change!.reveal === true ? 'reveal' : 'change',
      digest: row.digest.toString('hex'),
      createdAt: row.createdAt.toISOString(),
      expiresAt: row.expiresAt.toISOString(),
      outcome: row.outcome === null ? null : (JSON.parse(row.outcome) as Outcome),
    };
  }

  /**
   * The person's decision. Approved, the change is made here, once, as the
   * person through the connection, every check of the API's running again;
   * its outcome is stored for the client. `digest` is the one the page
   * showed: a change that is not what the person read is refused.
   */
  async decide(ctx: ApiContext, id: string, input: { approve: boolean; digest: string; value?: string }): Promise<Decision> {
    return withRefusals(ctx, () => this.#decide(ctx, id, input));
  }

  async #decide(ctx: ApiContext, id: string, input: { approve: boolean; digest: string; value?: string }): Promise<Decision> {
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
    if (input.approve && tool.change!.asks?.value !== undefined && (input.value === undefined || input.value === '')) {
      throw new ApiError('bad_request', 'type the value to set first');
    }

    await audited(ctx, async (tx, log) => {
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
    let connection: Awaited<ReturnType<typeof findConnection>>;
    try {
      connection = await findConnection(this.#deps.db, ctx.chainKey, { id: row.connectionId });
    } catch (error) {
      if (!(error instanceof AuthRowTampered)) throw error;
      connection = null;
    }
    const tool = TOOL_BY_NAME.get(row.tool);
    if (connection === null || tool?.change === undefined) throw notFound('no such approval');
    if (ctx.caller.principal.type !== 'user' || connection.principal !== `user:${ctx.caller.principal.id}`) {
      throw new Refusal(forbidden('this approval is for someone else'), denied(ctx, action, 'not_yours', { metadata: { approvalId: id } }));
    }
    if (connection.revokedAt !== null || connection.expiresAt <= connection.now || connection.generation !== ctx.caller.generation) {
      throw conflict(`${connection.clientName} is disconnected: this approval can no longer be decided`);
    }
    return { row, connection, tool };
  }

  /** The API in process, with this request's caller and connection, and nothing to authenticate again. */
  #client(ctx: ApiContext): CoffreClient {
    return createClient({ url: this.#deps.publicUrl, transport: (request) => serveApi(request, ctx) });
  }
}
