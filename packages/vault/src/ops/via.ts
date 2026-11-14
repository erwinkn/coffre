import { credentials, mcpApprovals } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { amended, part, WRITE_MS, type Operation, type Parts, type Seen } from '../change.ts';
import type { Row } from '../rows.ts';

/** A UUID as the vault writes one: an app that names the connection otherwise is at fault. */
const UUID = /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;

/** The parts a change read through a connection reads besides its own: the connection, the approval, and the caller's credential, by the token's hash. */
type ViaParts = {
  viaConnection: ReturnType<typeof part<typeof credentials>>;
  viaApproval: ReturnType<typeof part<typeof mcpApprovals>>;
  viaCaller: ReturnType<typeof part<typeof credentials>>;
};

/**
 * A change a person approved for an MCP connection on coffre's page
 * (`ForConnection` in @coffre/core/vault): the operation as it is, which
 * decides it on the person's own rows, with the connection and the approval
 * read beside them. The connection must stand, be the caller's own, of
 * their generation, the caller on a browser session, and unexpired by the
 * time the write starts: otherwise the change is refused `disconnected`.
 * The approval must be the connection's, pending, of the digest the page
 * rendered, and unexpired by the time the write starts: otherwise
 * `unknown_approval`. Made, the change writes the
 * approval approved, and its entry names both. Two Approves at once both
 * read it pending, and the second's write finds it changed, starts over and
 * is refused. Nothing else is decided on it, and an MCP access token is
 * never the caller of a change (`callerFrom`).
 */
export function through<P extends Parts, A, C>(operation: Operation<P, A, C>, via: unknown, token: Buffer): Operation<P & ViaParts, A, C> {
  const { connection, approval, digest } = (typeof via === 'object' && via !== null ? via : {}) as Record<string, unknown>;
  if (typeof connection !== 'string' || !UUID.test(connection) || typeof approval !== 'string' || !UUID.test(approval) || typeof digest !== 'string' || !HASH.test(digest)) {
    throw new TypeError("a change names the connection and the approval it is made for by their ids, and the approval's digest");
  }
  const read = {
    ...operation.read,
    viaConnection: part(credentials, sql`${credentials.id} = ${connection}::uuid`),
    viaApproval: part(mcpApprovals, sql`${mcpApprovals.id} = ${approval}::uuid`),
    viaCaller: part(credentials, sql`${credentials.tokenHash} = decode(${token.toString('hex')}, 'hex')`),
  } as P & ViaParts;
  const withVia = <T extends { detail: Readonly<Record<string, unknown>>; objects: readonly string[] }>(entry: T): T => ({
    ...entry,
    objects: [...entry.objects, `credential:${connection}`, `mcp_approval:${approval}`],
    detail: { ...entry.detail, via: connection, approval },
  });
  return {
    ...operation,
    read,
    // What rides beside the read (`beside`) goes to the operation too: a removal counts what it ends there.
    decide(seen, at, unsealed, checked, rode) {
      const plan = operation.decide(seen, at, unsealed, checked, rode);
      if ('refused' in plan) return plan;
      if (!stands(seen, plan.entry.credential, at)) return { refused: 'disconnected' };
      const [row] = seen.viaApproval as Row<typeof mcpApprovals>[];
      if (row === undefined || !waiting(row, connection, digest, at)) return { refused: 'unknown_approval' };
      const [standing] = seen.viaConnection as Row<typeof credentials>[];
      return {
        ...plan,
        writes: [...plan.writes, amended(mcpApprovals, row, { status: 'approved', decidedAt: new Date(at) })],
        // Neither the approval nor the connection changes its row by lapsing: the write starts a write's time before both end, or not at all.
        until: Math.min(plan.until ?? Infinity, heldUntil(row), heldUntil(standing!)),
        entry: withVia(plan.entry),
      };
    },
    ...(operation.denied === undefined
      ? {}
      : {
          denied(seen, at, refusal) {
            const entry = operation.denied!(seen, at, refusal);
            return entry === null ? null : withVia(entry);
          },
        }),
  };
}

/** Whether the connection read stands for the caller who asks: their own, of their generation, live, and the caller on a browser session. */
function stands(seen: Seen<ViaParts>, credential: string | null, at: number): boolean {
  const [connection] = seen.viaConnection as Row<typeof credentials>[];
  const [caller] = seen.viaCaller as Row<typeof credentials>[];
  if (connection === undefined || caller === undefined || caller.id !== credential || caller.kind !== 'browser') return false;
  return liveConnection(connection, caller.principal, caller.generation, at);
}

/** A connection that stands, of `principal` in `generation`: its own row, its code redeemed (not an access token under it, nor one whose client never came for its tokens), with a write's time left before it ends. */
export function liveConnection(connection: Row<typeof credentials>, principal: string, generation: number, at: number): boolean {
  return (
    connection.kind === 'mcp' &&
    connection.ancestors === null &&
    connection.challenge === null &&
    connection.principal === principal &&
    connection.generation === generation &&
    connection.revokedAt === null &&
    connection.frozenAt === null &&
    heldUntil(connection) > at
  );
}

/** Whether an approval waits for its person, of this connection and digest, with a write's time left before it expires. */
export function waiting(row: Row<typeof mcpApprovals>, connection: string, digest: string, at: number): boolean {
  return row.connectionId === connection && row.status === 'pending' && row.digest.toString('hex') === digest && heldUntil(row) > at;
}

/** The last instant a decision may start its write and still land before an approval, or its connection, expires (`WRITE_MS`, as a device login's). */
export const heldUntil = (row: { expiresAt: Date }) => row.expiresAt.getTime() - WRITE_MS;
