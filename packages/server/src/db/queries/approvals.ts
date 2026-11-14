import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

/**
 * The changes MCP clients ask for, waiting for their person
 * (`mcp_approvals`, docs/design/0.16.md, "An MCP client's changes"), as the
 * app reads them: the vault writes them (`mcp.ask`, `mcp.decide`, and the
 * change an Approve makes). The rows carry no MAC: one changes nothing by
 * itself, and the vault reads it again on every decision.
 */

/** An approval's row, with the database's clock as it was read. */
export type ApprovalRow = {
  id: string;
  connectionId: string;
  tool: string;
  /** JSON: the tool's arguments, as checked when it was called. */
  arguments: string;
  /** SHA-256 of the tool and its arguments, canonical (`callDigest`), lowercase hex. */
  digest: string;
  /** pending, approved or denied; 0.14 also wrote cancelled and failed. */
  status: 'pending' | 'approved' | 'denied' | 'cancelled' | 'failed';
  createdAt: Date;
  expiresAt: Date;
  decidedAt: Date | null;
  now: Date;
};

/** The connection an approval came on, as its row says: its person, its name, its client, and whether it stands. */
export type ApprovalConnection = { principal: string; label: string | null; client: string; live: boolean };

/**
 * An approval as the page and its client read it: the row, its connection,
 * and when its person approved the same call of the same connection last,
 * within `since` seconds before it was asked (`approvedBefore`).
 */
export type FoundApproval = ApprovalRow & { connection: ApprovalConnection | null; approvedBefore: Date | null };

const COLUMNS = sql`a.id::text AS id, a.connection_id::text AS "connectionId", a.tool, a.arguments, encode(a.digest, 'hex') AS digest, a.status,
  a.created_at AS "createdAt", a.expires_at AS "expiresAt", a.decided_at AS "decidedAt", now() AS now`;

const dateOrNull = (value: Date | string | null) => (value === null ? null : new Date(value));

/**
 * An approval by its id, with its connection's row as it stands (no MAC is
 * checked here: the vault reads it again on every decision), and the last
 * time the same call of the same connection was approved, `since` seconds
 * before this one was asked. One statement, by the two indexes.
 */
export async function findApproval(db: Queryable, id: string, since: number): Promise<FoundApproval | null> {
  const [row] = await rowsOf<FoundApproval>(db, sql`
    SELECT ${COLUMNS},
      CASE WHEN c.id IS NOT NULL THEN json_build_object('principal', c.principal, 'label', c.label, 'client', c.client,
        'live', c.kind = 'mcp' AND c.ancestors IS NULL AND c.challenge IS NULL AND c.revoked_at IS NULL AND c.frozen_at IS NULL AND c.expires_at > now()) END AS connection,
      (SELECT max(e.decided_at) FROM mcp_approvals e WHERE e.connection_id = a.connection_id AND e.digest = a.digest AND e.id <> a.id
        AND e.status = 'approved' AND e.decided_at BETWEEN a.created_at - make_interval(secs => ${since}) AND a.created_at) AS "approvedBefore"
    FROM mcp_approvals a LEFT JOIN credentials c ON c.id = a.connection_id
    WHERE a.id = ${id}::uuid`);
  if (row === undefined) return null;
  return { ...row, createdAt: new Date(row.createdAt), expiresAt: new Date(row.expiresAt), decidedAt: dateOrNull(row.decidedAt), approvedBefore: dateOrNull(row.approvedBefore), now: new Date(row.now) };
}

/** The approval a connection's same call waits on, if one does: the one a call that names none joins. One statement, by the index. */
export async function pendingAsk(db: Queryable, connectionId: string, digest: string): Promise<{ id: string; expiresAt: Date } | null> {
  const [row] = await rowsOf<{ id: string; expiresAt: Date | string }>(db, sql`
    SELECT id::text AS id, expires_at AS "expiresAt" FROM mcp_approvals
    WHERE connection_id = ${connectionId}::uuid AND digest = decode(${digest}, 'hex') AND status = 'pending' AND expires_at > now()
    ORDER BY created_at DESC LIMIT 1`);
  return row === undefined ? null : { id: row.id, expiresAt: new Date(row.expiresAt) };
}
