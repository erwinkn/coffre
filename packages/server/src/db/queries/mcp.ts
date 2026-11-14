import { clientIdKept, parseScopes, type McpScope } from '@coffre/core/mcp';
import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

/**
 * What the consent page and Connected apps read of MCP connections and the
 * clients that registered: the rows as they are, their MACs unchecked. What
 * they show decides nothing: the vault reads a registration again when a
 * person approves its client (`mcp.connect`), and a connection when it is
 * ended (`credential.end`).
 */

/** A registration, as its row keeps it: its name, its own claim, and its redirects. */
export type RegisteredClient = { name: string; redirectUris: string[] };

/** A connection, as Connected apps lists it. */
export type ConnectedApp = {
  id: string;
  /** The client's name and host, as the consent page showed them. */
  name: string;
  host: string | null;
  /** `dcr`: a registration, whose name is the app's own claim. */
  registration: 'cimd' | 'dcr';
  scopes: McpScope[];
  createdAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  expiresAt: string;
};

/** A registration's id: what `oauth_clients.id` holds, and what a document's URL never is. */
export const REGISTERED = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * A person's connections the client redeemed and that stand: the
 * connection's own row (no `ancestors`) with no code waiting (`challenge`).
 * By `credentials_live_idx`, the person's credentials not revoked.
 */
const redeemed = (principal: string, at: Date) => sql`c.principal = ${principal} AND c.revoked_at IS NULL AND c.expires_at > ${at} AND ${CONNECTION}`;

/** A credential `c` that is a connection its client redeemed: not one of its access tokens, nor one whose code waits. */
export const CONNECTION = sql`c.kind = 'mcp' AND c.ancestors IS NULL AND c.challenge IS NULL`;

/** A connection's row as Connected apps reads it (`APP_JSON`). */
export type AppRow = { id: string; label: string | null; client: string; createdAt: Date | string; lastUsedAt: Date | string | null; lastUsedIp: string | null; expiresAt: Date | string };

/** A connection `c`'s columns as `appOf` reads them, as JSON. */
export const APP_JSON = sql`json_build_object('id', c.id, 'label', c.label, 'client', c.client, 'createdAt', c.created_at, 'lastUsedAt', c.last_used_at, 'lastUsedIp', c.last_used_ip, 'expiresAt', c.expires_at)`;

/** A connection as Connected apps lists it; none for one whose client does not read as one. */
export function appOf(row: AppRow): ConnectedApp[] {
  const client = clientOf(row.client);
  if (client === undefined) return [];
  const iso = (value: Date | string) => new Date(value).toISOString();
  return [{
    id: row.id,
    name: row.label ?? 'Unnamed app',
    host: client.host,
    registration: client.registration,
    scopes: client.scopes,
    createdAt: iso(row.createdAt),
    lastUsedAt: row.lastUsedAt === null ? null : iso(row.lastUsedAt),
    lastUsedIp: row.lastUsedIp,
    expiresAt: iso(row.expiresAt),
  }];
}

/** The client a connection's row keeps, JSON (`storedClient` in the vault's ops/mcp.ts); undefined for one that does not read as such. */
export function clientOf(stored: string): { host: string | null; registration: 'cimd' | 'dcr'; scopes: McpScope[] } | undefined {
  try {
    const client = JSON.parse(stored) as Record<string, unknown>;
    const { host, registration, scopes } = client ?? {};
    if (!(host === null || typeof host === 'string') || (registration !== 'cimd' && registration !== 'dcr') || typeof scopes !== 'string') return undefined;
    return { host, registration, scopes: parseScopes(scopes).scopes };
  } catch {
    return undefined;
  }
}

function registeredOf(stored: { name: string; redirectUris: string } | null): RegisteredClient | null {
  if (stored === null) return null;
  try {
    const uris: unknown = JSON.parse(stored.redirectUris);
    return Array.isArray(uris) && uris.every((uri) => typeof uri === 'string') ? { name: stored.name, redirectUris: uris } : null;
  } catch {
    return null;
  }
}

/** A registration that is not revoked, by its id: one statement, none for an id no registration has. */
export async function registeredClient(db: Queryable, id: string): Promise<RegisteredClient | null> {
  if (!REGISTERED.test(id)) return null;
  const [row] = await rowsOf<{ name: string; redirectUris: string }>(db, sql`SELECT name, redirect_uris AS "redirectUris" FROM oauth_clients WHERE id = ${id}::uuid AND revoked_at IS NULL`);
  return registeredOf(row ?? null);
}

/**
 * What the consent page reads, in one statement: the client's registration,
 * when its id is one's (`registered`), and the scopes of each of the
 * person's connections of that client, which the approval may supersede.
 * None for an id no client may have, which Postgres may not even take.
 */
export async function consentRead(db: Queryable, principal: string, clientId: string, at: Date): Promise<{ registered: RegisteredClient | null; connections: McpScope[][] }> {
  if (!clientIdKept(clientId)) return { registered: null, connections: [] };
  const id = REGISTERED.test(clientId) ? clientId : null;
  const [row] = await rowsOf<{ registered: { name: string; redirectUris: string } | null; connections: string[] }>(db, sql`
    SELECT
      (SELECT json_build_object('name', o.name, 'redirectUris', o.redirect_uris) FROM oauth_clients o WHERE o.id = ${id}::uuid AND o.revoked_at IS NULL) AS registered,
      ARRAY(SELECT c.client FROM credentials c WHERE ${redeemed(principal, at)} AND c.client::jsonb ->> 'id' = ${clientId}) AS connections`);
  return {
    registered: registeredOf(row?.registered ?? null),
    connections: (row?.connections ?? []).flatMap((stored) => {
      const client = clientOf(stored);
      return client === undefined ? [] : [client.scopes];
    }),
  };
}

/** A person's connected apps, newest first: the connections their clients redeemed, which stand. One statement, of 20 rows at most (`MAX_CONNECTIONS`). */
export async function connectedApps(db: Queryable, principal: string, at: Date): Promise<ConnectedApp[]> {
  const rows = await rowsOf<AppRow>(db, sql`
    SELECT c.id, c.label, c.client, c.created_at AS "createdAt", c.last_used_at AS "lastUsedAt", c.last_used_ip AS "lastUsedIp", c.expires_at AS "expiresAt"
    FROM credentials c WHERE ${redeemed(principal, at)} ORDER BY c.created_at DESC, c.id`);
  return rows.flatMap(appOf);
}
