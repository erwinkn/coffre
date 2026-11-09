// How many connections each Hyperdrive config may open to the database,
// out of what the database lets coffre's logins open: what `coffre setup`
// reads as it connects, before it changes anything, and gives each config.
// The share is the one a Node process sizes its pools to (`@coffre/db/connections`).
import { DATABASE_FACTS, FEWEST, HELD_BACK, HYPERDRIVE_CONNECTIONS, share, tooFewConnections as tooFew, type Connections } from '@coffre/db/connections';
import type { PostgresClient } from '@coffre/db/connect';

export type { Connections };

/**
 * The most connections each of the three Hyperdrive configs may open: an
 * even share of what the database lets its logins open, less what is held
 * back. Hyperdrive opens connections up to its limit before it queues a
 * query, and left at Cloudflare's default, 60 on Paid, the configs outgrow a
 * small database, such as PlanetScale's smallest: it refuses the
 * connection a burst of requests needs ("remaining connection slots are
 * reserved", 53300), and they fail. Under the limit, a query waits its turn
 * instead, which a query holding a connection only while it runs keeps
 * short. Null when the share is short of what Hyperdrive takes.
 */
export function hyperdriveLimit(connections: Connections): number | null {
  const each = share(connections);
  return each < FEWEST ? null : Math.min(each, HYPERDRIVE_CONNECTIONS.most);
}

/**
 * The limit to give a config that may open `current` connections now:
 * `limit`, when it opens more or when that is not known (a config left
 * unset opens Cloudflare's default, 60 on Paid); null to leave it, since a
 * limit someone set lower is theirs to keep.
 */
export function cappedLimit(current: number | null | undefined, limit: number): number | null {
  return current === null || current === undefined || current > limit ? limit : null;
}

/** How the limit was chosen: `max_connections 25, 3 reserved, 4 kept for migrations and backups: 6 each`. */
export function limitReason(connections: Connections, limit: number): string {
  const each = share(connections);
  return (
    `max_connections ${connections.max}, ${connections.reserved} reserved, ${HELD_BACK} kept for migrations and backups: ` +
    `${each} each${each > limit ? `, capped at ${limit}` : ''}`
  );
}

/** Why a database letting in `connections` can have no Hyperdrive config for each login. */
export function tooFewConnections(connections: Connections): string {
  return tooFew(connections, { workers: true });
}

/** What the database lets in, as the administrator reads it. */
export async function connectionsOf(client: PostgresClient): Promise<Connections> {
  const [row] = await client.unsafe<Connections[]>(DATABASE_FACTS);
  return { max: row!.max, reserved: row!.reserved };
}
