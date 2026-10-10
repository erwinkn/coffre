// How many connections each Hyperdrive config may open to the database,
// out of what the database lets coffre's logins open: what `coffre setup`
// reads as it connects, before it changes anything, and gives each config.
import type pg from 'pg';

/** Connections the two Hyperdrive configs leave free: for the administrator, `coffre migrate` and the host's own tools. */
const HELD_BACK = 3;

/** The fewest connections Hyperdrive takes per config, and the most Free allows, which is plenty for coffre. */
const HYPERDRIVE_CONNECTIONS = { fewest: 5, most: 20 } as const;

/** What the database lets in: `max_connections`, and the slots it reserves for superusers and `pg_use_reserved_connections`. */
export type Connections = { max: number; reserved: number };

/** Each config's even share of what the database lets coffre's logins open, less what is held back. */
function share({ max, reserved }: Connections): number {
  return Math.floor((max - reserved - HELD_BACK) / 2);
}

/**
 * The most connections each of the two Hyperdrive configs may open: an even
 * share of what the database lets its logins open, less what is held back.
 * Hyperdrive opens connections up to its limit before it queues a query,
 * and left at Cloudflare's default, 60 on Paid, the two configs outgrow a
 * small database, such as PlanetScale's smallest: it refuses the
 * connection a burst of requests needs ("remaining connection slots are
 * reserved", 53300), and they fail. Under the limit, a query waits its turn
 * instead, which a query holding a connection only while it runs keeps
 * short. Null when the share is short of what Hyperdrive takes.
 */
export function hyperdriveLimit(connections: Connections): number | null {
  const each = share(connections);
  return each < HYPERDRIVE_CONNECTIONS.fewest ? null : Math.min(each, HYPERDRIVE_CONNECTIONS.most);
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

/** How the limit was chosen: `max_connections 25, 3 reserved, 3 kept for the administrator and migrations: 9 each`. */
export function limitReason(connections: Connections, limit: number): string {
  const each = share(connections);
  return (
    `max_connections ${connections.max}, ${connections.reserved} reserved, ${HELD_BACK} kept for the administrator and migrations: ` +
    `${each} each${each > limit ? `, capped at ${limit}` : ''}`
  );
}

/** Why a database letting in `connections` can have no Hyperdrive config for each login. */
export function tooFewConnections(connections: Connections): string {
  const needed = 2 * HYPERDRIVE_CONNECTIONS.fewest + HELD_BACK + connections.reserved;
  return (
    `the database's max_connections is ${connections.max}, ${connections.reserved} of them reserved; Hyperdrive takes at least ${HYPERDRIVE_CONNECTIONS.fewest} ` +
    `for each of coffre's two configs, and setup keeps ${HELD_BACK} for the administrator and migrations: raise max_connections to ${needed} or more, or move to a larger plan`
  );
}

/** What the database lets in, as the administrator reads it; `reserved_connections` is Postgres 16's, and none before. */
export async function connectionsOf(client: pg.Client): Promise<Connections> {
  const [row] = (await client.query<Connections>(
    `SELECT current_setting('max_connections')::int AS max,
            current_setting('superuser_reserved_connections')::int
              + coalesce(current_setting('reserved_connections', true), '0')::int AS reserved`,
  )).rows;
  return row!;
}
