import { postgresSession } from '../src/postgres.ts';

/**
 * `run`, holding the lock scripts/ensure-database.mjs takes on the cluster's roles: a migration from nothing alters
 * and grants coffre's roles, the cluster's, and two at once fail one of them with `tuple concurrently updated`.
 */
export async function holdingRoles<T>(base: string, run: () => Promise<T>): Promise<T> {
  const lock = postgresSession(Object.assign(new URL(base), { pathname: '/postgres' }).toString());
  try {
    await lock.unsafe("SELECT pg_advisory_lock(hashtextextended('coffre:local-roles', 0))");
    return await run();
  } finally {
    await lock.end();
  }
}
