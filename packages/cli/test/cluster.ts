// Disposable Postgres clusters, for the tests of `coffre setup`: roles are
// cluster-wide, so these make and drop coffre's own. scripts/test-setup.sh
// starts them, from `pnpm test:schema`: one, another, for a second
// deployment on a server of its own, and a small one.
import { postgresClient, quoteIdentifier, type PostgresClient } from '@coffre/db/connect';

/** The cluster's superuser URL, without a database; and the other's. */
export const CLUSTER = process.env.COFFRE_TEST_SETUP_CLUSTER;
export const OTHER_CLUSTER = process.env.COFFRE_TEST_SETUP_OTHER_CLUSTER;
/** One that lets in only 15 connections, 3 of them for superusers: too few for coffre's two Hyperdrive configs. */
export const SMALL_CLUSTER = process.env.COFFRE_TEST_SETUP_SMALL_CLUSTER;
export const needsCluster = { skip: CLUSTER === undefined && 'needs a disposable cluster: scripts/test-setup.sh' };

export async function asSuperuser<T>(database: string, work: (client: PostgresClient) => Promise<T>, cluster = CLUSTER): Promise<T> {
  const client = postgresClient(`${cluster}/${database}`, { max: 1 });
  try {
    return await work(client);
  } finally {
    await client.end();
  }
}

/** Connect as `url`, and say whether it worked. */
export async function connects(url: string): Promise<boolean> {
  const client = postgresClient(url, { max: 1 });
  try {
    await client.unsafe('SELECT count(*) FROM vault_members');
    return true;
  } catch {
    return false;
  } finally {
    await client.end().catch(() => {});
  }
}

/** The cluster as a fresh managed service's: no coffre roles, no databases of ours. */
export async function emptyCluster(cluster = CLUSTER): Promise<void> {
  await asSuperuser('postgres', async (client) => {
    for (const { datname } of await client.unsafe<{ datname: string }[]>("SELECT datname FROM pg_database WHERE datname LIKE 'setup\\_%'")) {
      await client.unsafe(`DROP DATABASE ${quoteIdentifier(datname)} WITH (FORCE)`);
    }
    await client.unsafe('DROP ROLE IF EXISTS coffre_runtime, coffre_vault_runtime, coffre_vault_hot, coffre_app, coffre_vault, coffre_backup, coffre_backup_login, setup_owner, setup_deployer, setup_reporting');
  }, cluster);
}

/**
 * A database, and the URL of its administrator: the superuser, or an owner
 * as PlanetScale and other managed hosts give one, with CREATEROLE and
 * CREATEDB but neither superuser nor any role's membership.
 */
export async function database(name: string, as: 'superuser' | 'owner'): Promise<string> {
  if (as === 'superuser') {
    await asSuperuser('postgres', (client) => client.unsafe(`CREATE DATABASE ${name}`));
    return `${CLUSTER}/${name}`;
  }
  await asSuperuser('postgres', (client) => client.unsafe("CREATE ROLE setup_owner LOGIN CREATEROLE CREATEDB PASSWORD 'owner-only-p4ss'"));
  const owner = new URL(CLUSTER!);
  owner.username = 'setup_owner';
  owner.password = 'owner-only-p4ss';
  const client = postgresClient(`${owner.href.replace(/\/$/, '')}/postgres`, { max: 1 });
  try {
    await client.unsafe(`CREATE DATABASE ${name}`);
  } finally {
    await client.end();
  }
  return `${owner.href.replace(/\/$/, '')}/${name}`;
}
