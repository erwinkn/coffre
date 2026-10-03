// Disposable Postgres clusters, for the tests of `coffre setup`: roles are
// cluster-wide, so these make and drop coffre's own. scripts/test-setup.sh
// starts them, from `pnpm test:schema`: one, and another, for a second
// deployment on a server of its own.
import pg from 'pg';

/** The cluster's superuser URL, without a database; and the other's. */
export const CLUSTER = process.env.COFFRE_TEST_SETUP_CLUSTER;
export const OTHER_CLUSTER = process.env.COFFRE_TEST_SETUP_OTHER_CLUSTER;
export const needsCluster = { skip: CLUSTER === undefined && 'needs a disposable cluster: scripts/test-setup.sh' };

export async function asSuperuser<T>(database: string, work: (client: pg.Client) => Promise<T>, cluster = CLUSTER): Promise<T> {
  const client = new pg.Client({ connectionString: `${cluster}/${database}` });
  await client.connect();
  try {
    return await work(client);
  } finally {
    await client.end();
  }
}

/** Connect as `url`, and say whether it worked. */
export async function connects(url: string): Promise<boolean> {
  const client = new pg.Client({ connectionString: url });
  try {
    await client.connect();
    await client.query('SELECT count(*) FROM vault_members');
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
    for (const { datname } of (await client.query<{ datname: string }>("SELECT datname FROM pg_database WHERE datname LIKE 'setup\\_%'")).rows) {
      await client.query(`DROP DATABASE ${client.escapeIdentifier(datname)} WITH (FORCE)`);
    }
    await client.query('DROP ROLE IF EXISTS coffre_runtime, coffre_vault_runtime, coffre_app, coffre_vault, setup_owner');
  }, cluster);
}

/**
 * A database, and the URL of its administrator: the superuser, or an owner
 * as PlanetScale and other managed hosts give one, with CREATEROLE and
 * CREATEDB but neither superuser nor any role's membership.
 */
export async function database(name: string, as: 'superuser' | 'owner'): Promise<string> {
  if (as === 'superuser') {
    await asSuperuser('postgres', (client) => client.query(`CREATE DATABASE ${name}`));
    return `${CLUSTER}/${name}`;
  }
  await asSuperuser('postgres', (client) => client.query("CREATE ROLE setup_owner LOGIN CREATEROLE CREATEDB PASSWORD 'owner-only-p4ss'"));
  const owner = new URL(CLUSTER!);
  owner.username = 'setup_owner';
  owner.password = 'owner-only-p4ss';
  const client = new pg.Client({ connectionString: `${owner.href.replace(/\/$/, '')}/postgres` });
  await client.connect();
  await client.query(`CREATE DATABASE ${name}`);
  await client.end();
  return `${owner.href.replace(/\/$/, '')}/${name}`;
}
