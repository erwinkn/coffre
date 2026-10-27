// Scratch databases belonging to one test run. The random run suffix keeps
// concurrent invocations and other checkouts separate, even with the same base.
import { postgresClient, quoteIdentifier } from '@coffre/db/connect';
import { restrictDatabase } from '@coffre/db/migrate';

/** How a connection to the local Postgres is opened, as its owner: a test replaces it. */
export const owners = {
    open: (database) => postgresClient(`postgresql://coffre_owner:local-dev-only@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${encodeURIComponent(database)}`, { max: 1 }),
};

export async function withOwner(work, database = 'postgres') {
    const owner = owners.open(database);
    try {
        return await work(owner);
    } finally {
        await owner.end();
    }
}

export async function cloneDatabase(template, name) {
    await withOwner(async (owner) => {
        await owner.unsafe(`CREATE DATABASE ${quoteIdentifier(name)} TEMPLATE ${quoteIdentifier(template)}`);
    });
    // TEMPLATE copies schema grants but not database ACLs. Use the same
    // restriction as migration, connected to the clone it must restrict.
    await withOwner(restrictDatabase, name);
}

export async function removeDatabases(template) {
    if (!/^[a-zA-Z0-9_]+_[a-f0-9]{16}$/.test(template)) throw new Error('not a test run template');
    const databases = await withOwner(async (owner) => {
        const rows = await owner.unsafe('SELECT datname FROM pg_database');
        return rows.map(({ datname }) => datname).filter((name) =>
            name === template || (name.startsWith(`${template}_`) && /^\d+$/.test(name.slice(template.length + 1))));
    });
    let next = 0;
    const results = await Promise.allSettled(Array.from({ length: Math.min(4, databases.length) }, () =>
        withOwner(async (owner) => {
            while (next < databases.length) {
                const name = databases[next++];
                await owner.unsafe(`DROP DATABASE ${quoteIdentifier(name)} WITH (FORCE)`);
            }
        })));
    for (const result of results) if (result.status === 'rejected') throw result.reason;

}

if (process.argv[2] === 'cleanup') await removeDatabases(process.argv[3]);
