// Scratch databases belonging to one test run. The random run suffix keeps
// concurrent invocations and other checkouts separate, even with the same base.
import pg from 'pg';

export async function withOwner(work) {
    const owner = new pg.Client('postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/postgres');
    await owner.connect();
    try {
        return await work(owner);
    } finally {
        await owner.end();
    }
}

export async function cloneDatabase(template, name) {
    await withOwner(async (owner) => {
        await owner.query(`CREATE DATABASE ${pg.escapeIdentifier(name)} TEMPLATE ${pg.escapeIdentifier(template)}`);
        // CREATE DATABASE copies the schema's grants, but not database ACLs.
        // Keep the same restricted logins and database privileges as migration.
        await owner.query(`REVOKE CREATE, TEMPORARY ON DATABASE ${pg.escapeIdentifier(name)} FROM PUBLIC, coffre_app, coffre_runtime, coffre_vault, coffre_vault_runtime`);
    });
}

export async function removeDatabases(template) {
    if (!/^[a-zA-Z0-9_]+_[a-f0-9]{16}$/.test(template)) throw new Error('not a test run template');
    const databases = await withOwner(async (owner) => {
        const { rows } = await owner.query('SELECT datname FROM pg_database');
        return rows.map(({ datname }) => datname).filter((name) =>
            name === template || (name.startsWith(`${template}_`) && /^\d+$/.test(name.slice(template.length + 1))));
    });
    let next = 0;
    const results = await Promise.allSettled(Array.from({ length: Math.min(4, databases.length) }, () =>
        withOwner(async (owner) => {
            while (next < databases.length) {
                const name = databases[next++];
                await owner.query(`DROP DATABASE ${pg.escapeIdentifier(name)} WITH (FORCE)`);
            }
        })));
    for (const result of results) if (result.status === 'rejected') throw result.reason;

}

if (process.argv[2] === 'cleanup') await removeDatabases(process.argv[3]);
