#!/usr/bin/env node
// Create a local database, and the restricted logins the app and the vault
// run as, unless they exist: `node scripts/ensure-database.mjs coffre`.
// Connects to the local Postgres as its owner; nothing here is for anywhere
// else.
//
// Production creates the logins in Terraform. Locally they are made here,
// before the migrations grant them what they need.
import pg from 'pg';

const name = process.argv[2];
if (!/^coffre[a-z0-9_]*$/.test(name ?? '')) {
    console.error('usage: ensure-database.mjs <coffre…>: a local database named coffre, coffre_dev2, …');
    process.exit(2);
}

const client = new pg.Client('postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/postgres');
await client.connect();
try {
    // Roles belong to the cluster, not this run's database. Match the lock
    // in setup-test-database.sh so independent checkouts cannot race ALTER.
    // A session lock also covers CREATE DATABASE, which cannot run in a
    // transaction; ending this client releases it, including on failure.
    await client.query("SELECT pg_advisory_lock(hashtextextended('coffre:local-roles', 0))");
    const options = 'LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
    for (const [login, password] of [['coffre_runtime', 'local-runtime-only'], ['coffre_vault_runtime', 'local-vault-only']]) {
        const role = await client.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [login]);
        await client.query(`${role.rowCount === 0 ? 'CREATE' : 'ALTER'} ROLE ${login} ${options} PASSWORD '${password}'`);
    }
    const database = await client.query('SELECT 1 FROM pg_database WHERE datname = $1', [name]);
    if (database.rowCount === 0) await client.query(`CREATE DATABASE ${name}`);
} finally {
    await client.end();
}
