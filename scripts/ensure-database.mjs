#!/usr/bin/env node
// Create a local database, and the restricted login the app runs as, unless
// they exist: `node scripts/ensure-database.mjs coffre`. Connects to the
// local Postgres as its owner; nothing here is for anywhere else.
//
// Production creates the login in Terraform. Locally it is made here, before
// the migrations grant it what it needs.
import pg from 'pg';

const name = process.argv[2];
if (!/^coffre[a-z0-9_]*$/.test(name ?? '')) {
    console.error('usage: ensure-database.mjs <coffre…>: a local database named coffre, coffre_dev2, …');
    process.exit(2);
}

const client = new pg.Client('postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/postgres');
await client.connect();
try {
    const role = await client.query("SELECT 1 FROM pg_roles WHERE rolname = 'coffre_runtime'");
    const options = 'LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
    await client.query(
        `${role.rowCount === 0 ? 'CREATE' : 'ALTER'} ROLE coffre_runtime ${options} PASSWORD 'local-runtime-only'`,
    );
    const database = await client.query('SELECT 1 FROM pg_database WHERE datname = $1', [name]);
    if (database.rowCount === 0) await client.query(`CREATE DATABASE ${name}`);
} finally {
    await client.end();
}
