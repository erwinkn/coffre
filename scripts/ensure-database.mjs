#!/usr/bin/env node
// Create a local database, and the restricted logins the app, the vault and
// its hot path run as and backups take, unless they exist:
// `node --conditions=coffre:source scripts/ensure-database.mjs coffre`.
// Connects to the local Postgres as its owner; nothing here is for anywhere
// else.
//
// Production creates the logins in Terraform. Locally they are made here,
// before the migrations grant them what they need.
import { postgresSession } from '@coffre/db/connect';

const name = process.argv[2];
if (!/^coffre[a-z0-9_]*$/.test(name ?? '')) {
    console.error('usage: ensure-database.mjs <coffre…>: a local database named coffre, coffre_dev2, …');
    process.exit(2);
}

// One session, whose advisory lock covers every statement: once its connection closes, none goes on without it.
const client = postgresSession(`postgresql://coffre_owner:local-dev-only@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/postgres`);
try {
    // Roles belong to the cluster, not this run's database. Match the lock
    // in setup-test-database.sh so independent checkouts cannot race ALTER.
    // A session lock also covers CREATE DATABASE, which cannot run in a
    // transaction; ending this client releases it, including on failure.
    await client.unsafe("SELECT pg_advisory_lock(hashtextextended('coffre:local-roles', 0))");
    const options = 'LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
    const logins = [
        ['coffre_runtime', 'local-runtime-only'],
        ['coffre_vault_runtime', 'local-vault-only'],
        // 0.15's hot path's: made here as a login, as `coffre setup` makes it, before 0022 grants it coffre_vault.
        ['coffre_vault_hot', 'local-hot-only'],
        ['coffre_backup_login', 'local-backup-only'],
    ];
    for (const [login, password] of logins) {
        const role = await client.unsafe('SELECT 1 FROM pg_roles WHERE rolname = $1', [login]);
        await client.unsafe(`${role.length === 0 ? 'CREATE' : 'ALTER'} ROLE ${login} ${options} PASSWORD '${password}'`);
    }
    const database = await client.unsafe('SELECT 1 FROM pg_database WHERE datname = $1', [name]);
    if (database.length === 0) await client.unsafe(`CREATE DATABASE ${name}`);
} finally {
    await client.end();
}
