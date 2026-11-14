#!/usr/bin/env node
// Start the local stack's database over, and keep it the stack's while it
// runs. It drops the database, so that dev/start.sh makes it again and
// migrates it from nothing; dev/start.sh also forgets every Worker's local
// storage, the signer's included: the signer keeps the log's head beside the
// database, so the two start over together or not at all (docs/design/0.16.md,
// "Going back").
//
// A stack that sits idle holds no connection to its database, so another
// checkout's `pnpm dev` on the same name could drop it under that stack's
// signer. So this takes a lock named for the database first, and holds it
// until dev/start.sh stops it: it prints `reset` once the database is gone,
// then waits. A second stack on the same database is refused.
import { postgresSession } from '@coffre/db/connect';
import { loadLocalSeedConfig } from './seed-config.mjs';

const url = new URL(loadLocalSeedConfig(process.env).databaseUrl);
// A local `coffre…` name: loadLocalSeedConfig refuses any other.
const name = url.pathname.slice(1);
url.pathname = '/postgres';
const client = postgresSession(url.href);
const refuse = async (message) => {
    console.error(`ERROR: ${message}`);
    await client.end();
    process.exit(1);
};

const [{ held }] = await client.unsafe('SELECT pg_try_advisory_lock(hashtext($1)) AS held', [`coffre dev ${name}`]);
if (!held) await refuse(`another stack runs on ${name}: stop it, or run this one on a database of its own (COFFRE_DEV_DATABASE)`);
try {
    // Not WITH (FORCE): a database someone is connected to is theirs.
    await client.unsafe(`DROP DATABASE IF EXISTS ${name}`);
} catch (error) {
    if (error?.code !== '55006') throw error;
    await refuse(`${name} is in use by a client: disconnect it, or run this stack on a database of its own (COFFRE_DEV_DATABASE)`);
}
console.log('reset');

// Held until dev/start.sh stops this, or dies without stopping it.
const parent = process.ppid;
const release = async () => {
    await client.end();
    process.exit(0);
};
process.on('SIGTERM', release);
process.on('SIGINT', release);
setInterval(() => process.ppid !== parent && release(), 1000);
