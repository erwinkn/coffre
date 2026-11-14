#!/usr/bin/env node
// Start the local stack's database over: drop it, so that dev/start.sh makes
// it again and migrates it from nothing. It runs before the stack starts,
// which also forgets every Worker's local storage, the signer's included: the
// signer keeps the log's head beside the database, so the two start over
// together or not at all: a signer that
// has signed an entry refuses to adopt a new database (docs/design/0.16.md,
// "Going back").
import { postgresSession } from '@coffre/db/connect';
import { loadLocalSeedConfig } from './seed-config.mjs';

const url = new URL(loadLocalSeedConfig(process.env).databaseUrl);
// A local `coffre…` name: loadLocalSeedConfig refuses any other.
const name = url.pathname.slice(1);
url.pathname = '/postgres';
const client = postgresSession(url.href);
try {
    // Not WITH (FORCE): a database someone is connected to, another checkout's stack on the shared `coffre`, say, is theirs.
    await client.unsafe(`DROP DATABASE IF EXISTS ${name}`);
} catch (error) {
    if (error?.code !== '55006') throw error;
    console.error(`ERROR: ${name} is in use, by another stack or a client: stop it, or run this one on a database of its own (COFFRE_DEV_DATABASE)`);
    process.exitCode = 1;
} finally {
    await client.end();
}
