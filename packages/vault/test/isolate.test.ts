// What an isolate keeps between calls. On Workers, every call to the vault
// opens a database of its own, and the isolate keeps one prepared vault for
// all of them. A call must never wait on work another call started: its
// I/O belongs to that call, and when that call is cancelled, as a page that
// navigates cancels its requests, the waiting call is cancelled too, as
// hung. So what the prepared vault keeps is settled values, and a call that
// finds nothing settled does its own reads.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createServer, type Socket } from 'node:net';

import { createDatabase } from '@coffre/db';
import pg from 'pg';

import { resolveVaultConfig } from '../src/config.ts';
import { openVault, prepareVault } from '../src/vault.ts';
import { emptyDatabase, openTestDatabase, places, postgresOnly, type TestDatabase } from './database.ts';

const ROOT = 'user:root@acme.example';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());
beforeEach(() => emptyDatabase(db.owner));

/** A database that takes the connection and never answers: a call's I/O that never completes. */
async function neverAnswers() {
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on('error', () => {});
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as { port: number };
  const pool = new pg.Pool({ connectionString: `postgresql://nobody:nothing@127.0.0.1:${port}/coffre` });
  pool.on('error', () => {});
  return {
    database: createDatabase(pool),
    /** Hang up, so that the stuck call fails and the test can end. */
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await pool.end().catch(() => {});
    },
  };
}

/** `work`, or a failure after `ms`: a call that waits on another's I/O never finishes. */
function within<T>(ms: number, work: Promise<T>): Promise<T> {
  return Promise.race([
    work,
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`still waiting after ${ms} ms: on another call's I/O`)), ms).unref()),
  ]);
}

function config() {
  return resolveVaultConfig({ kek: { id: 'vault-isolate-test', key: randomBytes(32).toString('base64') }, rootAdmins: ['root@acme.example'] });
}

test('a first call answers while another first call waits on its own I/O', postgresOnly('a database that never answers'), async () => {
  const prepared = await prepareVault(config());
  const stuck = await neverAnswers();
  // The isolate's first call: its database never answers, so whatever it starts never settles.
  const first = openVault(stuck.database, prepared).access(ROOT).catch(() => null);
  await new Promise((resolve) => setTimeout(resolve, 50));
  try {
    const access = await within(10_000, openVault(db.vault, prepared).access(ROOT));
    assert.equal(access.status, 'active');
  } finally {
    await stuck.close();
    await first;
  }
});

test("a first key operation answers while another waits on its own key check", postgresOnly('a database that never answers'), async () => {
  const placed = await places(db.owner);
  const [one, two] = [await placed.secret(placed.dev), await placed.secret(placed.dev)];
  const prepared = await prepareVault(config());
  // Settled once already: what is left to share is the key check before the first key operation.
  assert.equal((await openVault(db.vault, prepared).access(ROOT)).status, 'active');
  const stuck = await neverAnswers();
  const key = () => randomBytes(32).toString('base64');
  const first = openVault(stuck.database, prepared).wrap({ principal: ROOT, items: [{ secret: one, key: key() }] }).catch(() => null);
  await new Promise((resolve) => setTimeout(resolve, 50));
  try {
    const wrapped = await within(10_000, openVault(db.vault, prepared).wrap({ principal: ROOT, items: [{ secret: two, key: key() }] }));
    assert.ok(wrapped.ok, JSON.stringify(wrapped));
  } finally {
    await stuck.close();
    await first;
  }
});
