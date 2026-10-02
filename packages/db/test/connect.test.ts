import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { sql } from 'drizzle-orm';

import { engineOfUrl, openDatabase } from '../src/connect.ts';
import { migrateDatabase } from '../src/migrate.ts';

test('MySQL URLs are refused before opening a connection or running migrations', async () => {
  const url = 'mysql://unused:unused@127.0.0.1:1/coffre';
  const error = { message: 'coffre supports Postgres; MySQL support was removed' };
  assert.throws(() => engineOfUrl(url), error);
  await assert.rejects(openDatabase(url), error);
  await assert.rejects(migrateDatabase(url), error);
});

test('Postgres and local SQLite URLs retain their database engines', () => {
  assert.equal(engineOfUrl('postgres://localhost/coffre'), 'postgres');
  assert.equal(engineOfUrl('postgresql://localhost/coffre'), 'postgres');
  assert.equal(engineOfUrl('file:coffre.db'), 'sqlite');
});

// Refusing SSL must stop before any startup packet or password reaches the server.
test('system CA URLs require TLS in Node connections and migrations', async () => {
  const server = createServer((socket) => {
    socket.once('data', (request) => {
      assert.ok(Buffer.isBuffer(request));
      assert.equal(request.readInt32BE(0), 8);
      assert.equal(request.readInt32BE(4), 80877103);
      socket.end('N');
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = (server.address() as { port: number }).port;
  try {
    for (const parameters of ['sslrootcert=system', 'sslrootcert=system&sslmode=verify-full', 'sslrootcert=system&sslmode=verify-full&uselibpqcompat=true']) {
      const url = `postgres://unused:unused@127.0.0.1:${port}/coffre?${parameters}`;
      const connection = await openDatabase(url);
      try {
        await assert.rejects(connection.db.execute(sql`SELECT 1`), (error: { cause: Error }) => {
          assert.match(error.cause.message, /server does not support SSL/i);
          return true;
        });
      } finally {
        await connection.close();
      }
      await assert.rejects(migrateDatabase(url), /server does not support SSL/i);
    }
  } finally {
    server.close();
    await once(server, 'close');
  }
});

test('system CA URLs refuse weaker TLS modes', async () => {
  for (const sslmode of ['disable', 'allow', 'prefer', 'require', 'verify-ca', 'no-verify']) {
    const url = `postgres://unused:unused@127.0.0.1:1/coffre?sslrootcert=system&sslmode=${sslmode}`;
    await assert.rejects(openDatabase(url), /sslrootcert=system requires sslmode=verify-full/);
    await assert.rejects(migrateDatabase(url), /sslrootcert=system requires sslmode=verify-full/);
  }
});
