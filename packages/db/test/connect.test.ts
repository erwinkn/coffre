import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, isIP } from 'node:net';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ConnectionOptions } from 'node:tls';
import { sql, type SQL } from 'drizzle-orm';

import { engineOfUrl, openDatabase, postgresClient, postgresOptions, writes } from '../src/connect.ts';
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

/** The SQLite statements a test runs, on the database or a transaction. */
type Lite = { run(query: SQL): Promise<unknown>; all<Row>(query: SQL): Promise<Row[]> };

test("on SQLite, a lone write while a transaction holds the file's lock waits its turn, rather than blocking the thread and failing", async () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-sqlite-'));
  const { db, close } = await openDatabase(`file:${join(dir, 'queue.db')}`);
  const lite = db as unknown as Lite;
  try {
    await lite.run(sql`CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER NOT NULL)`);
    await lite.run(sql`INSERT INTO t VALUES (1, 0)`);
    let opened!: () => void;
    const open = new Promise<void>((resolve) => (opened = resolve));
    let commit!: () => void;
    const held = new Promise<void>((resolve) => (commit = resolve));
    const transaction = db.transaction(async (tx) => {
      await (tx as unknown as Lite).run(sql`INSERT INTO t VALUES (2, 0)`);
      opened();
      await held;
    });
    await open;
    const started = Date.now();
    // Asked while the transaction holds the lock, which commits only once a timer has run: a write that waited for
    // the lock itself would hold the thread, and the timer, until libsql's timeout failed it.
    const write = lite.run(sql`UPDATE t SET n = 1 WHERE id = 1`);
    setTimeout(commit, 20);
    await Promise.all([transaction, write]);
    assert.ok(Date.now() - started < 1_000, `the write took ${Date.now() - started} ms`);
    for (let read = 0; read < 4; read += 1) {
      assert.deepEqual(await lite.all(sql`SELECT id, n FROM t ORDER BY id`), [{ id: 1, n: 1 }, { id: 2, n: 0 }]);
    }
  } finally {
    await close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("SQLite's lone statements that may write are told from its queries by their words outside parentheses, strings and comments", () => {
  const reads = [
    'select "id" from "mcp_approvals" where "mcp_approvals"."id" = ?',
    '  -- a comment first\n  SELECT 1',
    '/* update */ VALUES (1)',
    'EXPLAIN QUERY PLAN SELECT 1',
    "WITH policy AS (SELECT * FROM audit_log WHERE action = 'update' LIMIT 1) SELECT json_object('deleted', 1)",
    'WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3) SELECT i FROM n',
    'with "delete" as materialized (select 1) select * from "delete"',
  ];
  const writing = [
    'update "mcp_connections" set "last_used_at" = ? where "mcp_connections"."id" = ?',
    'insert into "t" ("id") values (?) returning "id"',
    'DELETE FROM t',
    'REPLACE INTO t VALUES (1)',
    'WITH old AS (SELECT id FROM t) DELETE FROM t WHERE id IN (SELECT id FROM old)',
    'WITH old (id) AS NOT MATERIALIZED (SELECT 1) INSERT INTO t SELECT id FROM old',
    'PRAGMA journal_mode = WAL',
    'CREATE TABLE t (id INTEGER)',
    '',
  ];
  assert.deepEqual(reads.filter(writes), []);
  assert.deepEqual(writing.filter((statement) => !writes(statement)), []);
});

// Refusing SSL must stop before any startup packet or password reaches the server.
test('system CA URLs require TLS in Node connections and migrations', async () => {
  // What reaches the server after each SSLRequest, which it refuses: at most a TLS hello, never the login.
  const after: Buffer[] = [];
  const server = createServer((socket) => {
    socket.once('data', (request) => {
      assert.ok(Buffer.isBuffer(request));
      assert.equal(request.readInt32BE(0), 8);
      assert.equal(request.readInt32BE(4), 80877103);
      socket.on('data', (more: Buffer) => after.push(more));
      socket.end('N');
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = (server.address() as { port: number }).port;
  // postgres.js goes on to the TLS handshake, which the closed socket ends.
  const refused = /server does not support SSL|disconnected before secure TLS connection was established/i;
  try {
    for (const parameters of ['sslrootcert=system', 'sslrootcert=system&sslmode=verify-full', 'sslrootcert=system&sslmode=verify-full&uselibpqcompat=true']) {
      const url = `postgres://login-name:pass-word@127.0.0.1:${port}/coffre?${parameters}`;
      const connection = await openDatabase(url);
      try {
        await assert.rejects(connection.db.execute(sql`SELECT 1`), (error: { cause: Error }) => {
          assert.match(error.cause.message, refused);
          return true;
        });
      } finally {
        await connection.close();
      }
      await assert.rejects(migrateDatabase(url), refused);
    }
    const sent = Buffer.concat(after).toString('latin1');
    assert.ok(!sent.includes('login-name') && !sent.includes('pass-word'), 'the login reached a server that refused TLS');
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

/**
 * What postgres.js is given for each URL: TLS as node-postgres's
 * pg-connection-string reads `sslmode` (verified unless no-verify; libpq's
 * meanings with `uselibpqcompat=true`), the host checked against the URL's
 * own, an IP address included, and the query's parameters as pg reads them.
 */
test('connection URLs map to TLS as node-postgres reads them', () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-tls-'));
  try {
    for (const [name, text] of [['ca.pem', 'the CA'], ['cert.pem', 'the cert'], ['key.pem', 'the key']]) writeFileSync(join(dir, name), text);
    const ca = join(dir, 'ca.pem');
    type Seen = false | 'none' | 'chain' | 'full';
    /** How `url` verifies the server, checked by asking its options about certificates for the URL's host and another. */
    const verifies = (url: string): Seen => {
      const { ssl, host } = postgresOptions(url) as { ssl: false | ConnectionOptions; host: string };
      if (ssl === false) return false;
      if (ssl.rejectUnauthorized === false) return 'none';
      assert.equal(ssl.rejectUnauthorized, true);
      const certificate = (name: string) => ({ subject: { CN: name }, subjectaltname: isIP(name) ? `IP Address:${name}` : `DNS:${name}` }) as never;
      const check = ssl.checkServerIdentity!;
      if (check('ignored', certificate('elsewhere.example')) === undefined) return 'chain';
      assert.equal(check('ignored', certificate(host)), undefined, `${url}: the URL's own host passes`);
      return 'full';
    };
    const cases: [string, Seen][] = [
      ['', false],
      ['?sslmode=disable', false],
      ['?sslmode=prefer', 'full'],
      ['?sslmode=require', 'full'],
      ['?sslmode=verify-ca', 'full'],
      ['?sslmode=verify-full', 'full'],
      ['?sslmode=no-verify', 'none'],
      ['?ssl=true', 'full'],
      ['?ssl=1', 'full'],
      ['?sslnegotiation=direct', 'full'],
      [`?sslrootcert=${ca}`, 'full'],
      ['?sslrootcert=system', 'full'],
      ['?sslmode=verify-full&sslrootcert=system', 'full'],
      ['?uselibpqcompat=true&sslmode=disable', false],
      ['?uselibpqcompat=true&sslmode=prefer', 'none'],
      ['?uselibpqcompat=true&sslmode=require', 'none'],
      [`?uselibpqcompat=true&sslmode=require&sslrootcert=${ca}`, 'chain'],
      [`?uselibpqcompat=true&sslmode=verify-ca&sslrootcert=${ca}`, 'chain'],
      ['?uselibpqcompat=true&sslmode=verify-full', 'full'],
    ];
    for (const host of ['db.example.com', '10.0.0.7']) {
      const seen = Object.fromEntries(cases.map(([query]) => [query, verifies(`postgresql://u:p@${host}:5432/coffre${query}`)]));
      assert.deepEqual(seen, Object.fromEntries(cases), host);
      // SNI names a host, never an IP address.
      const { ssl } = postgresOptions(`postgresql://u:p@${host}/coffre?sslmode=verify-full`) as { ssl: ConnectionOptions };
      assert.equal(ssl.servername, isIP(host) ? undefined : host);
    }
    // libpq's verify-ca needs a CA of its own: with a public one, anyone with a certificate from it passes.
    assert.throws(() => postgresOptions('postgresql://u:p@db.example.com/coffre?uselibpqcompat=true&sslmode=verify-ca'), /verify-ca requires a CA/);
    // Files are read, as pg reads them.
    const { ssl: files } = postgresOptions(`postgresql://u:p@db.example.com/coffre?sslmode=verify-full&sslrootcert=${ca}&sslcert=${join(dir, 'cert.pem')}&sslkey=${join(dir, 'key.pem')}`) as { ssl: ConnectionOptions };
    assert.deepEqual([files.ca, files.cert, files.key], ['the CA', 'the cert', 'the key']);
    const { ssl: system } = postgresOptions('postgresql://u:p@db.example.com/coffre?sslrootcert=system') as { ssl: ConnectionOptions };
    assert.equal(system.ca, undefined, "Node's trusted roots");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a URL's other parts are read as node-postgres reads them, and no query parameter reaches the server as a setting it does not know", () => {
  const options = postgresOptions('postgresql://us%40er:p%40ss@[::1]:6543/the%20db?application_name=coffre&options=-c%20jit%3Doff&uselibpqcompat=true&sslpassword=x&connect_timeout=3');
  assert.deepEqual(
    { host: options.host, port: options.port, user: options.user, pass: options.pass, database: options.database, connection: options.connection },
    { host: '::1', port: 6543, user: 'us@er', pass: 'p@ss', database: 'the db', connection: { application_name: 'coffre', options: '-c jit=off' } },
  );
  // A user or password in the query wins, as in pg-connection-string; one given empty does not.
  const overridden = postgresOptions('postgresql://u:p@db/coffre?user=other&password=secret');
  assert.deepEqual([overridden.user, overridden.pass], ['other', 'secret']);
  const empty = postgresOptions('postgresql://u:p@db:6000/coffre?user=&password=&host=&port=');
  assert.deepEqual([empty.user, empty.pass, empty.host, empty.port], ['u', 'p', 'db', 6000]);
  // libpq's bound on opening, in seconds; an encrypted key's passphrase.
  assert.equal(postgresOptions('postgresql://u@db/coffre?connect_timeout=7').connect_timeout, 7);
  assert.equal(postgresOptions('postgresql://u@db/coffre?connect_timeout=0').connect_timeout, 0);
  // What libpq refuses, or the driver cannot do, refused rather than read as something else.
  assert.throws(() => postgresOptions('postgresql://u@db/coffre?sslmode=verify-everything'), /sslmode is one of libpq's/);
  assert.throws(() => postgresOptions('postgresql://u@db/coffre?sslnegotiation=sideways'), /sslnegotiation is postgres or direct/);
  assert.throws(() => postgresOptions('postgresql://u@db/coffre?channel_binding=require'), /channel_binding=require is not supported/);
  assert.equal((postgresOptions('postgresql://u@db/coffre?sslmode=verify-full&sslpassword=key-pass').ssl as ConnectionOptions).passphrase, 'key-pass');
  // No user: named, rather than the operating system's taken.
  assert.throws(() => postgresOptions('postgresql:///coffre?host=/var/run/postgresql'), /names its user/);
  // node-postgres's own client-side bound, refused rather than ignored.
  assert.throws(() => postgresOptions('postgresql://u@db/coffre?query_timeout=5000'), /query_timeout is not supported/);
  // The URL's sslnegotiation reaches the driver, past the client's own defaults.
  const direct = postgresClient('postgresql://u:p@db.example.com/coffre?sslnegotiation=direct') as unknown as { options: { sslnegotiation: unknown }; end(): Promise<void> };
  assert.equal(direct.options.sslnegotiation, 'direct');
  void direct.end();
  // The bounds node-postgres sent the server as the connection starts.
  assert.deepEqual(postgresOptions('postgresql://u@db/coffre?statement_timeout=2000&lock_timeout=1000&idle_in_transaction_session_timeout=60000').connection, {
    statement_timeout: '2000', lock_timeout: '1000', idle_in_transaction_session_timeout: '60000',
  });
  // A socket directory as the host, its port the query's when it names one.
  assert.equal((postgresOptions('postgresql://u@/coffre?host=/var/run/postgresql') as { path?: string }).path, '/var/run/postgresql/.s.PGSQL.5432');
  assert.equal((postgresOptions('postgresql://u@/coffre?host=/var/run/postgresql&port=1234') as { path?: string }).path, '/var/run/postgresql/.s.PGSQL.1234');
  // The database's name decoded whole, as pg-connection-string decodes it.
  assert.equal(postgresOptions('postgresql://u@db/my%2Fdb%40x').database, 'my/db@x');
  // Several hosts, which node-postgres did not dial in turn either: said, rather than a TLS name no certificate matches.
  for (const url of ['postgresql://u:p@a.example.com,b.example.com/coffre', 'postgresql://u:p@a.example.com:1111,b.example.com:2222/coffre', 'postgresql://u:p@h/coffre?host=a.example.com,b.example.com']) {
    assert.throws(() => postgresOptions(url), /names one host/);
  }
  // A parse error, a malformed escape included, never prints the URL's password.
  for (const url of ['not a url: password', 'postgres://u%zz:password@h/db', 'postgres://u:password@h/d%zzb', 'postgres://u:password@h%zz/db', 'postgres://u:password@h/db?port=abc', 'postgres://u:password@h/db?port=70000']) {
    assert.throws(() => postgresOptions(url), (error: Error) => error.message === 'invalid Postgres URL');
  }
});
