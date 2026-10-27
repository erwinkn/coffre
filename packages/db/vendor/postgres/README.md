# postgres.js, Coffre's copy

[postgres.js](https://github.com/porsager/postgres) 3.4.9 (npm tarball
`sha512-GD3qdB0x1z9xgFI6cdRD6xu2Sp2WCOEoe3mtnyB5Ee0XrrL5Pe+e4CCnJrRMnL1zYtRDZmQQVbvOttLnKDLnaw==`,
commit `e7dfa14519f363229ccc3ead7b1b2f2051937efb`), released under the
Unlicense (`UNLICENSE`). Coffre owns this copy: `src/` is the Node entry,
`cf/` the workerd one (`#postgres` in `@coffre/db`'s `package.json`), and
`types/` their declarations.

Seven changes from upstream, each marked `Coffre:` in the code:

- **One round trip per statement** (`typedByServer`, in both `connection.js`).
  Upstream asks the server for an unnamed statement's parameter types (Parse,
  Describe, Flush) and waits for them before it sends the values (Bind,
  Execute, Sync), which doubles the round trips of every query with parameters
  that Drizzle sends. Here the values go with the statement, as text the server
  types, as node-postgres sends them, unless one is an object postgres.js has
  no type for (an array is typed by its first element, so `[true]` is sent
  as a boolean: `postgresClient` sends arrays as their text before the
  driver sees them) (porsager/postgres#1225). `postgresClient`
  (`packages/db/src/postgres.ts`) sends arrays, dates and objects as text, so none is.
- **A transaction's BEGIN always learns its connection** (`execute`, in both
  `connection.js`). Upstream told `begin()` which connection its BEGIN went
  to only when more statements could follow it there, so a BEGIN queued
  behind `max_pipeline` statements, or written to a full socket, left
  `begin()` without its connection, and the connection inside a transaction
  no one would end.
- **A connection closed while it opens fails its query** (`closed`, in
  both `connection.js`), as node-postgres's "Connection terminated
  unexpectedly" did. Upstream dialled again, at once and for ever (thousands
  of dials a second), the query never answering; its retry was for the next
  of several hosts, which coffre never names (`postgresOptions` refuses
  them).
- **A query cut short by its connection's close leaves it** (`closed`, in
  both `connection.js`). Upstream rejected the query but kept it as the
  connection's, so `end()` waited for it to answer, for ever, unless another
  query opened the connection again: a Worker call whose connection was cut
  under a query, then closed (`HyperdrivePool.end`), hung until Cloudflare
  cancelled it. Likewise an `end()` asked while the connection opened or
  answered: the connection's close ends it.
- **An ending client opens no connection again** (`onclose`, in both
  `index.js`). Upstream opened a closed connection again for a query still
  waiting for one, even once `end()` had been asked, and answered: that
  connection outlived the client's end, which no other `end()` could close.
  Those queries fail, `CONNECTION_ENDED`, as any asked after `end()` does,
  and so do a `reserve()` and a `listen()` (in `index.js`); a connection
  reserved before `end()` and released after it closes, which `end()` waits
  for, where upstream gave it back to the pool.
- **A `reserve()` that opens its connection gets it** (`ReadyForQuery`, in
  both `connection.js`). Upstream handed it over after `fetch_types`'s own
  query, so without `fetch_types`, as coffre opens every client, a
  `reserve()` on a pool with no connection open waited for ever.
- **The pool takes the connection idle the shortest** (`Queue.pop`, in both
  `queue.js` and `index.js`), as pg-pool does. Upstream takes the one idle the
  longest, so a steady load cycles every connection of the pool and each
  backend's caches stay cold: Postgres spent ~8% more CPU per use at a pool of
  16 (`packages/db/test/pool.test.ts`).
