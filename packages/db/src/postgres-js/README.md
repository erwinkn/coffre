# postgres.js, Coffre's copy

[postgres.js](https://github.com/porsager/postgres) 3.4.9 (npm tarball
`sha512-GD3qdB0x1z9xgFI6cdRD6xu2Sp2WCOEoe3mtnyB5Ee0XrrL5Pe+e4CCnJrRMnL1zYtRDZmQQVbvOttLnKDLnaw==`,
commit `e7dfa14519f363229ccc3ead7b1b2f2051937efb`), released under the
Unlicense (`UNLICENSE`), in TypeScript. Coffre owns this copy, and keeps of
it what coffre uses. One tree runs on Node and on workerd: what differs, the
socket, TLS, hashes and a timer, is behind `#postgres/platform` (`@coffre/db`'s
`package.json`), `platform.node.ts` or `platform.workerd.ts` (upstream's
`cf/polyfills.js`), which both satisfy `platform.ts`.

| File | What |
| --- | --- |
| `index.ts` | The pool: `unsafe`, `begin` and its savepoints, `reserve`, `end`; its options |
| `connection.ts` | One connection: TLS, startup, authentication (SCRAM-SHA-256, MD5, cleartext), the extended and simple protocols |
| `query.ts` | A statement: a promise, sent once awaited or `execute`d; `.values()` for its rows as arrays |
| `result.ts` | Its rows, with `count`, `command` and `state` (the backend's pid and secret) |
| `types.ts` | The built-in parsers and serializers (text, numbers, JSON, booleans, dates, bytea) |
| `errors.ts`, `bytes.ts`, `queue.ts` | `PostgresError` and the driver's own errors, the message writer, the pool's queues |

## What is left out

What nothing in coffre reached: logical replication (`subscribe`), large
objects, COPY streams (a COPY a statement asks for fails, with an error that
says so), LISTEN/NOTIFY (a notification is dropped), cursors and `forEach`,
`fetch_types` and array types read from `pg_type` (`postgresClient` takes
Postgres's own as known), named prepared statements and their cache (every
statement is unnamed, as coffre sent them), `transform`, the tagged template
and its helpers (`sql\`…\``, `sql(rows)`, `sql.json`, `sql.typed`,
`sql.file`), two-phase commit (`prepare`), several hosts and
`target_session_attrs`, a statement's `cancel()`, and reading a URL and the
`PG*` environment: the driver takes an options object, every option given
or its default, and reads nothing from the environment (`postgresOptions`, in
`../postgres.ts`, reads the URL). A transaction's own statements, `begin`,
`savepoint`, `rollback` and `commit`, go as simple statements, where upstream
wrote them with its tagged template.

## Changes from upstream

Eleven, each marked `Coffre:` in the code:

- **One round trip per statement** (`typedByServer`, in `connection.ts`).
  Upstream asks the server for an unnamed statement's parameter types (Parse,
  Describe, Flush) and waits for them before it sends the values (Bind,
  Execute, Sync), which doubles the round trips of every query with parameters
  that Drizzle sends. Here the values go with the statement, as text the server
  types, as node-postgres sends them, unless one is an object postgres.js has
  no type for (an array is typed by its first element, so `[true]` is sent
  as a boolean: `postgresClient` sends arrays as their text before the
  driver sees them) (porsager/postgres#1225). `postgresClient`
  (`packages/db/src/postgres.ts`) sends arrays, dates and objects as text, so none is.
- **A transaction's BEGIN goes with its first statement** (`begin`, in
  `index.ts`; `toBuffer` and `CommandComplete`, in `connection.ts`), a round
  trip less for every transaction. Upstream sent BEGIN alone and waited for
  it. The two go under one Sync: as the extended protocol's Parse, Bind and
  Execute ahead of the statement's, or ahead of a group's when the work
  asked several together (below), or, for a lone statement without
  parameters, in one Query message (`begin;\n<statement>`). Either way, a
  BEGIN that fails has Postgres skip what went under its Sync, which so
  never runs outside its transaction; what waited behind it is not sent, nor anything the
  transaction asks after, which fails `TRANSACTION_NOT_BEGUN`, and nothing
  is rolled back. Nothing waits behind the BEGIN's statement for less: one
  the client failed to write (a value it cannot send) takes its BEGIN with
  it. A transaction that asks nothing sends nothing. It holds its
  connection from the start, as `reserve()` does, and gives it back once
  it has ended: upstream gave it back once Postgres said the connection
  was idle, which it also says after a BEGIN that failed. Its end is
  decided once its work has settled (`settle`): what the work left running
  asks from then on is refused, unsent (`TRANSACTION_ENDED`), as is what it
  asks once its connection closed (the close's error); the transaction
  then waits for every statement it asked to answer, and ends with a
  ROLLBACK if any failed, waited for or not, or if its work asked anything
  once settled (`TRANSACTION_UNFINISHED`: it would commit only part of
  it), else a COMMIT; and a COMMIT that Postgres answers with ROLLBACK (a
  savepoint's statement that failed once its savepoint's work had
  returned) fails it. A refused BEGIN's error names the BEGIN; a first
  statement's error its position in the statement. Upstream sent
  the COMMIT or ROLLBACK at once: a statement asked during it ran after it,
  outside the transaction, in autocommit, kept even when the transaction
  rolled back; and a statement that failed unwaited left a COMMIT, which
  Postgres answers with ROLLBACK, not an error, and upstream took for
  success. No ROLLBACK goes to a connection gone. A held
  connection asked to end meanwhile, its `max_lifetime` say, closes once
  given back (`release`, in `connection.ts`), and its socket draining
  never gives it to the pool (`drain`), as upstream's could, mid-transaction. Through Hyperdrive, the
  first statement reaches the pooler with its BEGIN, in one batch: the
  pooler keeps the connection for the transaction from the ReadyForQuery
  after it, which says so (`T`), and coffre's Hyperdrive configurations
  cache nothing (`docs/deploy.md`), so that statement is never answered
  from a cache. Both shapes reach the pooler: Parse, Bind and Execute under
  one Sync, and one Query message of two statements. Both were checked on
  a real Hyperdrive for 0.15, and again for T179's groups with
  `../../scripts/hyperdrive-pinning.ts` (below): `select pg_backend_pid()` as a transaction's
  first statement (with a parameter, and without, and after the vault's
  `SET LOCAL`) and again later in it, the same backend and transaction
  each time, over 11,000 transactions, 40 to 50 at once over 10 backends;
  what rolled back or failed kept nothing. A change to how they go is
  checked there again. Hyperdrive sends a client's Syncs on one at a
  time, each once the one before has answered: what costs a round trip
  there is a Sync, not a write, so `test/hyperdrive.test.ts` counts
  both. A first statement described first (Parse, Describe, Flush,
  then a wait) would reach Hyperdrive before any ReadyForQuery had pinned
  the connection, a flow Cloudflare says hangs under its pooling; coffre
  sends none (`postgresClient`), and none is supported there. This
  replaces PR A's fix for a BEGIN queued behind `max_pipeline` statements,
  which left `begin()` without its connection: a transaction now waits for
  a connection of its own instead.
- **Statements in a group go under one Sync** (`group`, in `index.ts`;
  `toBuffer`, `build` and `CommandComplete`, in `connection.ts`), a round
  trip for them all through a pooler that sends a client's Syncs on one at
  a time, as Hyperdrive does (`HyperdrivePool`'s `groupReads`, in
  `../hyperdrive.ts`). Each is its own Parse, Describe, Bind and Execute,
  its values sent with it; one Sync follows the last. The group is one
  query to the connection: each statement's rows are its own result,
  split at its CommandComplete, and the group answers once Postgres is
  ready again, every result at once. Postgres runs them as one implicit
  transaction, so if one fails it skips the rest, and the group fails with
  that error, naming the statement. A group holds plain reads alone
  (`select …`, `GROUP_NOT_READ` otherwise: a write grouped with a statement
  that fails would be rolled back by an error not its own; a `select` that
  writes through a function is not seen, and says so ahead of itself, as
  `/* writes */ select …`, which no group takes). A transaction groups
  its own statements (below). Upstream has no such thing; its pipelined
  statements each carry a Sync.
- **A transaction's statements asked together go under one Sync**
  (`gather`, `flush`, `together` and `settleWithCommit` in `index.ts`;
  `toBuffer` and `ReadyForQuery` in `connection.ts`). What its work asks
  in one task waits for the next (`nextTask`: Node's `setImmediate`, a
  timer of 0 on workerd), then goes as one group, in the order the
  statements were started (`Query.made`: awaited, `then` or `execute()`),
  not built, its BEGIN ahead of the first group. Drizzle starts a
  statement a microtask after it is asked for (it awaits the driver's), a
  builder once awaited, a `.then` at once (`prepared` in `../prepared.ts`
  runs one once awaited, as a builder does); `later` starts its own a
  microtask after it is called, as Drizzle does. So what must go first in
  a group is started first: `lockLogHeadRead` (`../log.ts`) starts the
  head's lock and its read with `.then`, ahead of a work's first `later`
  write.
  A statement the client cannot send in a group (a value only the server
  can type, one it cannot send) has each go alone, in order. If one fails,
  Postgres skips the rest: those before it answer with their rows
  (`Query.answered`), it fails with its error, and those after with
  "current transaction is aborted" (25P02), as each would have failed
  after it anyway, so the transaction fails as it did, rolled back, with
  the first error. The transaction's own statements (a savepoint, a
  rollback to one) go alone, after what was gathered before them. Its
  COMMIT goes with its work's last group when nothing awaits any statement
  of it (`Query.later`, which `later` in `../later.ts` sets), nothing sent
  before it that something awaits is still unanswered, and each can go in
  the group: work still running that awaits one must hear it answer
  first, and may then ask more, which is refused and rolls the
  transaction back, as before; and a statement that goes alone fails, if
  it does, where Postgres never hears of it. A statement of that group
  that fails has Postgres skip the COMMIT, and a group the client could
  not write never sent it: either way the transaction rolls back. Only a
  COMMIT Postgres ran and refused (a deferred constraint, `Query.refused`)
  has ended it, and no ROLLBACK follows. A statement of a group whose
  answer the client cannot read once Postgres ran it (a row a parser
  refuses, a COPY it does not take, `Query.unread`) fails alone, and the
  group reads on: with the COMMIT behind it, the transaction resolves, as
  Postgres committed it, and the statement's failure is that of an answer
  nothing awaited; awaited, it fails the transaction, which rolls back. Through Hyperdrive,
  which sends a client's Syncs on one at a time, a transaction that reads
  what it needs together and leaves its writes to `later` is two round
  trips, whatever it holds. Upstream sent each statement with a Sync of
  its own, and its COMMIT alone.
- **A connection closed while it opens fails its query** (`closed`, in
  `connection.ts`), as node-postgres's "Connection terminated
  unexpectedly" did. Upstream dialled again, at once and for ever (thousands
  of dials a second), the query never answering; its retry was for the next
  of several hosts, which coffre never names (`postgresOptions` refuses
  them).
- **A query cut short by its connection's close leaves it** (`closed`, in
  `connection.ts`). Upstream rejected the query but kept it as the
  connection's, so `end()` waited for it to answer, for ever, unless another
  query opened the connection again: a Worker call whose connection was cut
  under a query, then closed (`HyperdrivePool.end`), hung until Cloudflare
  cancelled it. Likewise an `end()` asked while the connection opened or
  answered: the connection's close ends it. And what the cut query's answer
  had left half read goes with it, its error, its row count, its results:
  upstream kept them, so the next query on the connection, opened again,
  failed with the dead one's error, and the one after answered its rows
  after the dead one's count, holes first.
- **An ending client opens no connection again** (`onclose`, in
  `index.ts`). Upstream opened a closed connection again for a query still
  waiting for one, even once `end()` had been asked, and answered: that
  connection outlived the client's end, which no other `end()` could close.
  Those queries fail, `CONNECTION_ENDED`, as any asked after `end()` does,
  and so does a `reserve()` (in `index.ts`); a connection reserved before
  `end()` and released after it closes, which `end()` waits for, where
  upstream gave it back to the pool.
- **A `reserve()` that opens its connection gets it** (`ReadyForQuery`, in
  `connection.ts`; `hold`, in `index.ts`). Upstream handed it over after
  `fetch_types`'s own query, so without `fetch_types`, as coffre opened
  every client, a `reserve()` on a pool with no connection open waited for
  ever. And upstream's reservation both waited in the pool's queue and
  opened a connection, which gave itself to the queue's first: one taken
  from the queue to open a connection again, after one closed, was no
  longer there, and waited for ever, as a transaction waiting for the
  connection its predecessor lost would have. A reservation now either
  waits or opens a connection, which is given to it.
- **The pool takes the connection idle the shortest** (`Queue.pop`, in
  `queue.ts` and `index.ts`), as pg-pool does. Upstream takes the one idle the
  longest, so a steady load cycles every connection of the pool and each
  backend's caches stay cold: Postgres spent ~8% more CPU per use at a pool of
  16 (`packages/db/test/pool.test.ts`).
- **An opening the client cannot finish fails its connection**
  (`openingFailed`, `secure`, `connected`, `createSocket` and
  `authenticate`, in `connection.ts`): its TLS (a key or certificate it
  cannot read), its startup, its sign-in (a hash that throws, a server's SCRAM
  message it cannot read, a method it has not: GSSAPI, SSPI, Kerberos), or a
  `socket` factory that throws (which backs off as a refused connection does)
  fails what waits for the connection and closes it, so that it opens again
  for the next query. Upstream left the error unhandled, which ends a Node
  process, or the connection opening until its `connect_timeout`, if any,
  every query after it waiting. A step of the opening that finishes once its
  socket has closed (on workerd, the server's answer to the SSLRequest and
  the hashes are promises, which can settle after the close) writes nothing
  and fails nothing: upstream went on with the connection opened again, or
  failed on its null socket.
- **A statement the client cannot write fails alone** (`execute`, in
  `connection.ts`): too many parameters, a value it cannot serialize.
  Nothing of it is sent; on an idle connection, a lone Sync answers it, so
  the connection goes on as after any answer. Upstream failed the statement
  already answering instead, and left this one waiting, its transaction and
  connection with it, for ever.

## Checking on a real Hyperdrive

Hyperdrive pools Postgres connections by transaction, telling where each
starts and ends from ReadyForQuery, and local workerd runs none, so no
suite holds the driver to it. A change to how a transaction reaches the
wire (its BEGIN, its groups, its COMMIT) is checked on Cloudflare first,
with `packages/db/scripts/hyperdrive-pinning.ts`:

1. `pnpm build`, then `node packages/db/scripts/hyperdrive-pinning.ts bundle <dir>`:
   the Worker of `hyperdrive-pinning.worker.ts`, the driver alone, minified (about 40 KiB).
2. A throwaway Postgres 16 (Debian, TLS) that only Cloudflare reaches (a
   Cloudflare Tunnel, behind an Access service token), a Hyperdrive
   configuration to it with caching off, and the Worker deployed with it
   bound as `HYPERDRIVE`.
3. `node packages/db/scripts/hyperdrive-pinning.ts run <worker url> --transactions 10000 --concurrency 50`.
4. Delete the Worker, the configuration, the tunnel, its DNS record, the
   Access application and token, and the database.

Each transaction is one of nine shapes, in turn: a first statement with a
parameter, without one, and after `SET LOCAL`; BEGIN with a group of
three, and with the vault's opening group (`SET LOCAL`, a row locked, a
read); reads together, then writes left to `later` with the COMMIT; a group
of which one statement fails; a write left to `later` that fails; and a
rollback. Every statement records its backend (`pg_backend_pid()`) and its
transaction (`txid_current()`), which must be one of each per transaction,
the writes' rows included; what failed or rolled back must keep no row.
T179 (PR 1): 10,800 transactions, 50 requests at once, on 60 backends, all held.

