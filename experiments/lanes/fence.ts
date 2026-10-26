// The revision fence under READ COMMITTED (W201), deterministically, in a
// scratch database: a use read revision 0, then its append starts while a
// change holds the lock; the change raises the revision to 1 and commits;
// then the append gets the lock. The append must write nothing. Four
// appends, each the moment Postgres shows it waiting for the lock (pg_locks),
// not after a sleep:
//
//   head, revision in another table   the brief's example: `WHERE (SELECT n FROM revision) = $rev`. Writes (wrong).
//   head, revision in the head row    simple.ts's APPEND_HEAD: the lock re-reads the row. Writes nothing.
//   seq, check in the lock's statement  one statement takes the shared lock and checks: its snapshot is older. Writes (wrong).
//   seq, append_use                   simple.ts: the check is a statement of its own, after the lock's. Writes nothing.
//
//   node experiments/lanes/fence.ts --url postgresql://user:password@host:port/db (a server where a scratch database may be made)
import { parseArgs } from 'node:util';

import pg from 'pg';

const { values } = parseArgs({ options: { url: { type: 'string' } } });
if (values.url === undefined) throw new Error('--url names a database on the server to use');
const scratch = new URL(values.url);
scratch.pathname = '/w201_fence';

const admin = new pg.Client({ connectionString: values.url });
await admin.connect();
await admin.query('DROP DATABASE IF EXISTS w201_fence');
await admin.query('CREATE DATABASE w201_fence');

const SCHEMA = `
  CREATE TABLE head (only_row boolean PRIMARY KEY, next_seq int NOT NULL, revision int NOT NULL);
  CREATE TABLE revision (n int NOT NULL);
  CREATE TABLE audit (seq int, revision int);
  CREATE FUNCTION append_use(p_seq int, p_revision int) RETURNS boolean LANGUAGE plpgsql AS $$
  BEGIN
    PERFORM pg_advisory_xact_lock_shared(201);
    IF NOT EXISTS (SELECT 1 FROM head WHERE only_row AND revision = p_revision) THEN RETURN false; END IF;
    INSERT INTO audit VALUES (p_seq, p_revision);
    RETURN true;
  END $$;`;

type Case = { name: string; lock: string; change: string; append: string; correct: boolean };
const CASES: Case[] = [
  {
    name: 'head, revision in another table', correct: false,
    lock: 'SELECT 1 FROM head WHERE only_row FOR UPDATE', change: 'UPDATE revision SET n = 1; UPDATE head SET next_seq = next_seq + 1',
    append: `WITH h AS (SELECT next_seq FROM head WHERE only_row FOR UPDATE) INSERT INTO audit SELECT h.next_seq, 0 FROM h WHERE (SELECT n FROM revision) = 0 RETURNING seq`,
  },
  {
    name: 'head, revision in the head row', correct: true,
    lock: 'SELECT 1 FROM head WHERE only_row FOR UPDATE', change: 'UPDATE head SET revision = 1, next_seq = next_seq + 1',
    append: `WITH h AS (SELECT next_seq FROM head WHERE only_row AND revision = 0 FOR UPDATE) INSERT INTO audit SELECT h.next_seq, 0 FROM h RETURNING seq`,
  },
  {
    name: "seq, check in the lock's statement", correct: false,
    lock: 'SELECT pg_advisory_xact_lock(201)', change: 'UPDATE head SET revision = 1',
    append: `INSERT INTO audit SELECT 7, 0 WHERE pg_advisory_xact_lock_shared(201) IS NOT NULL AND EXISTS (SELECT 1 FROM head WHERE only_row AND revision = 0) RETURNING seq`,
  },
  {
    name: 'seq, append_use', correct: true,
    lock: 'SELECT pg_advisory_xact_lock(201)', change: 'UPDATE head SET revision = 1',
    append: `SELECT append_use(7, 0)`,
  },
];

let wrong = 0;
try {
  const setup = new pg.Client({ connectionString: scratch.toString() });
  await setup.connect();
  await setup.query(SCHEMA);
  for (const c of CASES) {
    await setup.query('TRUNCATE head, revision, audit; INSERT INTO head VALUES (true, 1, 0); INSERT INTO revision VALUES (0)');
    const change = new pg.Client({ connectionString: scratch.toString() });
    const use = new pg.Client({ connectionString: scratch.toString() });
    await Promise.all([change.connect(), use.connect()]);
    const { rows: [{ pid }] } = await use.query('SELECT pg_backend_pid() AS pid');
    await change.query('BEGIN');
    await change.query(c.lock);
    // The use's append starts now, its snapshot from before the change commits; it waits for the lock.
    const appended = use.query(c.append);
    for (;;) {
      const { rows: [w] } = await setup.query('SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid = $1 AND NOT granted) AS waiting', [pid]);
      if (w.waiting) break;
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    await change.query(c.change);
    await change.query('COMMIT');
    await appended;
    const { rows: [{ n }] } = await setup.query('SELECT count(*)::int AS n FROM audit');
    const holds = n === 0;
    if (holds !== c.correct) wrong += 1;
    console.log(`${c.name.padEnd(36)} the append ${holds ? 'wrote nothing' : `wrote ${n} entry after the change committed revision 1`}${holds === c.correct ? '' : '  UNEXPECTED'}`);
    await Promise.all([change.end(), use.end()]);
  }
  await setup.end();
} finally {
  await admin.query('DROP DATABASE IF EXISTS w201_fence WITH (FORCE)');
  await admin.end();
}
process.exitCode = wrong === 0 ? 0 : 1;
