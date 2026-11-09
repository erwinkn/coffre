// The guard of T245's class of reads (R48): every read at run time that asks the audit log for the newest entries of a
// kind, its first, or a page back by `seq` (an `ORDER BY seq … LIMIT`, or its greatest or least `seq`), and every read
// of an object's newest changes in 0.15's log, is one a test holds to the same cost however long the run of other
// entries since: the vault's and the database's in `packages/vault/test/newest-lookups.test.ts`,
// the server's in `packages/server/test/newest-lookups.test.ts`, each against a run of its kind then a long tail of
// others. Postgres prices a walk back by `seq` with the rest as a filter as the one row it expects to meet first,
// whenever its statistics hold the kind common, and that walk read every entry since: 641 pages for the newest
// rotation behind 20,000 checkpoints. A new read of the kind fails here until it is listed, with the test that holds
// it, or why it needs none. A read of an object's changes goes through `changesOf` (access-entries.ts) on Postgres, or
// is SQLite's alone: asked plainly, Postgres walked the primary key back past every other object's changes, 441 pages
// behind 20,000 of another's. The database's functions' own are the vault's test's to list and hold.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../../', import.meta.url));

const VAULT = 'packages/vault/test/newest-lookups.test.ts';
const SERVER = 'packages/server/test/newest-lookups.test.ts';

/**
 * Each place in the sources that reads so (`file#function`, then `#2`… for a second in the same function): the test
 * that holds it, and the name that test asks it by; or why none needs to.
 */
const SITES: Record<string, { by: typeof VAULT | typeof SERVER; as: string } | { none: string }> = {
  'packages/db/src/grants.ts#accessEntries': { by: VAULT, as: 'newestAccess' },
  'packages/db/src/grants.ts#tamperReportsAbout': { by: VAULT, as: 'reportStands' },
  'packages/db/src/log.ts#vaultEntries': { by: VAULT, as: 'newestVaultEntries' },
  'packages/db/src/log.ts#newestSeqQuery': { by: VAULT, as: 'newestVaultSeq' },
  'packages/vault/src/store.ts#newestOf': { by: VAULT, as: 'latestRotation' },
  'packages/vault/src/store.ts#newestAccessSeq': { by: VAULT, as: 'memberLogs' },
  'packages/vault/src/store.ts#vaultPage': { by: VAULT, as: 'vaultPage' },
  'packages/vault/src/store.ts#keyChecks': { by: VAULT, as: 'keyChecks' },
  'packages/vault/src/store.ts#talliedAfter': { by: VAULT, as: 'talliedAfter' },
  'packages/vault/src/snapshot.postgres.ts#snapshotQuery': { by: VAULT, as: 'snapshot' },
  'packages/vault/src/snapshot.postgres.ts#snapshotQuery#2': { by: VAULT, as: 'snapshot' },
  'packages/vault/src/snapshot.postgres.ts#snapshotQuery#3': { by: VAULT, as: 'snapshot' },
  'packages/vault/src/snapshot.postgres.ts#snapshotQuery#4': { by: VAULT, as: 'snapshot' },
  'packages/vault/src/snapshot.postgres.ts#snapshotQuery#5': { by: VAULT, as: 'snapshot' },
  'packages/vault/src/snapshot.sqlite.ts#snapshotQuery': { by: VAULT, as: 'snapshot' },
  'packages/vault/src/snapshot.sqlite.ts#snapshotQuery#2': { by: VAULT, as: 'snapshot' },
  'packages/vault/src/snapshot.sqlite.ts#snapshotQuery#3': { by: VAULT, as: 'snapshot' },
  'packages/vault/src/snapshot.sqlite.ts#snapshotQuery#4': { by: VAULT, as: 'snapshot' },
  'packages/vault/src/snapshot.sqlite.ts#snapshotQuery#5': { by: VAULT, as: 'snapshot' },
  'packages/server/src/db/answers.ts#newest': { by: SERVER, as: 'policySeqAndSettings' },
  'packages/server/src/db/queries.ts#newestSigned': { by: SERVER, as: 'latestCheckpoint' },
  'packages/server/src/db/queries.ts#talliedAfter': { by: SERVER, as: 'talliedAfter' },
  'packages/server/src/db/rotation.ts#newestMove': { by: SERVER, as: 'newestMove' },
  'packages/db/src/log.ts#firstEntryUnder': { by: VAULT, as: 'firstVaultEntryUnder' },
  'packages/server/src/db/rotation.ts#newestAppEntry': { by: SERVER, as: 'newestAppEntry' },
  // A workload's session's freezes: the statement `sign_in` reads (`audit_log_frozen_idx`), a column its target, which
  // the vault's test holds as the functions' `freeze`.
  'packages/server/src/db/workloads.ts#frozen': { by: SERVER, as: 'frozenTargets' },
  'packages/server/src/db/workloads.ts#frozen#2': { by: SERVER, as: 'frozenTargets' },
  'packages/server/src/db/queries.ts#memberAccess': { by: SERVER, as: 'memberAccess' },
  // A member's tamper reports of either kind, by `audit_log_tamper_idx` (`reportsAbout`): the newest of 0.14's beside a
  // statement's other reads.
  'packages/db/src/grants.ts#findingsOf': { by: VAULT, as: 'findingsOf' },
  // Over all of a kind's history at once, which T248 bounds (Sol r6 of #556, items 5 and 6): every member's findings,
  // and every member's newest access entry, a pass over the vault (its start on 0.14's log alone, a cutover).
  'packages/db/src/grants.ts#tamperedMembers': { none: "every member's findings, grouped: T248" },
  'packages/db/src/grants.ts#tamperedMembers#2': { none: "the newest access entry of each member with 0.14's findings, grouped: T248" },
  'packages/vault/src/store.ts#newestAccessEntries': { none: "every member's newest access entry, grouped, a pass over the vault: T248" },
  'packages/server/src/db/audit.ts#appVerifier': { none: "the first of the app's moves from each previous key, grouped: the moves alone, a few for each change of key" },
  'packages/db/src/log.ts#underHead': { none: 'the newest entry of all: the primary key\'s first step, with nothing to filter' },
  'packages/db/src/log.ts#missingEntry': { none: 'the first entry after a gap, by the primary key, with nothing to filter' },
  'packages/db/src/log.ts#withinBytes': { none: "a batch's bounds by its caller's condition, read forward from a point (`entriesFrom`, `vaultEntriesAfter`, `talliedWithin`) or the audit page's (`auditPage`)" },
  'packages/db/src/log.ts#streamsOf': { by: SERVER, as: 'auditPage' },
  'packages/vault/src/store.ts#entriesFrom': { none: 'a batch of the chain from an entry on, by the primary key, with nothing to filter' },
  // The audit page: by actor a stream of each one's through `audit_log_actor_idx` (`withinBytes`' `by`), held by the
  // server's test; its other filters a search, a page at a time, which T248 bounds with its counts.
  'packages/server/src/db/queries.ts#auditPage': { by: SERVER, as: 'auditPage' },
  // SQLite's own credential reads: kept for tests and local development, no deployment runs on it (AGENTS.md). Each
  // reads the policy by the same condition and index as Postgres's functions (`entriesOf('policy')`), or a binding's freeze.
  'packages/vault/src/credentials.sqlite.ts#signInOnSqlite': { none: "SQLite's sign-in: a binding's newest freeze, no deployment's engine" },
  'packages/vault/src/credentials.sqlite.ts#revokeOnSqlite': { none: "SQLite's revoke: the newest policy (`entriesOf('policy')`), no deployment's engine" },
  'packages/vault/src/credentials.sqlite.ts#issueOnSqlite': { none: "SQLite's issue: the newest policy (`entriesOf('policy')`), no deployment's engine" },
  'packages/vault/src/credentials.sqlite.ts#bindingsOnSqlite': { none: "SQLite's bindings: the newest policy (`entriesOf('policy')`), no deployment's engine" },
  'packages/vault/src/use.sqlite.ts#readRoute': { none: "SQLite's use: a member's newest access entry (`accessAllowed`), no deployment's engine" },
  'packages/vault/src/use.sqlite.ts#useOnce': { none: "SQLite's use: a member's newest access entry (`accessAllowed`), no deployment's engine" },
};

/**
 * Each read of an object's newest changes in 0.15's log through `changesOf`, by the function it is in: the test that
 * holds it. `changesOf` itself, its shape of a value, of `log_object(…)` and of a column beside, is the vault's test's.
 */
const CHANGES: Record<string, { by: typeof VAULT | typeof SERVER; as: string }> = {
  'packages/db/src/grants.ts#newestNamed': { by: VAULT, as: 'newestChangeNames' },
  'packages/vault/src/store.ts#newestChange': { by: VAULT, as: 'newestChange' },
  'packages/vault/src/store.ts#loggedChangesQuery': { by: VAULT, as: 'loggedChanges' },
  'packages/vault/src/store.ts#memberLogsPostgres': { by: VAULT, as: 'memberLogs' },
  'packages/vault/src/snapshot.postgres.ts#MEMBER_CHANGE': { by: VAULT, as: 'snapshot' },
  // Held by the shape alone, each of a value, `log_object(…)` or a column beside (the vault's `changesOf` case).
  'packages/vault/src/store.ts#newestSeal': { by: VAULT, as: 'changesOf' },
  'packages/vault/src/store.ts#newestChangeJson': { by: VAULT, as: 'changesOf' },
  'packages/vault/src/store.ts#loggedEnvironments': { by: VAULT, as: 'changesOf' },
  'packages/vault/src/store.ts#roleRows': { by: VAULT, as: 'changesOf' },
  'packages/vault/src/store.ts#issuingCredential': { by: VAULT, as: 'changesOf' },
  'packages/vault/src/snapshot.postgres.ts#PLACE_CHANGE': { by: VAULT, as: 'changesOf' },
  'packages/vault/src/log-store.ts#postgresStore': { by: VAULT, as: 'changesOf' },
  'packages/vault/src/log-store.ts#readsStore': { by: VAULT, as: 'changesOf' },
  'packages/server/src/db/queries.ts#newestChangeColumns': { by: VAULT, as: 'changesOf' },
};

/**
 * Each read of an object's newest change asked plainly, by the function it is in: SQLite's alone, whose planner takes
 * the object's index (none deploys on it, AGENTS.md). Postgres's go through `changesOf`.
 */
const SQLITE_CHANGES = new Set([
  'packages/db/src/log.ts#changeOnSqlite',
  'packages/server/src/db/queries.ts#newestChanges',
  'packages/vault/src/credentials.sqlite.ts#signInOnSqlite',
  'packages/vault/src/credentials.sqlite.ts#revokeOnSqlite',
  'packages/vault/src/credentials.sqlite.ts#issueOnSqlite',
  'packages/vault/src/credentials.sqlite.ts#bindingsOnSqlite',
  'packages/vault/src/log-store.ts#sqliteStore',
  'packages/vault/src/store.ts#newestChangesQuery',
  'packages/vault/src/store.ts#newestSealsQuery',
  'packages/vault/src/store.ts#memberLogsSqlite',
  'packages/vault/src/use.sqlite.ts#readRoute',
  'packages/vault/src/use.sqlite.ts#CHUNK',
  'packages/vault/src/use.sqlite.ts#useOnce',
]);

/** The sources of the packages that run (core, db, vault, server), each with its text. */
function sources(): { file: string; text: string }[] {
  return execFileSync('git', ['ls-files', 'packages/core/src/**.ts', 'packages/db/src/**.ts', 'packages/vault/src/**.ts', 'packages/server/src/**.ts'], { cwd: ROOT, encoding: 'utf8' })
    .trim().split('\n').map((file) => ({ file, text: readFileSync(`${ROOT}${file}`, 'utf8') }));
}

/** The top-level function (or constant) that `at` in `text` is in. */
function within(text: string, at: number): string {
  const found = [...text.slice(0, at).matchAll(/^(?:export )?(?:async )?(?:function\s+(\w+)|const\s+(\w+)\s*=)/gm)].pop();
  return found?.[1] ?? found?.[2] ?? '(top)';
}

/** The table a statement at `at` reads, the last named before it: the audit log or 0.15's changes. */
function tableAt(text: string, at: number): 'audit' | 'changes' | null {
  const named = [...text.slice(Math.max(0, at - 700), at).matchAll(/\b(audit_log|auditLog|log_changes|logChanges)\b/g)].pop()?.[1];
  return named === undefined ? null : /audit/i.test(named) ? 'audit' : 'changes';
}

/**
 * Each place in the sources that orders the audit log by `seq` and takes a few: a Drizzle `orderBy(…seq)`, a
 * statement's `ORDER BY seq … LIMIT` (`${auditLog.seq}` too, or after a key), an order by a key then `seq` (`keyedBy`,
 * or an order a helper wrote, `${about.order}`), or its greatest or least `seq`; within a statement that names the
 * audit log, by the top-level function it is in, then `#2`… for a second in the same function.
 */
function sites(): string[] {
  const found: string[] = [];
  for (const { file, text } of sources()) {
    const seen = new Map<string, number>();
    const orders = /orderBy\((?:[^()]|\([^()]*\))*\b(?:asc|desc)\(\w+\.seq\)|keyedBy\(db\b|orderBy\(\w+\.order\)|ORDER BY \$\{\w+\.order\}|ORDER BY (?:(?:\$\{\w+\}|[\w.]+)(?: DESC| ASC)?, )?(?:\w+\.|\$\{\w+\.)?seq\}?(?: DESC| ASC)?(?=\s+LIMIT|`)|\b(?:max|min)\((?:\$\{\w+\.seq\}|(?:\w+\.)?seq)\)/g;
    for (const order of text.matchAll(orders)) {
      if (tableAt(text, order.index + (/^(max|min)/.test(order[0]) ? 200 : 0)) !== 'audit') continue;
      if (/^(?:ORDER|orderBy)/.test(order[0]) && !/limit/i.test(text.slice(order.index, order.index + order[0].length + 120))) continue;
      // A comment's words, not a statement.
      if (/^\s*(?:\/\/|\*)/.test(text.slice(text.lastIndexOf('\n', order.index) + 1, order.index))) continue;
      const site = `${file}#${within(text, order.index)}`;
      const nth = (seen.get(site) ?? 0) + 1;
      seen.set(site, nth);
      found.push(nth === 1 ? site : `${site}#${nth}`);
    }
  }
  return found;
}

/**
 * Each read of an object's newest (or oldest) changes in the sources, by the function it is in: through `changesOf`
 * (`keyed`), or asked plainly, `object = … ORDER BY number`, Drizzle's `eq(logChanges.object, …)` then
 * `desc(logChanges.number)`, or the greatest or least number of an object's (`plain`).
 */
function changeSites(): { keyed: string[]; plain: string[] } {
  const keyed = new Set<string>();
  const plain = new Set<string>();
  for (const { file, text } of sources()) {
    if (file === 'packages/db/src/access-entries.ts') continue;
    for (const use of text.matchAll(/\bchangesOf\(/g)) keyed.add(`${file}#${within(text, use.index)}`);
    const asked = /\.object\s*=\s*(?:(?!ORDER BY|`).)*?ORDER BY [\w.]*number|eq\(logChanges\.object,[^\n]*\n?[^\n]*orderBy\(desc\(logChanges\.number\)\)|\b(?:max|min)\(\w*\.?number\)\s+FROM log_changes \w*\s*WHERE \w*\.?object\s*=/g;
    for (const read of text.matchAll(asked)) plain.add(`${file}#${within(text, read.index)}`);
  }
  return { keyed: [...keyed], plain: [...plain] };
}

test('every read of the newest entries of a kind in the sources is listed, with the test that holds it to a flat cost, or why none needs one (T245, R48)', () => {
  const found = sites();
  assert.deepEqual(found.filter((site) => !(site in SITES)), [], 'a read the list does not name: list it with its test, which seeds a run of its kind then a long tail of others');
  assert.deepEqual(Object.keys(SITES).filter((site) => !found.includes(site)), [], 'a site listed that no longer reads so');
  const tests = new Map([VAULT, SERVER].map((file) => [file, readFileSync(`${ROOT}${file}`, 'utf8')]));
  for (const [site, held] of Object.entries(SITES)) {
    if ('as' in held) assert.match(tests.get(held.by)!, new RegExp(`\\b${held.as}\\b`), `${site}: ${held.by} asks ${held.as}`);
  }
});

test("every read of an object's newest changes in the sources goes through `changesOf`, held by a test, or is SQLite's (T245, R48)", () => {
  const { keyed, plain } = changeSites();
  assert.deepEqual(plain.filter((site) => !SQLITE_CHANGES.has(site)), [], 'a read of an object\'s changes asked plainly on Postgres: ask it through `changesOf`');
  assert.deepEqual([...SQLITE_CHANGES].filter((site) => !plain.includes(site)), [], 'a SQLite read listed that no longer reads so');
  assert.deepEqual(keyed.filter((site) => !(site in CHANGES)), [], 'a read through `changesOf` the list does not name: list it with its test');
  assert.deepEqual(Object.keys(CHANGES).filter((site) => !keyed.includes(site)), [], 'a site listed that no longer reads so');
  const vault = readFileSync(`${ROOT}${VAULT}`, 'utf8');
  for (const [site, held] of Object.entries(CHANGES)) assert.match(held.by === VAULT ? vault : readFileSync(`${ROOT}${SERVER}`, 'utf8'), new RegExp(`\\b${held.as}\\b`), `${site}: ${held.by} asks ${held.as}`);
});
