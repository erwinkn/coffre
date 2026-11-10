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
// Two shapes more walk a log as far (Sol r8 of #556): an `EXISTS` gate over a log, which the vault's start asked of
// every rotation (4,741 pages past 40,000), and the least or greatest of a column of 0.15's uses, which the
// checkpointer's `lowestAbove` asks past every use sealed at the `at` a backlog shares (7,069 pages past 390,000). Each
// is listed too, with its test or why none needs one. And every aggregate over a log (T248): a count, a greatest or
// least, a `json_agg` or a `GROUP BY` reads every entry it aggregates, as every member's findings did (1,177 pages at
// 40,000 reports) and an audit page's count of what it hid (355 at 40,000 heartbeats), unless something bounds them.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../../', import.meta.url));

const VAULT = 'packages/vault/test/newest-lookups.test.ts';
const SERVER = 'packages/server/test/newest-lookups.test.ts';
const AGGREGATES_TEST = 'packages/server/test/history-aggregates.test.ts';

/**
 * Each place in the sources that reads so (`file#function`, then `#2`… for a second in the same function): the test
 * that holds it, and the name that test asks it by; or why none needs to.
 */
const SITES: Record<string, { by: typeof VAULT | typeof SERVER | typeof AGGREGATES_TEST; as: string } | { none: string }> = {
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
  // Whether a member no row names has an access entry: as an `EXISTS`, a scan past every refusal about them (review r8).
  'packages/server/src/db/queries.ts#missingMembers': { by: SERVER, as: 'missingMembers' },
  // A member's tamper reports of either kind, by `audit_log_tamper_idx` (`reportsAbout`): the newest of 0.14's beside a
  // statement's other reads (`findingsOf`), or each reported member's (`tamperedMembers`, T248), with their newest
  // access entry.
  'packages/db/src/grants.ts#findingsAt': { by: VAULT, as: 'findingsOf' },
  'packages/db/src/grants.ts#newestAccessOf': { by: AGGREGATES_TEST, as: 'tamperedMembers' },
  // Every member's newest access entry: the sweep of 0.14's log alone, and its one cutover to 0.15's (`AGGREGATES`).
  'packages/vault/src/store.ts#newestAccessEntries': { none: "every member's newest access entry, grouped: the sweep of 0.14's log alone, and its one cutover to 0.15's" },
  // A page's count of what it hides: its stretch's newest `HIDDEN_COUNTED` (T248).
  'packages/server/src/db/queries.ts#auditActionCounts': { by: AGGREGATES_TEST, as: 'auditActionCounts' },
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
  // A credential's first change, its sign-in or issue, behind other objects' changes before it.
  'packages/server/src/db/queries.ts#originsOf': { by: SERVER, as: 'originsOf' },
  // Whether a member no row names has a change, beside their access entry.
  'packages/server/src/db/queries.ts#missingMembers': { by: SERVER, as: 'missingMembers' },
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

const LOG_STORE = 'packages/vault/test/log-store.test.ts';
const REQUEST_COST = 'packages/server/test/request-cost.alone.ts';

/**
 * Each `EXISTS` gate over a log (0.14's, 0.15's changes or uses), by the function it is in: the test that holds it to
 * the same cost however long the run of other entries.
 */
const GATES: Record<string, { by: typeof VAULT | typeof SERVER; as: string }> = {
  // 0.15's named findings, by `audit_log_tamper_idx` and the change it names.
  'packages/db/src/grants.ts#findingsAt': { by: VAULT, as: 'findingsOf' },
  // Whether an append's key was moved from, by `audit_log_subject_idx` keyed by the key.
  'packages/db/src/log.ts#underHead': { by: VAULT, as: 'lockLogHeadRead' },
  'packages/server/src/db/queries.ts#hasTombstone': { by: SERVER, as: 'hasTombstone' },
};

/**
 * Each least or greatest of a column of 0.15's uses (`min(…)`, `max(…)` … `FROM log_uses`), by the function it is in:
 * the test that holds it, or why none needs one.
 */
const USES: Record<string, { by: typeof LOG_STORE; as: string } | { none: string }> = {
  // The lowest `at` of the uses a part of a capped window left above it (T169): a walk of `log_uses_at_number_idx`, past
  // each run of uses sealed at one `at` in a step (T248), which the test holds as a backlog drains, its uses stamped one
  // after another or sharing one `at`.
  'packages/vault/src/log-store.ts#postgresStore': { by: LOG_STORE, as: 'lowestAbove' },
  // SQLite's own: its numbering (both trees one sequence, each table's greatest number, a step of its rowid) and its
  // checkpointer's reads. Kept for tests and local development, no deployment runs on it (AGENTS.md).
  'packages/db/src/log.ts#changeOnSqlite': { none: "SQLite's numbering: each tree's greatest number, no deployment's engine" },
  'packages/vault/src/store.ts#changeOnSqlite': { none: "SQLite's numbering: each tree's greatest number, no deployment's engine" },
  'packages/vault/src/store.ts#nextNumber': { none: "SQLite's numbering: each tree's greatest number, no deployment's engine" },
  'packages/vault/src/credentials.sqlite.ts#nextNumber': { none: "SQLite's numbering: each tree's greatest number, no deployment's engine" },
  'packages/vault/src/use.sqlite.ts#NEXT': { none: "SQLite's numbering: each tree's greatest number, no deployment's engine" },
  ...Object.fromEntries(['', '#2', '#3', '#4'].map((nth) => [`packages/vault/src/log-store.ts#sqliteStore${nth}`, { none: "SQLite's checkpointer: its numbering, no deployment's engine" }])),
};

const SQLITE_NUMBERING = "SQLite's numbering: each tree's greatest number, no deployment's engine";

/**
 * Each aggregate over a log (a count, a greatest or least, a sum, a `json_agg` or `json_group_array`, an `array_agg`,
 * or a `GROUP BY`), in SQL's words or Drizzle's, by the function it is in: the test that holds it to a flat cost, or
 * why none needs one (T248, R48). The least or greatest of a column of 0.15's uses are `USES`'s.
 */
const AGGREGATES: Record<string, { by: typeof VAULT | typeof AGGREGATES_TEST | typeof REQUEST_COST | typeof LOG_STORE; as: string } | { none: string }> = {
  // 0.15's records a page hides, counted over a stretch `sealedReach` bounds to `HIDDEN_COUNTED` of them.
  'packages/server/src/db/queries.ts#sealedHidden': { by: REQUEST_COST, as: 'sealedHidden' },
  'packages/server/src/db/queries.ts#sealedHidden#2': { by: REQUEST_COST, as: 'sealedHidden' },
  // The rotations of the log's key, every one, which the keyring weighs: no more than `ROTATIONS_HELD` (T248).
  'packages/vault/src/log-store.ts#postgresStore#2': { by: LOG_STORE, as: 'ROTATIONS_HELD' },
  'packages/vault/src/log-store.ts#postgresStore#3': { by: LOG_STORE, as: 'ROTATIONS_HELD' },
  // The lowest `at` above a part, of the steps of its walk (T248).
  'packages/vault/src/log-store.ts#postgresStore': { by: LOG_STORE, as: 'lowestAbove' },
  'packages/vault/src/log-store.ts#postgresStore#4': { none: "a use's place among its window's changes: those between the pair before it and it, a window's at most (`locate`)" },
  // The newest of each kind a snapshot reads, each a step of its index (the vault's test's `snapshot`).
  'packages/vault/src/snapshot.postgres.ts#snapshotQuery': { by: VAULT, as: 'snapshot' },
  'packages/vault/src/snapshot.sqlite.ts#snapshotQuery': { by: VAULT, as: 'snapshot' },
  'packages/db/src/log.ts#missingEntry': { none: 'a count of a stretch of the primary key, `COUNTED_AT_ONCE` entries at most (T245)' },
  'packages/server/src/db/audit.ts#appVerifier': { none: "the first of the app's moves from each previous key, grouped: the moves alone, a few for each change of key" },
  'packages/server/src/db/audit.ts#appVerifier#2': { none: "the first of the app's moves from each previous key, grouped: the moves alone, a few for each change of key" },
  'packages/vault/src/store.ts#newestAccessEntries': { none: "every member's newest access entry, grouped: the sweep of 0.14's log alone, and its one cutover to 0.15's, whose sweep reads each member's by `memberLogs`" },
  'packages/vault/src/store.ts#newestAccessEntries#2': { none: "every member's newest access entry, grouped: the sweep of 0.14's log alone, and its one cutover to 0.15's, whose sweep reads each member's by `memberLogs`" },
  ...Object.fromEntries([
    'packages/db/src/log.ts#changeOnSqlite', 'packages/vault/src/credentials.sqlite.ts#nextNumber', 'packages/vault/src/store.ts#changeOnSqlite', 'packages/vault/src/store.ts#nextNumber',
    'packages/vault/src/store.ts#memberLogsSqlite', 'packages/vault/src/store.ts#newestChangesQuery', 'packages/vault/src/store.ts#newestSealsQuery',
    'packages/vault/src/use.sqlite.ts#CHUNK', 'packages/vault/src/use.sqlite.ts#NEXT',
    ...['', '#2', '#3', '#4'].map((nth) => `packages/vault/src/log-store.ts#sqliteStore${nth}`),
  ].map((site) => [site, { none: SQLITE_NUMBERING }])),
};

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
 * `asc` or `desc(logChanges.number)`, or the greatest or least number of an object's (`plain`), in SQL's words or
 * Drizzle's columns.
 */
function changeSites(): { keyed: string[]; plain: string[] } {
  const keyed = new Set<string>();
  const plain = new Set<string>();
  for (const { file, text } of sources()) {
    if (file === 'packages/db/src/access-entries.ts') continue;
    for (const use of text.matchAll(/\bchangesOf\(/g)) keyed.add(`${file}#${within(text, use.index)}`);
    // Each spelling: SQL's words, or Drizzle's columns interpolated (`${logChanges.number}`, Sol r7 of #556).
    const asked = /\.object\}?\s*=\s*(?:(?!ORDER BY|`).)*?ORDER BY (?:\$\{)?[\w.]*number|eq\(logChanges\.object,[^\n]*\n?[^\n]*orderBy\((?:asc|desc)\(logChanges\.number\)\)|\b(?:max|min)\((?:\$\{\w+\.number\}|\w*\.?number)\)\s+FROM (?:log_changes|\$\{logChanges\})\s*\w*\s*WHERE (?:\$\{\w+\.object\}|\w*\.?object)\s*=/g;
    for (const read of text.matchAll(asked)) plain.add(`${file}#${within(text, read.index)}`);
  }
  return { keyed: [...keyed], plain: [...plain] };
}

type Source = { file: string; text: string };

/**
 * Each place in `files` that `pattern` finds, outside comments and that `keep` keeps, by the function it is in, then
 * `#2`… for a second in the same function.
 */
function placesOf(pattern: RegExp, files: Source[], keep: (match: RegExpMatchArray, text: string) => boolean = () => true): string[] {
  const found: string[] = [];
  for (const { file, text } of files) {
    const seen = new Map<string, number>();
    for (const match of text.matchAll(pattern)) {
      if (/^\s*(?:\/\/|\*)/.test(text.slice(text.lastIndexOf('\n', match.index) + 1, match.index))) continue;
      if (!keep(match, text)) continue;
      const site = `${file}#${within(text, match.index)}`;
      const nth = (seen.get(site) ?? 0) + 1;
      seen.set(site, nth);
      found.push(nth === 1 ? site : `${site}#${nth}`);
    }
  }
  return found;
}

/** A log, as a statement names it: its table, or Drizzle's (`${auditLog}`, or `${log}` as `findingsOf` calls it). */
const LOG = /^(?:audit_log|log_changes|log_uses|\$\{(?:auditLog|logChanges|logUses|log)\})$/;
/** 0.15's uses, as a statement names them. */
const LOG_USES = /^(?:log_uses|\$\{logUses\})$/;

/**
 * What else a gate's subquery or an aggregate reads from, by the name a statement gives it: no log, each with what it
 * is. A name neither a log nor here (a CTE, an alias, Drizzle's table under a name of its own: `${history}`) is one the
 * scans cannot follow, so it is a site to list as a log's would be, until it is named here (review r9 of #556).
 */
const NOT_LOGS: Record<string, string> = {
  ...Object.fromEntries(['pg_locks', 'pg_roles', 'pg_shdepend', 'pg_auth_members', 'pg_db_role_setting', 'pg_depend', 'pg_inherits'].map((name) => [name, "Postgres's catalog"])),
  ...Object.fromEntries(['json_each', 'jsonb_each', 'jsonb_array_elements'].map((name) => [name, 'a list of values the statement gives'])),
  audit_chain_head: "the audit log's head, one row",
  checkpoint_fence: "the uses' fence, one row",
  log_checkpoints: "0.15's checkpoints, one row each",
  log_read_days: 'the days a member read on, a row each',
  log_read_newest: "each member's newest read of each key and version, a row each (T252)",
  '${reads}': 'the reads of members by their days (reads.ts), no log of these',
  principals: 'the members', passkeys: 'the passkeys', environments: 'the environments',
  secret_versions: "the secrets' versions", secret_references: "the secrets' references",
  '${projects}': 'the projects', '${credentials}': 'the credentials', '${mcpConnections}': 'the MCP connections',
  '${serviceBindings}': 'the service bindings', '${secrets}': 'the secrets',
  '${m}': "the members, `memberAccess`'s name for `principals` (queries.ts)",
  sealing: "the checkpoint a use's number falls under, one row of `log_checkpoints` (log-store.ts)",
  spent: 'the ID token spent by a sign-in, its one row (queries.ts)',
  grants: 'the grants', unnest: 'a list of values the statement gives, each a probe of its own',
  log_read_place_days: 'the days a place was read on, a row each',
  // Drizzle's tables, by the names their chains give them (review r1 of #559).
  '${environments}': 'the environments', '${grants}': 'the grants', '${principals}': 'the members', '${identities}': "the members' identities",
  '${passkeys}': 'the passkeys', '${secretVersions}': "the secrets' versions",
  '${live}': "a place's live keys, a CTE of `secrets` (`countedPlaceRows`, queries.ts)",
  '${keys}': "each place's count of `live`'s keys, a subquery (`countedPlaceRows`, queries.ts)",
};

/** Whether a statement's `from` reads no log, by what `NOT_LOGS` says it is; a log, or a name it cannot follow, is to list. */
const unlisted = (from: string) => !(from in NOT_LOGS);

/**
 * Each `EXISTS` (or `NOT EXISTS`) whose subquery's first table is a log, or one the scan cannot follow, in SQL's words;
 * and Drizzle's `exists(q)` or `notExists(q)` of a query `q` from a log's table, or one not built in sight.
 */
function gateSites(files: Source[] = sources()): string[] {
  const words = placesOf(/\bEXISTS\s*\(\s*SELECT\b(?:(?!\bFROM\b|`).){0,160}?\bFROM\s+(\$\{[\w.]+\}|\w+)/gs, files, (match) => unlisted(match[1]!));
  const drizzle = placesOf(/\b(?:exists|notExists)\((\w+)\)/g, files, (match, text) => {
    const from = new RegExp(String.raw`\b${match[1]}\s*=[^;]*?\.from\((\w+)\)`).exec(text.slice(Math.max(0, match.index! - 800), match.index))?.[1];
    return from === undefined || /^(auditLog|logChanges|logUses)$/.test(from);
  });
  return [...words, ...drizzle];
}

/**
 * Each `min(…)` or `max(…)` of a statement whose first table after it is 0.15's uses (`FROM log_uses`, or Drizzle's
 * `${logUses}`), or one the scan cannot follow, whatever else it selects beside.
 */
function useSites(files: Source[] = sources()): string[] {
  return placesOf(/\b(?:max|min)\((?:\$\{[\w.]+\}|[\w.]+)\)(?:(?!\bFROM\b|`|\(SELECT\b).){0,200}?\bFROM\s+(\$\{[\w.]+\}|\w+)/gs, files, (match) =>
    LOG_USES.test(match[1]!) || (!LOG.test(match[1]!) && unlisted(match[1]!)));
}

test('every read of the newest entries of a kind in the sources is listed, with the test that holds it to a flat cost, or why none needs one (T245, R48)', () => {
  const found = sites();
  assert.deepEqual(found.filter((site) => !(site in SITES)), [], 'a read the list does not name: list it with its test, which seeds a run of its kind then a long tail of others');
  assert.deepEqual(Object.keys(SITES).filter((site) => !found.includes(site)), [], 'a site listed that no longer reads so');
  const tests = new Map([VAULT, SERVER, AGGREGATES_TEST].map((file) => [file, readFileSync(`${ROOT}${file}`, 'utf8')]));
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

test('every `EXISTS` gate over a log in the sources is listed, with the test that holds it to a flat cost (T245, R48, Sol r8 of #556)', () => {
  const found = gateSites();
  assert.deepEqual(found.filter((site) => !(site in GATES)), [], 'an `EXISTS` over a log the list does not name: list it with its test, which seeds a long run of the entries it must not walk');
  assert.deepEqual(Object.keys(GATES).filter((site) => !found.includes(site)), [], 'a gate listed that no longer reads so');
  for (const [site, held] of Object.entries(GATES)) assert.match(readFileSync(`${ROOT}${held.by}`, 'utf8'), new RegExp(`\\b${held.as}\\b`), `${site}: ${held.by} asks ${held.as}`);
});

test("every least or greatest of 0.15's uses in the sources is listed, with the test that holds it, or why none needs one (T245, R48, Sol r8 of #556)", () => {
  const found = useSites();
  assert.deepEqual(found.filter((site) => !(site in USES)), [], 'a `min` or `max` over the uses the list does not name: list it with its test');
  assert.deepEqual(Object.keys(USES).filter((site) => !found.includes(site)), [], 'a read listed that no longer reads so');
  for (const [site, held] of Object.entries(USES)) {
    if ('as' in held) assert.match(readFileSync(`${ROOT}${held.by}`, 'utf8'), new RegExp(`\\b${held.as}\\b`), `${site}: ${held.by} asks ${held.as}`);
  }
});

/**
 * Each aggregate over a log in `files`: in SQL's words, one whose statement's next table is a log or one the scan
 * cannot follow (the least or greatest of a column of 0.15's uses aside, `useSites`'); Drizzle's, a `select` of
 * `count()`, `max(…)`, `min(…)` or `sum(…)` from a log's table, or from one under a name `NOT_LOGS` does not place (a
 * log's table under a name of its own: review r1 of #559); and a `GROUP BY` or `.groupBy(` of a statement that names
 * a log, or such a name. By the function each is in, `#2`… for a second.
 */
function aggregateSites(files: Source[] = sources()): string[] {
  const found: string[] = [];
  const words = new RegExp(String.raw`\b(count|max|min|sum|json_agg|jsonb_agg|json_group_array|array_agg|string_agg|bool_and|bool_or)\((?:(?!\bFROM\b|` + '`' + String.raw`|\(SELECT\b).){0,240}?\bFROM\s+(\$\{[\w.]+\}|\w+)`, 'gs');
  const drizzle = /\.select\(\{((?:[^{}]|\{[^{}]*\})*)\}\)\s*\.from\((\w+)\)/gs;
  const grouped = /\bGROUP BY\b|\.groupBy\(/g;
  // Drizzle's table, by the name its chain gives it: a log's, or one the scan cannot follow, as `${name}` in SQL's words.
  const logVar = (name: string) => /^(?:auditLog|logChanges|logUses|logReads)$/.test(name) || unlisted(`\${${name}}`);
  for (const { file, text } of files) {
    const at = new Set<number>();
    for (const match of text.matchAll(words)) {
      const from = match[2]!;
      // The least or greatest of a column of 0.15's uses: `USES`'s.
      if (/^(?:max|min)$/.test(match[1]!) && LOG_USES.test(from)) continue;
      if (LOG.test(from) || /^(?:log_reads|\$\{logReads\})$/.test(from) || unlisted(from)) at.add(match.index!);
    }
    for (const match of text.matchAll(drizzle)) if (/\b(?:count|max|min|sum)\(/.test(match[1]!) && logVar(match[2]!)) at.add(match.index!);
    for (const match of text.matchAll(grouped)) {
      // SQL's within its statement, from the backtick that opens it; Drizzle's of the table its chain selects from.
      const before = text.slice(Math.max(0, match.index! - 1500), match.index);
      const names = match[0] === 'GROUP BY'
        ? /\b(?:audit_log|log_changes|log_uses|log_reads)\b|\$\{(?:auditLog|logChanges|logUses|logReads)\}/.test(before.slice(before.lastIndexOf('`') + 1))
        : logVar([...before.matchAll(/\.from\((\w+)\)/g)].pop()?.[1] ?? 'grants');
      if (names) at.add(match.index!);
    }
    const seen = new Map<string, number>();
    for (const index of [...at].sort((a, b) => a - b)) {
      if (/^\s*(?:\/\/|\*)/.test(text.slice(text.lastIndexOf('\n', index) + 1, index))) continue;
      const site = `${file}#${within(text, index)}`;
      const nth = (seen.get(site) ?? 0) + 1;
      seen.set(site, nth);
      found.push(nth === 1 ? site : `${site}#${nth}`);
    }
  }
  return found;
}

test('every aggregate over a log in the sources is listed, with the test that holds it to a flat cost, or why none needs one (T248, R48)', () => {
  const found = aggregateSites();
  assert.deepEqual(found.filter((site) => !(site in AGGREGATES)), [], 'an aggregate over a log the list does not name: list it with its test, which grows the history it reads ten times over (`holdsFlat`)');
  assert.deepEqual(Object.keys(AGGREGATES).filter((site) => !found.includes(site)), [], 'an aggregate listed that no longer reads so');
  for (const [site, held] of Object.entries(AGGREGATES)) {
    if ('as' in held) assert.match(readFileSync(`${ROOT}${held.by}`, 'utf8'), new RegExp(`\\b${held.as}\\b`), `${site}: ${held.by} asks ${held.as}`);
  }
});

test('the scans list a gate or an aggregate whose table they cannot follow: a CTE, a log under a name of its own, a query built elsewhere (review r9 of #556)', () => {
  const one = (name: string, body: string): Source[] => [{ file: 'x.ts', text: `export function ${name}(db) {\n${body}\n}\n` }];
  // A gate over a CTE of the log's entries, over the log under a name of its own, and Drizzle's of a query built elsewhere.
  assert.deepEqual(gateSites(one('cte', 'return sql`WITH recent AS (SELECT seq FROM audit_log) SELECT 1 WHERE EXISTS (SELECT 1 FROM recent r WHERE r.seq > 1)`;')), ['x.ts#cte']);
  assert.deepEqual(gateSites(one('named', "const { auditLog: history } = tablesOf(db);\nreturn sql`SELECT EXISTS (SELECT 1 FROM ${history} h WHERE h.key_id = 'k')`;")), ['x.ts#named']);
  assert.deepEqual(gateSites(one('elsewhere', 'return db.select().from(grants).where(notExists(given));')), ['x.ts#elsewhere']);
  // The uses' least under a name of their own, and their greatest beside another column.
  assert.deepEqual(useSites(one('named', 'const { logUses: uses } = tablesOf(db);\nreturn sql`SELECT min(${uses.at}) FROM ${uses} WHERE ${uses.number} > 1`;')), ['x.ts#named']);
  assert.deepEqual(useSites(one('beside', 'return sql`SELECT max(u.at), count(*) AS n FROM log_uses u`;')), ['x.ts#beside']);
  // An aggregate over a log in SQL, over one under a name of its own, in Drizzle, and a log's statement grouped (T248).
  assert.deepEqual(aggregateSites(one('words', "return sql`SELECT subject_principal, max(seq) FROM audit_log WHERE action = 'x' GROUP BY 1`;")), ['x.ts#words', 'x.ts#words#2']);
  assert.deepEqual(aggregateSites(one('named', 'const { logReads: history } = tablesOf(db);\nreturn sql`SELECT json_agg(r.at) FROM ${history} r`;')), ['x.ts#named']);
  assert.deepEqual(aggregateSites(one('drizzle', 'return db.select({ n: count() }).from(auditLog).where(x);')), ['x.ts#drizzle']);
  assert.deepEqual(aggregateSites(one('grouped', 'return db.select({ a: auditLog.action }).from(auditLog).groupBy(auditLog.action);')), ['x.ts#grouped']);
  // Drizzle's over a log's table under a name of its own, counted or grouped (review r1 of #559).
  assert.deepEqual(aggregateSites(one('aliased', 'const { auditLog: history } = tablesOf(db);\nreturn db.select({ n: count() }).from(history);')), ['x.ts#aliased']);
  assert.deepEqual(aggregateSites(one('aliasedGroup', 'const { logReads: history } = tablesOf(db);\nreturn db.select({ a: history.principal }).from(history).groupBy(history.principal);')), ['x.ts#aliasedGroup']);
  // What reads no log, by what `NOT_LOGS` says it is, is no site.
  const none = one('none', 'return sql`SELECT EXISTS (SELECT 1 FROM principals p) AS any, (SELECT max(v.created_at) FROM secret_versions v) AS at`;');
  assert.deepEqual([...gateSites(none), ...useSites(none), ...aggregateSites(none)], []);
});
