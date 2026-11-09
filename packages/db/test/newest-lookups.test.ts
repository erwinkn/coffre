// The guard of T245's class of reads (R48): every read at run time that asks the audit log for the newest entries of a
// kind, its first, or a page back by `seq` (an `ORDER BY seq … LIMIT`) is one a test holds to the same cost however
// long the run of other entries since: the vault's and the database's in `packages/vault/test/newest-lookups.test.ts`,
// the server's in `packages/server/test/newest-lookups.test.ts`, each against a run of its kind then a long tail of
// others. Postgres prices a walk back by `seq` with the rest as a filter as the one row it expects to meet first,
// whenever its statistics hold the kind common, and that walk read every entry since: 641 pages for the newest
// rotation behind 20,000 checkpoints. A new read of the kind fails here until it is listed, with the test that holds
// it, or why it needs none. The database's functions' own are the vault's test's to list and hold.
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
  'packages/server/src/db/workloads.ts#frozen': { by: VAULT, as: 'freeze' },
  'packages/db/src/log.ts#underHead': { none: 'the newest entry of all: the primary key\'s first step, with nothing to filter' },
  'packages/db/src/log.ts#missingEntry': { none: 'the first entry after a gap, by the primary key, with nothing to filter' },
  'packages/db/src/log.ts#withinBytes': { none: "a batch's bounds by its caller's condition, read forward from a point (`entriesFrom`, `vaultEntriesAfter`, `talliedWithin`) or the audit page's (`auditPage`)" },
  'packages/vault/src/store.ts#entriesFrom': { none: 'a batch of the chain from an entry on, by the primary key, with nothing to filter' },
  'packages/server/src/db/queries.ts#auditPage': { none: "the audit page, a search by the reader's filters, each its own `(…, seq)` index, a page at a time" },
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
 * Each place in the sources of the packages that run (core, db, vault, server) that orders the audit log by `seq` and
 * takes a few: a Drizzle `orderBy(…seq)`, a statement's `ORDER BY seq … LIMIT` (`${auditLog.seq}` too, or after a key), or an order by a key then `seq` (`keyedBy`), within a statement that names the
 * audit log, by the top-level function it is in.
 */
function sites(): string[] {
  const files = execFileSync('git', ['ls-files', 'packages/core/src/**.ts', 'packages/db/src/**.ts', 'packages/vault/src/**.ts', 'packages/server/src/**.ts'], { cwd: ROOT, encoding: 'utf8' })
    .trim().split('\n');
  const found: string[] = [];
  for (const file of files) {
    const text = readFileSync(`${ROOT}${file}`, 'utf8');
    const seen = new Map<string, number>();
    for (const order of text.matchAll(/orderBy\((?:[^()]|\([^()]*\))*\b(?:asc|desc)\(\w+\.seq\)|keyedBy\(db\b|ORDER BY (?:[\w.]+(?: DESC| ASC)?, )?(?:\w+\.|\$\{\w+\.)?seq\}?(?: DESC| ASC)?\s+LIMIT/g)) {
      if (!/audit_log|auditLog/.test(text.slice(Math.max(0, order.index - 700), order.index))) continue;
      if (!order[0].startsWith('keyedBy') && !/limit/i.test(text.slice(order.index, order.index + order[0].length + 120))) continue;
      const within = [...text.slice(0, order.index).matchAll(/^(?:export )?(?:async )?(?:function\s+(\w+)|const\s+(\w+)\s*=)/gm)].pop();
      const site = `${file}#${within?.[1] ?? within?.[2] ?? '(top)'}`;
      const nth = (seen.get(site) ?? 0) + 1;
      seen.set(site, nth);
      found.push(nth === 1 ? site : `${site}#${nth}`);
    }
  }
  return found;
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
