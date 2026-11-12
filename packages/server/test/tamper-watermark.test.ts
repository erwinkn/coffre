// T179 PR 4a: the app's readers of the vault's findings about a member, under 0.15's log. A finding names the newest
// change of theirs it weighed, by its MAC, and stands until a change after it; a member the log has a change of, with no row, is
// missing. Neither leans on 0.14's access entries, which 0.16 stops writing (docs/design/two-trips.md, PR 4).
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { ACCESS_ACTIONS } from '@coffre/core/vault';
import { logObject } from '@coffre/db/log';
import { and, desc, eq, gt, inArray, max } from 'drizzle-orm';

import { clientFor, LOG, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { withLogUnlocked } from './db/engine.ts';
import { auditLog, logChanges, grants, principals } from '@coffre/db/schema';

const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const MEMBER = `user:${DEV}`;
const LOG_015_ONLY = { skip: LOG === '0.15' ? false : "0.15's log only: a finding names a change only under it" } as const;

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: ReturnType<typeof clientFor>;

before(async () => {
  db = await openTestDatabase();
  deps = testDeps(db.runtime, [ROOT]);
  root = clientFor(deps, ROOT);
});

after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  await root.members.add(MEMBER);
  await root.projects.create('market', { name: 'Market' });
  await root.access.set(MEMBER, { market: 'developer' });
});

/** The member's row and grants as they are now, to put back later as the database's owner could. */
async function snapshot() {
  const [row] = await db.owner.select().from(principals).where(eq(principals.principal, MEMBER));
  const held = await db.owner.select().from(grants).where(eq(grants.principal, MEMBER));
  return async () => {
    await db.owner.delete(grants).where(eq(grants.principal, MEMBER));
    await db.owner.update(principals).set(row!).where(eq(principals.principal, MEMBER));
    if (held.length > 0) await db.owner.insert(grants).values(held);
  };
}

/** Whether the member reads tampered: on their page (`memberAccess`), in the list, and on their own (`members`). */
async function tampered(): Promise<[boolean, boolean, boolean]> {
  const listed = (await root.members.list()).members.find((entry) => entry.member === MEMBER);
  return [(await root.members.access(MEMBER)).status === 'tampered', listed?.tampered === true, (await root.members.get(MEMBER)).status === 'tampered'];
}

/** The vault's 0.14 access entries about the member after `seq` taken out, as 0.16 writes none. */
async function dropAccessEntriesAfter(seq: bigint): Promise<void> {
  await withLogUnlocked(db.owner, (owner) => owner.delete(auditLog).where(and(
    eq(auditLog.author, 'vault'), eq(auditLog.subjectPrincipal, MEMBER), gt(auditLog.seq, seq), inArray(auditLog.action, [...ACCESS_ACTIONS]),
  )));
}

/** Gives the member's newest change in 0.15's log the number `to`, as a database writer can (no MAC covers it); answers the one it had. */
async function renumberNewest(to: bigint): Promise<bigint> {
  const [newest] = await db.owner.select({ number: logChanges.number }).from(logChanges)
    .where(eq(logChanges.object, logObject('principal', MEMBER))).orderBy(desc(logChanges.number)).limit(1);
  await db.owner.update(logChanges).set({ number: to }).where(eq(logChanges.number, newest!.number));
  return newest!.number;
}

test('a finding stands on every reader until a change after the one it weighed, however that one is renumbered, with or without the access entry 0.14 wrote beside it', LOG_015_ONLY, async () => {
  const old = await snapshot();
  await root.access.set(MEMBER, { market: 'viewer' });
  const newest = await snapshot();
  // A row from before that change, put back: the vault's next check of them finds it, and logs it.
  await old();
  assert.equal((await deps.vault.access(MEMBER)).status, 'tampered');
  assert.deepEqual(await tampered(), [true, true, true]);
  // Their newest row back: no change since, so the finding stands, though the change it names is numbered up.
  await newest();
  assert.deepEqual(await tampered(), [true, true, true]);
  const [top] = await db.owner.select({ number: max(logChanges.number) }).from(logChanges);
  const genuine = await renumberNewest(top!.number! + 1_000_000n);
  assert.deepEqual(await tampered(), [true, true, true]);
  await renumberNewest(genuine);
  const [finding] = await db.owner.select({ seq: max(auditLog.seq) }).from(auditLog).where(eq(auditLog.action, 'vault.tampered'));

  // The change that settles it, its 0.14 entries then taken out: the change alone says so.
  await root.access.set(MEMBER, { market: 'developer' });
  await dropAccessEntriesAfter(finding!.seq!);
  assert.deepEqual(await tampered(), [false, false, false]);
});

test('a member the log has a change of, with no row and no access entry of 0.14\'s, is missing: their report says tampered, not 404', LOG_015_ONLY, async () => {
  await db.owner.delete(grants).where(eq(grants.principal, MEMBER));
  await db.owner.delete(principals).where(eq(principals.principal, MEMBER));
  await dropAccessEntriesAfter(-1n);
  // Their report, by a change of theirs in 0.15's log and no row. The list of everyone finds the rowless by 0.14's
  // entries alone (PR 4b, with PR 6): it does not list them.
  assert.equal((await root.members.get(MEMBER)).status, 'tampered');
  assert.equal((await root.members.list()).members.some((entry) => entry.member === MEMBER), false);
});
