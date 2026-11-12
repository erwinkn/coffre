import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { eq } from 'drizzle-orm';

import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { grants, principals } from '@coffre/db/schema';

const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const MEMBER = `user:${DEV}`;

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

async function deleteMember() {
  await db.owner.delete(grants).where(eq(grants.principal, MEMBER));
  await db.owner.delete(principals).where(eq(principals.principal, MEMBER));
}

test('R3: a member with access history but no row is listed as tampered before their next use', async () => {
  await deleteMember();
  const listed = (await root.members.list()).members.find((entry) => entry.member === MEMBER);
  assert.ok(listed, 'the missing member must stay visible for recovery');
  assert.equal(listed.tampered, true);
  assert.deepEqual(listed.grants, []);
  assert.equal((await root.members.get(MEMBER)).status, 'tampered');
});

test('removing an unknown or an already removed clean member returns 404', async () => {
  await assert.rejects(root.members.remove('user:nobody@acme.example'), { status: 404 });
  await root.members.remove(MEMBER);
  await assert.rejects(root.members.remove(MEMBER), { status: 404 });
});
