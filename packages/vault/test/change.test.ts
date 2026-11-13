import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { leafHash } from '@coffre/core/log';
import { openDatabase } from '@coffre/db/connect';
import { rowsOf } from '@coffre/db/dialect';
import * as schema from '@coffre/db/schema';
import { and, eq, is, not, sql, type SQL } from 'drizzle-orm';
import { PgTable } from 'drizzle-orm/pg-core';

import { Busy, CHANGE_LOCK, change, commit, drop, part, prepare, put, type Operation, type Parts, type Refusal, type Seen, type Write } from '../src/change.ts';
import { entryOf, type Said } from '../src/entry.ts';
import { keyOf, nameOf, sealedBy, shapeOf, type Fresh, type Row, type Sealed } from '../src/rows.ts';
import { postgresProxy } from '../../../scripts/postgres-proxy.ts';
import { emptyDatabase, openTestVault, VAULT_URL } from './database.ts';

const { bindings, credentials, deviceLogins, dismissedKeys, enrollmentCodes, environments, grants, identities, oauthClients, policy, principals, projects, roles, secrets } = schema;

const vault = await openTestVault();
after(() => vault.close());
beforeEach(async () => {
  await emptyDatabase(vault.owner);
  vault.woken.length = 0;
});

const said = (action: string, actor: string | null = null): Said => ({ kept: true, action, actor, credential: null, request: null, ip: null, objects: [], detail: {} });
const nothing = { none: part(principals, sql`false`) };
const owning = and(eq(principals.role, 'owner'), eq(principals.status, 'active'));
/** A change that reads nothing and writes `writes`. */
const writing = (...writes: Write[]): Operation<typeof nothing, null> => ({ read: nothing, decide: () => ({ writes, entry: said('test.write'), answer: null }) });
const done = async <P extends Parts, A>(operation: Operation<P, A>): Promise<A> => {
  const result = await change(vault, operation);
  assert.ok('answer' in result, `refused: ${JSON.stringify(result)}`);
  return result.answer;
};
/** What a read of `table` finds, as a decision would see it. */
async function seenOf<T extends Sealed>(table: T, where: SQL = sql`true`): Promise<Row<T>[]> {
  let seen: Row<T>[] = [];
  await prepare(vault, { read: { found: part(table, where) }, decide: ({ found }) => ((seen = found as Row<T>[]), { refused: 'only a read' }) });
  return seen;
}

const at = new Date(Date.UTC(2026, 10, 13, 9, 30, 15, 123));
const member = (id: string, role = 'member'): Fresh<typeof principals> => ({
  id, status: 'active', role, scope: null, generation: 0, createdAt: at, createdBy: 'user:root@acme.example', statusChangedAt: at, statusChangedBy: 'user:root@acme.example', frozenAt: null,
});
const [ada, bo, cy] = ['user:ada@acme.example', 'user:bo@acme.example', 'user:cy@acme.example'];

/**
 * A member's role, as `formal/quint/change.qnt` has it: an Owner promotes,
 * demotes or removes, and never the last Owner. It reads every Owner, since
 * it counts them.
 */
function setRole(caller: string, target: string, to: 'owner' | 'member' | 'removed') {
  const read = {
    caller: part(principals, eq(principals.id, caller)),
    target: part(principals, eq(principals.id, target)),
    owners: part(principals, owning),
  };
  return {
    read,
    decide({ caller: [by], target: [who], owners }: Seen<typeof read>, now: number): { writes: Write[]; entry: Said; answer: string } | Refusal {
      const owner = (row?: Row<typeof principals>) => row?.status === 'active' && row.role === 'owner';
      if (!owner(by)) return { refused: 'not_owner' };
      if (who === undefined || who.status === 'removed') return { refused: 'no_member' };
      if (owner(who) && to !== 'owner' && owners.length <= 1) return { refused: 'last_owner' };
      const { mac: _, ...kept } = who;
      const row = to === 'removed'
        ? { ...kept, status: 'removed', role: 'member', generation: who.generation + 1, statusChangedAt: new Date(now), statusChangedBy: caller }
        : { ...kept, role: to };
      return { writes: [put(principals, row, who)], entry: { ...said('member.role', caller), objects: [`principal:${target}`], detail: { to } }, answer: to };
    },
  };
}

test('every sealed table has a row that reads back as the vault sealed it', async () => {
  const [project, environment, parent, secret, source, identity, binding, code] = Array.from({ length: 8 }, () => randomUUID());
  const service = 'token:deploy';
  // One row with every column filled, where the table's checks let it, and one of nulls, per table.
  const written: [Sealed, object][] = [
    [projects, { id: project, slug: 'market', name: 'Market', createdAt: at, archivedAt: at, folder: 'Payments' }],
    [projects, { id: randomUUID(), slug: 'billing', name: 'Billing', createdAt: at, archivedAt: null, folder: null }],
    [dismissedKeys, { environmentId: parent, key: 'OLD_KEY', dismissedAt: at, dismissedBy: ada, restoredAt: at, restoredBy: ada }],
    [dismissedKeys, { environmentId: environment, key: 'OLD_KEY', dismissedAt: at, dismissedBy: ada, restoredAt: null, restoredBy: null }],
    [environments, { id: parent, projectId: project, slug: 'prod', name: 'Production', createdAt: at, archivedAt: at, parentId: null, owner: null, protected: true, frozenCredentials: ['stripe', 'aws'] }],
    [environments, { id: environment, projectId: project, slug: 'ada', name: 'Ada’s', createdAt: at, archivedAt: null, parentId: parent, owner: ada, protected: false, frozenCredentials: [] }],
    [secrets, { id: source, projectId: project, environmentId: parent, key: 'STRIPE_KEY', createdAt: at, updatedAt: at, versions: 3, currentVersion: 3, archivedAt: at, folder: 'Payments', sourceId: null }],
    [secrets, { id: secret, projectId: project, environmentId: environment, key: 'STRIPE_KEY', createdAt: at, updatedAt: at, versions: 0, currentVersion: null, archivedAt: null, folder: null, sourceId: source }],
    [principals, { ...member(ada, 'owner'), scope: '{"projects":"all","environments":{"only":["prod"]}}' }],
    [principals, { ...member(service), frozenAt: at }],
    [grants, { id: randomUUID(), principal: ada, projectId: project, environmentId: null, role: 'contributor', expiresAt: at, grantedAt: at, grantedBy: ada }],
    [grants, { id: randomUUID(), principal: service, projectId: null, environmentId: parent, role: 'viewer', expiresAt: null, grantedAt: at, grantedBy: ada }],
    [roles, { instance: true, id: 'owner', name: 'Owner', description: 'Everything.', permissions: ['secret.read', 'secret.write'], protected: ['secret.read'] }],
    [roles, { instance: false, id: 'owner', name: 'Owner', description: '', permissions: [], protected: [] }],
    [policy, { onlyRow: true, serviceAccounts: '{"projects":"all","environments":"all"}', workloadsFrozenAt: at, changedAt: at, changedBy: ada }],
    [identities, { id: identity, provider: 'github', subject: '583231', issuerHash: 'x', generation: 0, principal: ada, email: 'ada@acme.example', createdAt: at, createdBy: ada, lastSignInAt: at, revokedAt: null, revokedBy: null }],
    [identities, { id: randomUUID(), provider: 'oidc', subject: 'gone', issuerHash: 'y', generation: 0, principal: ada, email: null, createdAt: at, createdBy: ada, lastSignInAt: null, revokedAt: at, revokedBy: ada }],
    [bindings, {
      id: binding, principal: service, generation: 0, profile: 'kubernetes', issuer: 'https://k8s.example', jwksUri: 'sha256:00', jwks: '{"keys":[]}', claims: '{"sub":"system:serviceaccount:app:api"}',
      scope: '[]', policy: '{"enroll":"approve"}', label: 'API pods', createdAt: at, createdBy: ada, lastUsedAt: at, frozenAt: at, revokedAt: at, revokedBy: ada,
    }],
    [enrollmentCodes, { id: code, bindingId: binding, codeHash: randomBytes(32), codeHint: 'coffre_enr_ab', scope: '[]', createdAt: at, createdBy: service, createdWith: randomUUID(), expiresAt: at, supersededAt: at }],
    [credentials, {
      id: randomUUID(), kind: 'workload', tokenHash: randomBytes(32), tokenHint: 'ab12', previousTokenHash: randomBytes(32), generation: 0, principal: service, identityId: null, scope: '[]',
      places: null, label: 'pod', createdAt: at, createdBy: service, expiresAt: at, lastUsedAt: at, lastUsedIp: '2001:db8::1', frozenAt: at, revokedAt: at, revokedBy: ada, jkt: 'thumb', notAfter: at,
      ancestors: '[]', constraints: '{}', enrollmentId: code, approvedAt: at, approvedBy: ada, run: '{"run_id":"7"}', client: null, challenge: null,
    }],
    [credentials, {
      id: randomUUID(), kind: 'browser', tokenHash: randomBytes(32), tokenHint: null, previousTokenHash: null, generation: 0, principal: ada, identityId: identity, scope: null,
      places: null, label: null, createdAt: at, createdBy: ada, expiresAt: at, lastUsedAt: null, lastUsedIp: null, frozenAt: null, revokedAt: null, revokedBy: null, jkt: null, notAfter: null,
      ancestors: null, constraints: null, enrollmentId: null, approvedAt: null, approvedBy: null, run: null, client: null, challenge: null,
    }],
    [deviceLogins, { id: randomUUID(), deviceCodeHash: randomBytes(32), userCode: 'WDJB-MJHT', clientLabel: 'laptop', clientIp: '192.0.2.7', createdAt: at, expiresAt: at, decidedAt: at, decision: 'approved', generation: 2, principal: ada, consumedAt: at }],
    [deviceLogins, { id: randomUUID(), deviceCodeHash: randomBytes(32), userCode: 'AAAA-BBBB', clientLabel: null, clientIp: null, createdAt: at, expiresAt: at, decidedAt: null, decision: null, generation: 0, principal: null, consumedAt: null }],
    [oauthClients, { id: randomUUID(), name: 'An MCP client', redirectUris: '["https://client.example/cb"]', createdAt: at, createdIp: '192.0.2.7', revokedAt: at }],
  ];
  // In one change: a row and the rows it points at, whatever order Postgres writes them in.
  await done(writing(...written.map(([table, row]) => put(table, row as never))));

  // The schema's own mark of one: a MAC that may be empty, as the upgrade leaves it. The log's MACs never are.
  const sealed = Object.values(schema).filter((table: unknown): table is Sealed => is(table, PgTable) && 'mac' in table && (table.mac as { hasDefault: boolean }).hasDefault);
  assert.deepEqual(sealed.map((table) => shapeOf(table).name).sort(), [...new Set(written.map(([table]) => shapeOf(table).name))].sort(), 'a sealed table this test writes no row of');
  for (const table of sealed) {
    const wrote = written.filter(([its]) => its === table);
    const found = await seenOf(table);
    assert.equal(found.length, wrote.length, `${shapeOf(table).name}: rows the vault wrote and does not take as its own`);
    for (const [, row] of wrote) {
      const { mac: _, ...read } = found.find((other) => nameOf(table, other) === nameOf(table, row))! as Record<string, unknown>;
      delete read.activeSubject;
      assert.deepEqual(read, row, `${shapeOf(table).name} reads back as written`);
    }
  }
});

test('a change is two round trips: its read, and its write, with the lock ahead of it and the commit behind', async () => {
  // Through a proxy that counts what a pooler like Hyperdrive sends on one at a time.
  const sent: string[][] = [];
  const proxy = await postgresProxy(VAULT_URL, { onSync: (statements) => sent.push(statements.map((text) => text.trimStart().slice(0, 12))) });
  const through = await openDatabase(proxy.url);
  try {
    const counted = { ...vault, db: through.db };
    // The first opens the connection.
    assert.ok('answer' in (await change(counted, writing(put(principals, member(ada, 'owner')), put(principals, member(bo, 'owner'))))));
    const before = { trips: proxy.trips, syncs: proxy.syncs };
    sent.length = 0;
    assert.deepEqual(await change(counted, setRole(ada, bo, 'member')), { answer: 'member' });
    assert.deepEqual({ trips: proxy.trips - before.trips, syncs: proxy.syncs - before.syncs }, { trips: 2, syncs: 2 });
    // What went together, in order: the read alone; then the transaction, its lock, its write and its end.
    assert.deepEqual(sent, [['SELECT part,'], ['begin isolat', 'SELECT set_c', 'WITH same AS', 'commit']]);
    // And a write that lost to another is one more of each, read and write.
    const stale = await prepare(counted, setRole(ada, bo, 'owner'));
    assert.ok(!('refused' in stale));
    await done(setRole(ada, bo, 'removed'));
    const again = { trips: proxy.trips, syncs: proxy.syncs };
    assert.equal(await commit(counted, stale), false);
    assert.deepEqual({ trips: proxy.trips - again.trips, syncs: proxy.syncs - again.syncs }, { trips: 1, syncs: 1 });
  } finally {
    await through.close();
    await proxy.close();
  }
});

test('three Owners each demote themselves at once: one stays', async () => {
  await done(writing(put(principals, member(ada, 'owner')), put(principals, member(bo, 'owner')), put(principals, member(cy, 'owner'))));
  const results = await Promise.all([ada, bo, cy].map((who) => change(vault, setRole(who, who, 'member'))));
  assert.deepEqual(results.map((result) => ('refused' in result ? result.refused : 'done')).sort(), ['done', 'done', 'last_owner']);
  assert.equal((await seenOf(principals, owning)).length, 1);
});

test('a write compares against the rows as they are once it holds the lock, whatever the database defaults to', async () => {
  await done(writing(put(principals, member(ada, 'owner')), put(principals, member(bo, 'owner')), put(principals, member(cy, 'owner'))));
  // Each decides alone, having read three Owners.
  const prepared = await Promise.all([ada, bo, cy].map((who) => prepare(vault, setRole(who, who, 'member'))));

  // A database whose transactions see it as of their first statement, unless they say otherwise.
  await vault.owner.execute(sql`ALTER DATABASE ${sql.identifier(process.env.COFFRE_TEST_DATABASE ?? 'coffre_test')} SET default_transaction_isolation = 'repeatable read'`);
  const fresh = await openTestVault();
  try {
    // All three writes wait for the lock at once, each having started before any other landed.
    const landed = await vault.owner.transaction(async (holder) => {
      await holder.execute(sql`SELECT pg_advisory_xact_lock(${sql.raw(String(CHANGE_LOCK))})`);
      const writes = prepared.map((one) => commit({ ...vault, db: fresh.db }, one as never));
      for (;;) {
        const [{ waiting }] = await rowsOf<{ waiting: number }>(holder, sql`SELECT count(*)::int AS waiting FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`);
        if (waiting === 3) return writes;
      }
    });
    assert.deepEqual((await Promise.all(landed)).filter(Boolean).length, 1, 'the first write changes an Owner row the other two counted');
    assert.equal((await seenOf(principals, owning)).length, 2);
  } finally {
    await vault.owner.execute(sql`ALTER DATABASE ${sql.identifier(process.env.COFFRE_TEST_DATABASE ?? 'coffre_test')} RESET default_transaction_isolation`);
    await fresh.close();
  }
});

test('a row that came since the read stops the write', async () => {
  await done(writing(put(principals, member(ada, 'owner'))));
  // Bo is admitted only if nobody is named so: the read finds no row.
  const admit = (id: string) => {
    const read = { caller: part(principals, eq(principals.id, ada)), named: part(principals, eq(principals.id, id)) };
    return { read, decide: ({ named }: Seen<typeof read>) => (named.length > 0 ? { refused: 'taken' } : { writes: [put(principals, member(id))], entry: said('member.admit', ada), answer: null }) };
  };
  const [first, second] = [await prepare(vault, admit(bo)), await prepare(vault, admit(bo))];
  assert.equal(await commit(vault, first as never), true);
  assert.equal(await commit(vault, second as never), false);
  assert.deepEqual(await change(vault, admit(bo)), { refused: 'taken' });
});

test('a row written behind the vault is no row', async () => {
  await done(writing(put(principals, member(ada, 'owner')), put(principals, member(bo))));
  // Promoted in the database: the MAC is of the Member's row.
  await vault.owner.update(principals).set({ role: 'owner' }).where(sql`id = ${bo}`);
  // Inserted in the database, with a MAC of another key.
  const forged = { ...member(cy, 'owner'), mac: Buffer.concat([keyOf(randomBytes(32)).id, randomBytes(32)]) };
  await vault.owner.insert(principals).values(forged);
  // And one the upgrade left, not yet adopted.
  await vault.owner.insert(principals).values({ ...member('user:dee@acme.example', 'owner') });

  assert.deepEqual((await seenOf(principals)).map((row) => row.id), [ada]);
  assert.deepEqual(await change(vault, setRole(bo, ada, 'member')), { refused: 'not_owner' });
  assert.deepEqual(await change(vault, setRole(ada, ada, 'member')), { refused: 'last_owner' }, 'forged Owners do not count');

  // The genuine row put back is the vault's again: that is the signer's to catch, against its mirror.
  await vault.owner.update(principals).set({ role: 'member' }).where(sql`id = ${bo}`);
  assert.deepEqual((await seenOf(principals)).map((row) => row.id).sort(), [ada, bo]);
});

test('a refusal writes nothing, and a change logs what it replaced', async () => {
  await done(writing(put(principals, member(ada, 'owner')), put(principals, member(bo))));
  const pendingRows = () => rowsOf<{ kept: boolean; body: string; mac: Buffer }>(vault.owner, sql`SELECT kept, body, mac FROM log_pending ORDER BY id`);
  const before = (await pendingRows()).length;
  vault.woken.length = 0;

  assert.deepEqual(await change(vault, setRole(bo, ada, 'removed')), { refused: 'not_owner' });
  assert.equal((await pendingRows()).length, before);
  assert.equal(vault.woken.length, 0);

  const [was] = await seenOf(principals, eq(principals.id, bo));
  const [by] = await seenOf(principals, eq(principals.id, ada));
  vault.tick(1500);
  // The entry is dated once the rows are read, not before: the read may wait, and the write, sent next, may not.
  const db = Object.create(vault.db) as typeof vault.db;
  db.execute = ((...args: Parameters<typeof vault.db.execute>) => (vault.tick(500), vault.db.execute(...args))) as typeof vault.db.execute;
  assert.deepEqual(await change({ ...vault, db }, setRole(ada, bo, 'removed')), { answer: 'removed' });
  const [now] = await seenOf(principals, eq(principals.id, bo));
  assert.equal(now!.generation, 1);
  assert.equal(now!.statusChangedAt.getTime(), vault.now());

  const logged = (await pendingRows()).at(before)!;
  const entry = entryOf(vault.keys, logged)!;
  assert.deepEqual(
    { ...entry, id: null },
    {
      id: null, at: vault.now(), action: 'member.role', actor: ada, credential: null, request: null, ip: null, objects: [`principal:${bo}`],
      // What it wrote, then what it read and left: Ada's row, once, though it was read as the caller and as an Owner.
      rows: [
        { row: JSON.stringify(['principals', bo]), was: was!.mac.toString('hex'), now: now!.mac.toString('hex') },
        { row: JSON.stringify(['principals', ada]), was: by!.mac.toString('hex'), now: by!.mac.toString('hex') },
      ],
      detail: { to: 'removed' },
    },
  );
  assert.deepEqual(vault.woken, [leafHash(Buffer.from(logged.body))], 'the signer is told the hash of the entry committed');
  // The tree is under the MAC, and so is every byte of the body.
  assert.equal(entryOf(vault.keys, { ...logged, kept: false }), undefined);
  assert.equal(entryOf(vault.keys, { ...logged, body: logged.body.replace('removed', 'member') }), undefined);
  assert.equal(entryOf([keyOf(randomBytes(32))], logged), undefined);
});

test('a change leaves what only says when a row was last seen', async () => {
  const id = randomUUID();
  const account: Fresh<typeof identities> = { id, provider: 'github', subject: '1', issuerHash: 'x', generation: 0, principal: ada, email: null, createdAt: at, createdBy: ada, lastSignInAt: null, revokedAt: null, revokedBy: null };
  await done(writing(put(principals, member(ada, 'owner')), put(identities, account)));
  const read = { account: part(identities, eq(identities.id, id)) };
  const revoke = await prepare(vault, {
    read,
    decide: ({ account: [found] }: Seen<typeof read>) => ({ writes: [put(identities, { ...account, revokedAt: at, revokedBy: ada }, found!)], entry: said('identity.revoke', ada), answer: null }),
  });
  // A sign-in between the read and the write moves the last sign-in on, with no change.
  await vault.owner.update(identities).set({ lastSignInAt: at }).where(sql`id = ${id}`);
  assert.equal(await commit(vault, revoke as never), true, 'the MAC does not cover it');
  const [found] = await seenOf(identities);
  assert.deepEqual([found!.revokedBy, found!.lastSignInAt], [ada, at]);
});

test('a row is dropped only as it was read', async () => {
  await done(writing(put(principals, member(ada, 'owner')), put(roles, { instance: false, id: 'deployer', name: 'Deployer', description: '', permissions: ['secret.use'], protected: [] })));
  const read = { role: part(roles, and(not(roles.instance), eq(roles.id, 'deployer'))) };
  const remove: Operation<typeof read, null> = { read, decide: ({ role: [found] }) => (found === undefined ? { refused: 'no_role' } : { writes: [drop(roles, found)], entry: said('role.delete', ada), answer: null }) };
  const [first, second] = [await prepare(vault, remove), await prepare(vault, remove)];
  assert.equal(await commit(vault, first as never), true);
  assert.equal(await commit(vault, second as never), false);
  assert.deepEqual(await seenOf(roles), []);
  assert.deepEqual(await change(vault, remove), { refused: 'no_role' });
});

test('a decision that writes around its read is a fault, not a change', async () => {
  await done(writing(put(principals, member(ada, 'owner'))));
  const [row] = await seenOf(principals);
  await assert.rejects(change(vault, writing(put(principals, member(ada), row!))), /did not read/);
  await assert.rejects(change(vault, writing(put(principals, member(bo)), put(principals, member(bo)))), /twice/);
  const read = { found: part(principals, sql`true`) };
  await assert.rejects(change(vault, { read, decide: ({ found: [it] }: Seen<typeof read>) => ({ writes: [put(principals, member(bo), it!)], entry: said('test'), answer: null }) }), /moves its key/);
  // Postgres would store each as another value, a row the vault never sealed: a UUID in small letters, a number as a text.
  const grant = { id: randomUUID(), principal: ada, projectId: randomUUID(), environmentId: null, role: 'viewer', expiresAt: null, grantedAt: at, grantedBy: ada };
  await assert.rejects(change(vault, writing(put(grants, { ...grant, id: grant.id.toUpperCase() }))), /grants\.id: .* is not a uuid as Postgres stores one/);
  await assert.rejects(change(vault, writing(put(grants, { ...grant, role: 5 as never }))), /grants\.role: 5 is not a text as Postgres stores one/);
  await assert.rejects(change(vault, writing(put(grants, { ...grant, grantedAt: new Date(Number.NaN) }))), /grants\.granted_at: null is not a time as Postgres stores one/);
  // A new row whose key is taken was never read: Postgres refuses it, and nothing of the change is kept.
  const entries = (await rowsOf(vault.owner, sql`SELECT 1 FROM log_pending`)).length;
  await assert.rejects(change(vault, writing(put(principals, member(bo)), put(principals, member(ada)))));
  assert.deepEqual([(await seenOf(principals)).length, (await rowsOf(vault.owner, sql`SELECT 1 FROM log_pending`)).length], [1, entries]);
});

test('a change that cannot have the lock answers busy, and holds nothing', async () => {
  await done(writing(put(principals, member(ada, 'owner'))));
  const waited = await vault.owner.transaction(async (holder) => {
    await holder.execute(sql`SELECT pg_advisory_xact_lock(${sql.raw(String(CHANGE_LOCK))})`);
    const started = Date.now();
    await assert.rejects(change(vault, writing(put(principals, member(bo)))), Busy);
    return Date.now() - started;
  });
  assert.ok(waited >= 2000 && waited < 4000, `waited ${waited} ms`);
  // The bound was the transaction's: the next change runs.
  await done(writing(put(principals, member(bo))));
  assert.equal((await seenOf(principals)).length, 2);
});

test('a write that runs past its bound answers busy, and writes nothing', async () => {
  await done(writing(put(principals, member(ada, 'owner'))));
  const entries = (await rowsOf(vault.owner, sql`SELECT 1 FROM log_pending`)).length;
  // The database's writer makes every entry slow to write.
  await vault.owner.execute(sql`CREATE FUNCTION slow_entry() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(10); RETURN NEW; END $$`);
  await vault.owner.execute(sql`CREATE TRIGGER slow_entry BEFORE INSERT ON log_pending FOR EACH ROW EXECUTE FUNCTION slow_entry()`);
  try {
    const started = Date.now();
    await assert.rejects(change(vault, writing(put(principals, member(bo)))), Busy);
    const ran = Date.now() - started;
    assert.ok(ran >= 5000 && ran < 8000, `ran ${ran} ms`);
  } finally {
    await vault.owner.execute(sql`DROP TRIGGER slow_entry ON log_pending`);
    await vault.owner.execute(sql`DROP FUNCTION slow_entry()`);
  }
  assert.deepEqual([(await seenOf(principals)).length, (await rowsOf(vault.owner, sql`SELECT 1 FROM log_pending`)).length], [1, entries]);
  // The lock went with the write, and the bound: the next change runs.
  await done(writing(put(principals, member(bo))));
});

test('a change that keeps losing answers busy', async () => {
  await done(writing(put(principals, member(ada, 'owner')), put(principals, member(bo))));
  const read = { who: part(principals, eq(principals.id, bo)) };
  /** Bo's generation, moved on by `by`. */
  const bump = (by: number): Operation<typeof read, null> => ({
    read,
    decide: ({ who: [row] }) => {
      const { mac: _, ...kept } = row!;
      return { writes: [put(principals, { ...kept, generation: kept.generation + by }, row!)], entry: said('test.bump'), answer: null };
    },
  });
  // Each time it has read, someone else's change lands ahead of its write.
  let writes = 0;
  const db = Object.create(vault.db) as typeof vault.db;
  db.transaction = (async (...args: Parameters<typeof vault.db.transaction>) => {
    writes += 1;
    await done(bump(1));
    return vault.db.transaction(...args);
  }) as typeof vault.db.transaction;
  await assert.rejects(change({ ...vault, db }, bump(100)), Busy);
  assert.equal(writes, 5);
  assert.equal((await seenOf(principals, eq(principals.id, bo)))[0]!.generation, 5, 'none of its own writes landed');
});
