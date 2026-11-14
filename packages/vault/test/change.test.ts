import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';
import { setTimeout as wait } from 'node:timers/promises';

import { leafHash } from '@coffre/core/log';
import { openDatabase } from '@coffre/db/connect';
import { rowsOf } from '@coffre/db/dialect';
import * as schema from '@coffre/db/schema';
import { and, eq, is, not, sql, type SQL } from 'drizzle-orm';
import { PgTable } from 'drizzle-orm/pg-core';

import { failureOf } from '../src/failure.ts';
import { Busy, CHANGE_LOCK, change, commit, drop, part, prepare, put, weigh, written, type Operation, type Parts, type Refusal, type Seen, type Write } from '../src/change.ts';
import { entryOf, type Said } from '../src/entry.ts';
import { keyOf, nameOf, sealedBy, shapeOf, type Fresh, type Row, type Sealed } from '../src/rows.ts';
import { postgresProxy } from '../../../scripts/postgres-proxy.ts';
import { emptyDatabase, openTestVault, VAULT_URL } from './database.ts';
import { binding, credential } from './world.ts';

const { bindings, credentials, deviceLogins, dismissedKeys, enrollmentCodes, environments, grants, identities, oauthClients, policy, principals, projects, roles, secrets } = schema;

const vault = await openTestVault();
after(() => vault.close());
beforeEach(async () => {
  await emptyDatabase(vault.owner);
  vault.woken.length = 0;
  vault.refused.clear();
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
    [secrets, { id: source, projectId: project, environmentId: parent, key: 'STRIPE_KEY', createdAt: at, updatedAt: at, versions: 3, currentVersion: 3, archivedAt: at, folder: 'Payments', sourceId: null, nature: 'sensitive', recipe: 'ecdsa:p-256', pairId: randomUUID(), pairHalf: 'private' }],
    [secrets, { id: secret, projectId: project, environmentId: environment, key: 'STRIPE_KEY', createdAt: at, updatedAt: at, versions: 0, currentVersion: null, archivedAt: null, folder: null, sourceId: source, nature: null, recipe: null, pairId: null, pairHalf: null }],
    [principals, { ...member(ada, 'owner'), scope: '{"projects":"all","environments":{"only":["prod"]}}' }],
    [principals, { ...member(service), frozenAt: at }],
    [grants, { id: randomUUID(), principal: ada, generation: 0, projectId: project, environmentId: null, role: 'contributor', expiresAt: at, grantedAt: at, grantedBy: ada }],
    [grants, { id: randomUUID(), principal: service, generation: 0, projectId: null, environmentId: parent, role: 'viewer', expiresAt: null, grantedAt: at, grantedBy: ada }],
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
    // What went together, in order: the read, with its bounds; then the transaction, its lock, its write and its end.
    assert.deepEqual(sent, [['begin isolat', 'SELECT set_c', 'SELECT part,', 'commit'], ['begin isolat', 'SELECT set_c', 'WITH same AS', 'commit']]);
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

test('a change leaves what only says when a row was last used, and nothing else: an account\'s last sign-in is a change\'s to write', async () => {
  const id = randomUUID();
  const session = credential('ada-web', ada);
  const account: Fresh<typeof identities> = { id, provider: 'github', subject: '1', issuerHash: 'x', generation: 0, principal: ada, email: null, createdAt: at, createdBy: ada, lastSignInAt: null, revokedAt: null, revokedBy: null };
  await done(writing(put(principals, member(ada, 'owner')), put(identities, account), put(credentials, session)));
  const read = { session: part(credentials, eq(credentials.id, session.id)), account: part(identities, eq(identities.id, id)) };
  const revoke = await prepare(vault, {
    read,
    decide: ({ session: [found] }: Seen<typeof read>) => ({ writes: [put(credentials, { ...session, revokedAt: at, revokedBy: ada }, found!)], entry: said('token.revoke', ada), answer: null }),
  });
  // A use between the read and the write moves the last use on, with no change.
  await vault.owner.update(credentials).set({ lastUsedAt: at, lastUsedIp: '192.0.2.7' }).where(sql`id = ${session.id}`);
  assert.equal(await commit(vault, revoke as never), true, 'the MAC does not cover it');
  const [found] = await seenOf(credentials);
  assert.deepEqual([found!.revokedBy, found!.lastUsedAt, found!.lastUsedIp], [ada, at, '192.0.2.7']);
  // Not so an account's last sign-in: moved on behind the vault, the row is no longer the vault's.
  assert.equal((await seenOf(identities)).length, 1);
  await vault.owner.update(identities).set({ lastSignInAt: at }).where(sql`id = ${id}`);
  assert.deepEqual(await seenOf(identities), []);
});

test('a change that spends a proof is made once: a second is refused `replayed` and writes nothing, and one that starts over does not find its own', async () => {
  await done(writing(put(principals, member(ada, 'owner'))));
  const proof = randomBytes(32);
  const read = { who: part(principals, eq(principals.id, ada)) };
  const promote = (to: string, once: Buffer): Operation<typeof read, string> => ({
    read,
    decide: ({ who: [found] }) => ({ writes: [put(principals, member(ada, to), found!)], once, entry: said(`role.${to}`, ada), answer: to }),
  });
  const spent = async () => (await rowsOf<{ hash: Buffer }>(vault.owner, sql`SELECT hash FROM spent_id_tokens`)).map((row) => row.hash.toString('hex'));
  const entries = async () => (await rowsOf<{ n: number }>(vault.owner, sql`SELECT count(*)::int AS n FROM log_pending`))[0]!.n;

  // Decided, then a row it read moves before it writes: nothing is written, the proof not spent.
  const first = await prepare(vault, promote('admin', proof));
  await done({ read, decide: ({ who: [found] }) => ({ writes: [put(principals, member(ada, 'auditor'), found!)], entry: said('role.auditor', ada), answer: null }) });
  const before = await entries();
  vault.woken.length = 0;
  assert.equal(await commit(vault, first as never), false);
  assert.deepEqual([await spent(), await entries(), vault.woken.length], [[], before, 0]);
  // Started over, it is made, and its proof spent with it, dated by the vault.
  assert.deepEqual(await change(vault, promote('admin', proof)), { answer: 'admin' });
  assert.deepEqual([await spent(), await entries(), vault.woken.length, (await seenOf(principals))[0]!.role], [[proof.toString('hex')], before + 1, 1, 'admin']);
  const [{ at: dated }] = await rowsOf<{ at: Date }>(vault.owner, sql`SELECT spent_at AS at FROM spent_id_tokens`) as [{ at: Date }];
  assert.equal(new Date(dated).getTime(), vault.now());
  // The same proof again: refused, with no row moved, no entry and no word to the signer. Another proof is another change.
  assert.deepEqual(await change(vault, promote('member', proof)), { refused: 'replayed' });
  assert.deepEqual([await entries(), vault.woken.length, (await seenOf(principals))[0]!.role], [before + 1, 1, 'admin']);
  assert.deepEqual(await change(vault, promote('member', randomBytes(32))), { answer: 'member' });
  // Two at once on one proof, each on rows of its own, so that nothing but the proof sets them apart: one is made.
  await done(writing(put(principals, member(bo))));
  const twin = randomBytes(32);
  const others = { who: part(principals, eq(principals.id, bo)) };
  const [left, right] = await Promise.all([
    prepare(vault, promote('admin', twin)),
    prepare(vault, { read: others, decide: ({ who: [found] }: Seen<typeof others>) => ({ writes: [put(principals, member(bo, 'admin'), found!)], once: twin, entry: said('role.admin', bo), answer: 'admin' }) }),
  ]);
  assert.deepEqual([await written(vault, left as never), await written(vault, right as never)], ['made', 'spent']);
  assert.equal((await seenOf(principals)).find((row) => row.id === bo)!.role, 'member');
  // A row that moved is told before a proof that was spent: the change starts over, and is made, its proof spent once.
  const later = randomBytes(32);
  let moved = false;
  const racing: Operation<typeof read, string> = {
    ...promote('auditor', later),
    async check() {
      if (!moved) {
        moved = true;
        await done({ read, decide: ({ who: [found] }) => ({ writes: [put(principals, member(ada, 'owner'), found!)], entry: said('role.owner', ada), answer: null }) });
      }
      return undefined;
    },
  };
  assert.deepEqual(await change(vault, racing), { answer: 'auditor' });
  assert.equal((await spent()).filter((hash) => hash === later.toString('hex')).length, 1);
  // A proof is its hash's 32 bytes, as a Buffer: anything else is told before a write.
  await assert.rejects(change(vault, promote('admin', randomBytes(16))), /32 bytes/);
  await assert.rejects(change(vault, promote('admin', new Uint8Array(32) as Buffer)), /32 bytes/);
});

test('a change whose decision holds until a time is written only if its write starts by then, on the database\'s clock', async () => {
  await done(writing(put(principals, member(ada))));
  const read = { who: part(principals, eq(principals.id, ada)) };
  let decisions = 0;
  // A decision that holds for `ms` from its time, the first of them for `first`.
  const holding = (to: string, ms: number, first = ms): Operation<typeof read, string> => ({
    read,
    decide: ({ who: [found] }, at) => ({ writes: [put(principals, member(ada, to), found!)], until: at + ((decisions += 1) === 1 ? first : ms), entry: said(`role.${to}`, ada), answer: to }),
  });
  const role = async () => (await seenOf(principals, eq(principals.id, ada)))[0]!.role;
  const entries = async () => (await rowsOf<{ n: number }>(vault.owner, sql`SELECT count(*)::int AS n FROM log_pending`))[0]!.n;

  // Written in time: made. The time is the database's, between its read and its write: the vault's own clock moving on is not it.
  const early = await prepare(vault, holding('admin', 60_000));
  vault.tick(120_000);
  assert.deepEqual([await written(vault, early as never), await role()], ['made', 'admin']);
  // Written late: nothing is, no row, no entry, no word to the signer, though no row it read has changed.
  const [before, late] = [await entries(), await prepare(vault, holding('auditor', 40))];
  vault.woken.length = 0;
  await wait(80);
  assert.deepEqual([await written(vault, late as never), await role(), await entries(), vault.woken.length], ['moved', 'admin', before, 0]);
  // Late by its wait for the change lock: the time is told as its statement starts, behind the lock, not as it is sent.
  const queued = await prepare(vault, holding('auditor', 300));
  const { landing } = await vault.owner.transaction(async (holder) => {
    await holder.execute(sql`SELECT pg_advisory_xact_lock(${sql.raw(String(CHANGE_LOCK))})`);
    const landing = written(vault, queued as never);
    await wait(600);
    return { landing };
  });
  assert.deepEqual([await landing, await role(), await entries()], ['moved', 'admin', before]);
  // A change that comes late starts over, and is decided again at a later time.
  decisions = 0;
  const slow: Operation<typeof read, string> = { ...holding('auditor', 60_000, 40), check: async () => void (decisions === 0 && (await wait(80))) };
  assert.deepEqual([await change(vault, slow), decisions, await role(), await entries()], [{ answer: 'auditor' }, 2, 'auditor', before + 1]);
  // It holds until a time after its decision, a number, and by a row it read.
  const until = (to: (at: number) => number, from: Parts = read): Operation<Parts, null> => ({ read: from, decide: (_, at) => ({ writes: [], until: to(at), entry: said('test'), answer: null }) });
  for (const bad of [until((at) => at), until((at) => at - 1), until(() => Number.NaN), until(() => Infinity), until((at) => at + 1000, nothing)]) await assert.rejects(change(vault, bad), /holds until a time after its decision, by a row it read/);
});

test('a change that is a use of a binding moves its last use on, to its entry\'s date, if and only if it is made', async () => {
  const api = 'token:api';
  const [bound, idle] = [binding(api), binding(api)];
  await done(writing(put(principals, member(api)), put(principals, member(ada)), put(bindings, bound), put(bindings, idle)));
  const read = { binding: part(bindings, eq(bindings.id, bound.id)), who: part(principals, eq(principals.id, ada)) };
  const exchange = (to: string, once?: Buffer): Operation<typeof read, string> => ({
    read,
    decide: ({ binding: [found], who: [was] }) => ({ writes: [put(principals, member(ada, to), was!)], once, used: found!, entry: said('token.exchange', api), answer: to }),
  });
  const lastUse = async () => (await rowsOf<{ at: string | null }>(vault.owner, sql`SELECT last_used_at AS at FROM bindings WHERE id = ${bound.id}`)).map(({ at }) => (at === null ? null : new Date(at).getTime()))[0];
  const entryAt = async () => (JSON.parse((await rowsOf<{ body: string }>(vault.owner, sql`SELECT body FROM log_pending ORDER BY id DESC LIMIT 1`))[0]!.body) as { at: number }).at;

  // Decided, then a row it read moves: not made, and the binding was not used.
  const lost = await prepare(vault, exchange('admin'));
  await done({ read: { who: read.who }, decide: ({ who: [was] }) => ({ writes: [put(principals, member(ada, 'auditor'), was!)], entry: said('role.auditor', ada), answer: null }) });
  assert.deepEqual([await written(vault, lost as never), await lastUse()], ['moved', null]);
  // Made: the entry's date, and the row is still the vault's, as every change that read it found it.
  const proof = randomBytes(32);
  const mine = await prepare(vault, exchange('admin', proof));
  vault.tick(1000);
  assert.equal(await written(vault, mine as never), 'made');
  assert.deepEqual([await lastUse(), (await seenOf(bindings)).length], [await entryAt(), 2]);
  assert.equal(await lastUse(), vault.now() - 1000, 'dated as its entry, not as it landed');
  // Late for the time its decision held until: not made either, its proof not spent and the binding not used again.
  const [overdue, usedAt] = [randomBytes(32), await lastUse()];
  const tardy = await prepare(vault, { read, decide: ({ binding: [found], who: [was] }: Seen<typeof read>, at: number) => ({ writes: [put(principals, member(ada, 'owner'), was!)], once: overdue, used: found!, until: at + 40, entry: said('token.exchange', api), answer: 'owner' }) });
  await wait(80);
  assert.deepEqual([await written(vault, tardy as never), await lastUse(), await rowsOf(vault.owner, sql`SELECT 1 FROM spent_id_tokens WHERE hash = decode(${overdue.toString('hex')}, 'hex')`)], ['moved', usedAt, []]);
  // One that read the binding before a use of it is not stopped by that use.
  const beside = await prepare(vault, { read: { binding: read.binding }, decide: ({ binding: [found] }: Pick<Seen<typeof read>, 'binding'>) => ({ writes: [], used: found!, entry: said('token.renew', api), answer: null }) });
  vault.tick(1000);
  assert.deepEqual(await change(vault, { read: { binding: read.binding }, decide: ({ binding: [found] }) => ({ writes: [], used: found!, entry: said('token.renew', api), answer: null }) }), { answer: null });
  const moved = await lastUse();
  assert.equal(moved, vault.now());
  // The older one lands after: made, since the row's MAC is the one it read, and the later date stays.
  assert.deepEqual([await written(vault, beside as never), await lastUse()], ['made', moved]);
  // A proof spent before: refused, and no use.
  vault.tick(1000);
  assert.deepEqual([await change(vault, exchange('member', proof)), await lastUse()], [{ refused: 'replayed' }, moved]);
  // The binding is one the decision read, a binding, and one the change does not write as well, or drop.
  const [found] = await seenOf(bindings, eq(bindings.id, bound.id));
  await assert.rejects(change(vault, { read: nothing, decide: () => ({ writes: [], used: found!, entry: said('test'), answer: null }) }), /a binding its decision read/);
  await assert.rejects(change(vault, { read, decide: ({ who: [was] }: Seen<typeof read>) => ({ writes: [], used: was as never, entry: said('test'), answer: null }) }), /a binding its decision read/);
  await assert.rejects(change(vault, { read, decide: ({ binding: [it] }: Seen<typeof read>) => ({ writes: [drop(bindings, it!)], used: it!, entry: said('test'), answer: null }) }), /does not move its last use on too/);
  await assert.rejects(
    change(vault, { read, decide: ({ binding: [it] }: Seen<typeof read>) => ({ writes: [put(bindings, { ...bound, label: 'CI' }, it!)], used: it!, entry: said('test'), answer: null }) }),
    /does not move its last use on too/,
  );
  // Through it all, only the binding used: the service's other one never was.
  assert.deepEqual([await lastUse(), (await seenOf(bindings, eq(bindings.id, idle.id)))[0]!.lastUsedAt], [moved, null]);
});

test('a change weighed answers what it would, in one round trip, and writes nothing: no row, no entry, no proof spent, no binding used', async () => {
  const api = 'token:api';
  const bound = binding(api);
  await done(writing(put(principals, member(ada, 'owner')), put(principals, member(bo, 'owner')), put(principals, member(api)), put(bindings, bound)));
  const state = async () => ({
    rows: await rowsOf(vault.owner, sql`SELECT id, role, status, generation, encode(mac, 'hex') AS mac FROM principals ORDER BY id`),
    entries: (await rowsOf<{ n: number }>(vault.owner, sql`SELECT count(*)::int AS n FROM log_pending`))[0]!.n,
    spent: (await rowsOf<{ n: number }>(vault.owner, sql`SELECT count(*)::int AS n FROM spent_id_tokens`))[0]!.n,
    used: (await rowsOf<{ at: string | null }>(vault.owner, sql`SELECT last_used_at AS at FROM bindings`)).map(({ at }) => at),
    woken: vault.woken.length,
  });
  const before = await state();

  // Through a proxy that counts round trips: the read, and no write behind it.
  const sent: string[][] = [];
  const proxy = await postgresProxy(VAULT_URL, { onSync: (statements) => sent.push(statements.map((text) => text.trimStart().slice(0, 12))) });
  const through = await openDatabase(proxy.url);
  try {
    const counted = { ...vault, db: through.db };
    await weigh(counted, setRole(ada, bo, 'member'));
    const trips = proxy.trips;
    sent.length = 0;
    assert.deepEqual(await weigh(counted, setRole(ada, bo, 'member')), { answer: 'member' });
    assert.equal(proxy.trips - trips, 1);
    assert.deepEqual(sent, [['begin isolat', 'SELECT set_c', 'SELECT part,', 'commit']]);
  } finally {
    await through.close();
    await proxy.close();
  }
  assert.deepEqual(await state(), before);

  // One that spends a proof and is a use of a binding: neither happens, and the change made after is the first to spend it.
  const proof = randomBytes(32);
  const read = { binding: part(bindings, eq(bindings.id, bound.id)), who: part(principals, eq(principals.id, bo)) };
  const exchange: Operation<typeof read, string> = {
    read,
    decide: ({ binding: [found], who: [was] }) => ({ writes: [put(principals, member(bo, 'admin'), was!)], once: proof, used: found!, entry: said('token.exchange', api), answer: 'admin' }),
  };
  assert.deepEqual([await weigh(vault, exchange), await weigh(vault, exchange)], [{ answer: 'admin' }, { answer: 'admin' }]);
  assert.deepEqual(await state(), before);
  assert.deepEqual(await change(vault, exchange), { answer: 'admin' });
  // Weighed again once spent, it still answers: the write alone sees the proofs spent.
  assert.deepEqual([await weigh(vault, exchange), await change(vault, exchange)], [{ answer: 'admin' }, { refused: 'replayed' }]);

  // A check runs, and a fault in a decision is a fault: all of a change but its write.
  let checks = 0;
  assert.deepEqual(await weigh(vault, { read: nothing, check: async () => ((checks += 1), 'seen'), decide: (_seen, _at, _unsealed, checked) => ({ writes: [], entry: said('test'), answer: checked }) }), { answer: 'seen' });
  assert.equal(checks, 1);
  const [found] = await seenOf(bindings);
  await assert.rejects(weigh(vault, { read: nothing, decide: () => ({ writes: [], used: found!, entry: said('test'), answer: null }) }), /a binding its decision read/);
});

test('a change weighed and refused is refused as the change is, and logged as one: once a minute, with the change\'s own refusals', async () => {
  await done(writing(put(principals, member(ada, 'owner')), put(principals, member(bo))));
  const denied = (operation: ReturnType<typeof setRole>, actor: string) => ({
    ...operation,
    denied: (_seen: unknown, _at: number, refusal: Refusal) => ({ action: 'member.role', actor, credential: null, request: null, ip: null, objects: [], detail: { refused: refusal.refused } }),
  });
  const logged = async () => (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(vault.owner, sql`SELECT kept, body, mac FROM log_pending ORDER BY id`)).map((row) => entryOf(vault.keys, row)!);
  const before = (await logged()).length;
  vault.woken.length = 0;

  assert.deepEqual(await weigh(vault, denied(setRole(bo, ada, 'removed'), bo)), { refused: 'not_owner' });
  assert.deepEqual((await logged()).slice(before).map((entry) => [entry.action, entry.actor, entry.detail]), [['member.role', bo, { refused: 'not_owner' }]]);
  assert.equal(vault.woken.length, 1);
  // The change itself, refused within the minute, and weighed again: the one entry stands for them all.
  assert.deepEqual(await change(vault, denied(setRole(bo, ada, 'removed'), bo)), { refused: 'not_owner' });
  assert.deepEqual(await weigh(vault, denied(setRole(bo, ada, 'removed'), bo)), { refused: 'not_owner' });
  assert.equal((await logged()).length, before + 1);
  // The last Owner weighs their own demotion: the refusal the change would give, from the rows as they are.
  assert.deepEqual(await weigh(vault, setRole(ada, ada, 'member')), { refused: 'last_owner' });
  assert.deepEqual(await weigh(vault, setRole(ada, bo, 'owner')), { answer: 'owner' });
  assert.equal((await seenOf(principals, eq(principals.id, bo)))[0]!.role, 'member');
});

test('a check runs between a change\'s read and its decision, on the rows read, and again each time the change starts over', async () => {
  await done(writing(put(principals, member(ada, 'owner'))));
  const read = { who: part(principals, eq(principals.id, ada)) };
  const checks: string[] = [];
  let moved = false;
  const operation: Operation<typeof read, string, string> = {
    read,
    async check({ who: [found] }, unsealed) {
      checks.push(`${found!.role} ${unsealed.who}`);
      // Another change lands after the first check, before the write.
      if (!moved) {
        moved = true;
        await done({ read, decide: ({ who: [row] }) => ({ writes: [put(principals, member(ada, 'admin'), row!)], entry: said('role.admin', ada), answer: null }) });
      }
      return `checked as ${found!.role}`;
    },
    decide: ({ who: [found] }, _at, _unsealed, checked) => ({ writes: [put(principals, member(ada, 'member'), found!)], entry: said('role.member', ada), answer: checked }),
  };
  // The decision is handed what the check of the same rows found: the second one's, once the change started over.
  assert.deepEqual(await change(vault, operation), { answer: 'checked as admin' });
  assert.deepEqual(checks, ['owner 0', 'admin 0']);
  // A check that fails, fails the change, which writes nothing.
  const logged = async () => (await rowsOf<{ n: number }>(vault.owner, sql`SELECT count(*)::int AS n FROM log_pending`))[0]!.n;
  const before = await logged();
  const failing: Operation<typeof read, string, string> = { ...operation, check: () => Promise.reject(new Error('no such key')), decide: ({ who: [found] }) => ({ writes: [put(principals, member(ada, 'auditor'), found!)], entry: said('role.auditor', ada), answer: 'x' }) };
  await assert.rejects(change(vault, failing), /no such key/);
  assert.deepEqual([(await seenOf(principals))[0]!.role, await logged()], ['member', before]);
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

/** Busy, which the vault answers as an outage, 503, with Postgres's code for the wait that ended. */
const busy = (code: string) => (error: unknown) => {
  assert.ok(error instanceof Busy);
  // Its own, which crosses a Worker's binding to the app, where a cause may not.
  assert.equal(error.code, code);
  assert.deepEqual(failureOf(error), { status: 503, body: { error: error.message, code } });
  return true;
};

test('a change that cannot have the lock answers busy, and holds nothing', async () => {
  await done(writing(put(principals, member(ada, 'owner'))));
  const waited = await vault.owner.transaction(async (holder) => {
    await holder.execute(sql`SELECT pg_advisory_xact_lock(${sql.raw(String(CHANGE_LOCK))})`);
    const started = Date.now();
    await assert.rejects(change(vault, writing(put(principals, member(bo)))), busy('55P03'));
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
    await assert.rejects(change(vault, writing(put(principals, member(bo)))), busy('57014'));
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
  // Each time it has read, someone else's change lands ahead of its write: of its transactions, each second.
  let [calls, writes] = [0, 0];
  const db = Object.create(vault.db) as typeof vault.db;
  db.transaction = (async (...args: Parameters<typeof vault.db.transaction>) => {
    if ((calls += 1) % 2 === 0) {
      writes += 1;
      await done(bump(1));
    }
    return vault.db.transaction(...args);
  }) as typeof vault.db.transaction;
  await assert.rejects(change({ ...vault, db }, bump(100)), busy('55P03'));
  assert.equal(writes, 5);
  assert.equal((await seenOf(principals, eq(principals.id, bo)))[0]!.generation, 5, 'none of its own writes landed');
});

test('a value is the current version of a secret the same change writes, in an environment it read, or the change is a fault', async () => {
  const [place, id] = [randomUUID(), randomUUID()];
  const environment: Fresh<typeof environments> = { id: place, projectId: randomUUID(), slug: 'prod', name: 'prod', createdAt: at, archivedAt: null, parentId: null, owner: null, protected: false, frozenCredentials: [] };
  const secret = (versions: number, currentVersion: number | null, nature: Fresh<typeof secrets>['nature'] = currentVersion === null ? null : 'secret'): Fresh<typeof secrets> => ({ id, projectId: environment.projectId, environmentId: place, key: 'A', createdAt: at, updatedAt: at, versions, currentVersion, archivedAt: null, folder: null, sourceId: null, nature, recipe: null, pairId: null, pairHalf: null });
  const version = (of: string, number: number, plaintext: string | null = null, sensitive = false) => ({ version: { id: randomUUID(), secretId: of, version: number, createdAt: at, firstWrittenAt: at, createdBy: ada, plaintext, sensitive }, text: Buffer.from('x') });
  const here = put(environments, environment);
  const tries: [string, Write[], ReturnType<typeof version>, RegExp][] = [
    ['no secret written', [here], version(id, 1), /current version of a secret it writes/],
    ['another secret written', [here, put(secrets, secret(1, 1))], version(randomUUID(), 1), /current version/],
    ['an older number than its secret is at', [here, put(secrets, secret(2, 2))], version(id, 1), /current version/],
    ['a number its secret counts past', [here, put(secrets, secret(2, 1))], version(id, 1), /current version/],
    ['a secret left with no value', [here, put(secrets, secret(1, null))], version(id, 1), /current version/],
    ['an environment neither read nor written', [put(secrets, secret(1, 1))], version(id, 1), /that it read/],
    ['an environment of another project', [put(environments, { ...environment, projectId: randomUUID() }), put(secrets, secret(1, 1))], version(id, 1), /of its project/],
    ['a plain copy that is not the value', [here, put(secrets, secret(1, 1, 'plain'))], version(id, 1, 'y'), /copy is the value/],
    // What its secret's row says of the value, which the next change reads, is what it is sealed as.
    ['a plain value of a secret its row says is a secret', [here, put(secrets, secret(1, 1))], version(id, 1, 'x'), /sealed as plain .* says secret/],
    ['a secret value of a secret its row says is sensitive', [here, put(secrets, secret(1, 1, 'sensitive'))], version(id, 1), /sealed as secret .* says sensitive/],
    ['a sensitive value of a secret its row says is plain', [here, put(secrets, secret(1, 1, 'plain'))], version(id, 1, null, true), /sealed as sensitive .* says plain/],
  ];
  for (const [what, writes, value, why] of tries) {
    await assert.rejects(change(vault, { read: nothing, decide: () => ({ writes, values: [value], entry: said('test.write'), answer: null }) }), why, what);
  }
  assert.equal(vault.woken.length, 0);
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT 1 FROM secrets UNION ALL SELECT 1 FROM secret_versions`), []);
  // And as it should be: written with its secret and its environment, plain or not.
  const project = put(projects, { id: environment.projectId, slug: 'market', name: 'Market', createdAt: at, archivedAt: null, folder: null });
  const done = await change(vault, { read: nothing, decide: () => ({ writes: [project, here, put(secrets, secret(1, 1, 'plain'))], values: [version(id, 1, 'x')], entry: said('test.write'), answer: null }) });
  assert.ok('answer' in done);
  // An environment the change drops is no place for a value, though it read it.
  const next = version(id, 2);
  const dropping = { place: part(environments, eq(environments.id, place)), held: part(secrets, eq(secrets.id, id)) };
  await assert.rejects(change(vault, { read: dropping, decide: ({ place: [was], held: [row] }) => ({ writes: [drop(environments, was!), put(secrets, secret(2, 2), row!)], values: [next], entry: said('test.write'), answer: null }) }), /that it read/);
});

test('a refused change is logged once a minute for who asked and what, and the log never costs its refusal', async (t) => {
  const refusing = (reason: string, actor: string | null = ada, action = 'member.role'): Operation<typeof nothing, null> => ({
    read: nothing,
    decide: () => ({ refused: reason }),
    denied: (_seen, _at, refusal) => (actor === null ? null : { action, actor, credential: null, request: null, ip: null, objects: [], detail: { refused: refusal.refused } }),
  });
  const logged = async () => (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(vault.owner, sql`SELECT kept, body, mac FROM log_pending ORDER BY id`)).map((row) => ({ kept: row.kept, ...entryOf(vault.keys, row)! }));

  // Twenty at once, before any has written: one entry between them.
  assert.deepEqual(await Promise.all(Array.from({ length: 20 }, () => change(vault, refusing('not_owner')))), Array.from({ length: 20 }, () => ({ refused: 'not_owner' })));
  assert.equal((await logged()).length, 1);
  const [first] = await logged();
  assert.deepEqual([first!.kept, first!.action, first!.actor, first!.detail, first!.rows], [false, 'member.role', ada, { refused: 'not_owner' }, []]);
  assert.equal(vault.woken.length, 1, 'the signer is told of it');
  // Again within the minute, for another reason even: nothing more. Another caller: theirs. One who does not stand: none.
  assert.deepEqual(await change(vault, refusing('last_owner')), { refused: 'last_owner' });
  assert.equal((await logged()).length, 1);
  await change(vault, refusing('not_owner', bo));
  await change(vault, refusing('unauthenticated', null));
  assert.deepEqual((await logged()).map((entry) => entry.actor), [ada, bo]);
  // The same caller refused something else: that is another entry, then once a minute too.
  await change(vault, refusing('no_access', bo, 'member.remove'));
  await change(vault, refusing('no_access', bo, 'member.remove'));
  assert.deepEqual((await logged()).map((entry) => `${entry.actor} ${entry.action}`), [`${ada} member.role`, `${bo} member.role`, `${bo} member.remove`]);
  vault.tick(59_999);
  await change(vault, refusing('not_owner'));
  assert.equal((await logged()).length, 3);
  vault.tick(1);
  await change(vault, refusing('not_owner'));
  assert.deepEqual((await logged()).map((entry) => entry.actor), [ada, bo, bo, ada]);
  // An operation that says nothing of its refusals logs none.
  await change(vault, { read: nothing, decide: () => ({ refused: 'no' }) });
  assert.equal((await logged()).length, 4);

  // The log held by someone else: the refusal is answered all the same, two seconds later, and said in the Worker's log.
  const errors = t.mock.method(console, 'error', () => {});
  vault.tick(60_000);
  let release!: () => void;
  const holding = vault.owner.transaction(async (tx) => {
    await tx.execute(sql`LOCK TABLE log_pending IN ACCESS EXCLUSIVE MODE`);
    await new Promise<void>((resolve) => (release = resolve));
  });
  await new Promise((resolve) => setTimeout(resolve, 100));
  try {
    assert.deepEqual(await change(vault, refusing('not_owner')), { refused: 'not_owner' });
    assert.equal(errors.mock.callCount(), 1);
  } finally {
    release();
    await holding;
  }
  // Not remembered as logged: the next one is.
  await change(vault, refusing('not_owner'));
  assert.equal((await logged()).length, 5);
  // An operation that cannot say its refusal: refused all the same, said in the vault's own log, and not in the audit log.
  assert.deepEqual(await change(vault, { read: nothing, decide: () => ({ refused: 'no' }), denied: () => { throw new Error('nothing to say'); } }), { refused: 'no' });
  assert.deepEqual([errors.mock.callCount(), (await logged()).length], [2, 5]);
});
