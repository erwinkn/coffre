import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { INSTANCE_ROLES, ROLES } from '@coffre/core/access';
import { deriveLogKey, sealEntry, type LogFields } from '@coffre/core/audit';
import { encrypt, ownerKey, type SecretContext } from '@coffre/core/envelope';
import type { Transaction } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { auditArchive, credentials, environments, grants, principals, projects, secrets, secretVersions } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { adopt, adopted } from '../src/adopt.ts';
import { keyOf, sealedBy, shapeOf, type Fresh } from '../src/rows.ts';
import { MIRRORED, Signer, type Finding } from '../src/signer.ts';
import { use, type Value } from '../src/use.ts';
import { emptyDatabase, memoryStore, openTestVault } from './database.ts';
import { amend, ask, credential, environment, grant, principal, project, rows, secret, user, value, write } from './world.ts';

/**
 * The vault's adoption of a database (docs/design/0.16.md, "Upgrade from
 * 0.14"): one as the migration from 0.14 leaves it, its rows with empty
 * MACs, its values in 0.14's envelope and its policy in the archive; and a
 * fresh one. Each check the adoption makes has a case it fails.
 */
const seed = randomBytes(32);
const vault = { ...(await openTestVault()), keys: [keyOf(seed)] };
after(() => vault.close());
const config = { keks: vault.keks, owners: ['root@acme.example'], signingKeys: [seed] };
const [ada, root] = [user('ada'), user('root')];

let store: ReturnType<typeof memoryStore>;
const signer = () => Signer.open({ db: vault.db, keys: vault.keys, now: vault.now, store, keepUsesDays: 90 });
/** The adoption, by the signer the object opens from its storage. */
const adopting = async (by?: Signer) => adopt(by ?? (await signer()), vault, config);
/** A signer told of what the vault committed, run once: what it found. */
async function signed(on?: Signer, full = false): Promise<Finding[]> {
  const running = on ?? (await signer());
  for (const hash of vault.woken.splice(0)) await running.wake(hash);
  await running.run(full);
  return running.take();
}

beforeEach(async () => {
  await emptyDatabase(vault.owner);
  vault.woken.length = 0;
  store = memoryStore();
});

const count = async (table: string, where = sql`true`) => (await rowsOf<{ n: number }>(vault.owner, sql`SELECT count(*)::int AS n FROM ${sql.identifier(table)} WHERE ${where}`))[0]!.n;
const unsealed = async () => {
  let n = 0;
  for (const table of MIRRORED) n += await count(shapeOf(table).name, sql`octet_length(mac) = 0`);
  return n;
};

/** 0.14's log, as the archive keeps it: an entry in the vault's name, under the MAC 0.14's vault gave it, or under none. */
let seq = 0n;
async function archived(action: string, metadata: object, more: Partial<LogFields> & { forged?: boolean } = {}): Promise<void> {
  const { forged, ...given } = more;
  const key = deriveLogKey(given.author ?? 'vault', seed);
  const fields: LogFields = {
    seq: (seq += 1n), author: key.author, keyId: key.keyId, occurredAt: Date.UTC(2026, 9, 1), actor: ada, action, decision: 'allow', code: null, subjectPrincipal: null,
    projectId: null, environmentId: null, secretId: null, secretVersionId: null, operationId: null, requestId: null, sourceIp: null, relatedSeq: null, metadata: JSON.stringify(metadata), ...given,
  };
  const prevHash = randomBytes(32);
  const { mac, hash } = sealEntry(forged === true ? { ...key, key: randomBytes(32) } : key, prevHash, fields);
  await vault.owner.insert(auditArchive).values({ ...fields, prevHash, mac, hash });
}

/** A value as 0.14 wrote it: envelope format 1, whose wrap names neither the version's number nor whether it is plain. */
async function value14(of: Fresh<typeof secrets>, text: string, more: { sensitive?: boolean; plain?: boolean; owner?: string } = {}): Promise<Fresh<typeof secrets>> {
  const ids = { projectId: of.projectId, environmentId: of.environmentId, secretId: of.id };
  const named: SecretContext = { ...ids, ...(more.owner === undefined ? {} : { owner: ownerKey(more.owner) }), ...(more.sensitive ? { sensitive: true } : {}) };
  const dek = randomBytes(32);
  const wrapped = await vault.keks.wrap(dek, named);
  const version = of.versions + 1;
  const row = {
    id: crypto.randomUUID(), secretId: of.id, version, envelopeVersion: 1, ...encrypt(Buffer.from(text), ids, dek), wrappedDek: wrapped.bytes, kekProvider: wrapped.kekProvider, kekId: wrapped.kekId, kekVersion: wrapped.kekVersion,
    createdAt: new Date(0), firstWrittenAt: new Date(0), createdBy: ada, plaintext: more.plain ? text : null, sensitive: more.sensitive === true,
  };
  versions.push(row);
  // Its nature as the migration leaves it, from the version's labels.
  return { ...of, versions: version, currentVersion: version, nature: more.sensitive ? 'sensitive' : more.plain ? 'plain' : 'secret' };
}
const versions: (typeof secretVersions.$inferInsert)[] = [];

/**
 * market/prod, with a fork, Ada's personal config; market/vault, which
 * 0.14's policy protects. Ada views market. Her CLI session's token is
 * `ada`. Written as the migration leaves rows: no MAC.
 */
async function upgraded() {
  const market = project('market');
  const [prod, vaulted, gone] = [environment(market, 'prod'), environment(market, 'vault'), environment(market, 'old~deleted-2026-10-05')];
  const dropped = project('legacy~deleted-2026-10-05');
  const within = environment(dropped, 'prod');
  const mine = environment(market, 'prod-ada', { parentId: prod.id, owner: ada });
  const database = await value14(await value14(secret(prod, 'DATABASE_URL'), 'postgres://old'), 'postgres://prod');
  const flag = await value14(secret(prod, 'FLAG'), 'on', { plain: true });
  const stripe = await value14(secret(prod, 'STRIPE_KEY'), 'sk_live', { sensitive: true });
  const own = await value14(secret(mine, 'DATABASE_URL'), 'postgres://ada', { owner: ada });
  const erased = { ...secret(prod, 'ERASED'), versions: 1, currentVersion: 1, nature: 'secret' as const };
  versions.push({ ...versions.at(-1)!, id: crypto.randomUUID(), secretId: erased.id, version: 1, ciphertext: Buffer.alloc(0), wrappedDek: Buffer.alloc(0), plaintext: null, sensitive: false });
  await vault.owner.insert(projects).values([market, dropped]);
  await vault.owner.insert(environments).values([prod, vaulted, mine, gone, within]);
  await vault.owner.insert(secrets).values([database, flag, stripe, own, erased]);
  await vault.owner.insert(secretVersions).values(versions.splice(0));
  await vault.owner.insert(principals).values([principal(ada)]);
  await vault.owner.insert(grants).values([grant(ada, 'viewer', { project: market })]);
  await vault.owner.insert(credentials).values([credential('ada', ada)]);
  await archived('policy.change', { policy: { roles: { viewer: { ...ROLES.viewer, name: 'Reader' } }, instanceRoles: {}, protected: [vaulted, gone, within].map((place) => ({ projectId: place.projectId, environmentId: place.id, at: 0 })) } });
  await archived('settings.change', { serviceAccounts: { projects: { only: [market.id] }, environments: 'all' } });
  // The instance's freeze is the app's, whose MAC the vault cannot check.
  await archived('workload.freeze', { target: 'instance' }, { author: 'app', occurredAt: Date.UTC(2026, 9, 2) });
  return { market, prod, vaulted, mine, database, flag, stripe, own, erased };
}

/** A use's values, by key: the value, or why not. */
async function reveal(label: string, place: string, keys: string[], mine = false): Promise<Record<string, string>> {
  const answer = await use(vault, ask(label, place, keys, { mine }));
  assert.ok(!('refused' in answer), JSON.stringify(answer));
  return Object.fromEntries(answer.values.map((each: Value) => [each.key, 'value' in each ? each.value.toString() : `refused: ${each.refused}`]));
}

test('a database as the upgrade leaves it is adopted: policy from the archive, every key wrapped again, every row sealed, then served', async () => {
  const w = await upgraded();
  assert.equal(await adopting(), true);

  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT id, name FROM roles WHERE NOT instance AND id = 'viewer'`), [{ id: 'viewer', name: 'Reader' }]);
  assert.equal(await count('roles'), Object.keys(ROLES).length + Object.keys(INSTANCE_ROLES).length);
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT slug FROM environments WHERE protected`), [{ slug: 'vault' }]);
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT service_accounts, workloads_frozen_at IS NOT NULL AS frozen FROM policy`), [{ service_accounts: JSON.stringify({ projects: { only: [w.market.id] }, environments: 'all' }), frozen: true }]);
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT id, role, status FROM principals ORDER BY id`), [{ id: ada, role: 'member', status: 'active' }, { id: root, role: 'owner', status: 'active' }]);
  // A deleted place the policy names, or one in a deleted project, protects nothing, as in 0.14.
  // Every key wrapped again, but the erased version's, which keeps its label and has nothing to open.
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT envelope_version AS format, count(*)::int AS n FROM secret_versions GROUP BY 1 ORDER BY 1`), [{ format: 1, n: 1 }, { format: 2, n: 5 }]);
  // Each secret's row says what its value opened as: the erased one's nothing, so the strictest.
  assert.deepEqual(await natures(), { 'prod DATABASE_URL': 'secret', 'prod FLAG': 'plain', 'prod STRIPE_KEY': 'sensitive', 'prod ERASED': 'sensitive', 'prod-ada DATABASE_URL': 'secret' });
  assert.equal(await unsealed(), 0);
  const [first] = await rowsOf<{ body: { action: string; detail: { archive: { seq: number }; rows: Record<string, number> } } }>(vault.owner, sql`SELECT body::jsonb AS body FROM log_pending`);
  assert.equal(first!.body.action, 'vault.adopt');
  assert.equal(first!.body.detail.archive.seq, Number(seq));
  assert.deepEqual(first!.body.detail.rows, { secret_versions: 5, projects: 2, environments: 5, secrets: 5, dismissed_keys: 0, principals: 2, grants: 1, roles: 12, policy: 1, identities: 0, bindings: 0, credentials: 1, device_logins: 0, enrollment_codes: 0, oauth_clients: 0 });

  // Not served before the signer has its mirror.
  assert.equal(await adopted(vault.db), false);
  assert.deepEqual(await signed(), []);
  assert.equal(await adopted(vault.db), true);

  assert.deepEqual(await reveal('ada', 'market/prod', ['DATABASE_URL', 'FLAG', 'STRIPE_KEY', 'ERASED']), {
    DATABASE_URL: 'postgres://prod',
    FLAG: 'on',
    STRIPE_KEY: 'refused: sensitive',
    ERASED: 'refused: unreadable',
  });
  await amend(vault, 'principals', sql`id = ${ada}`, { role: 'owner' });
  assert.deepEqual(await reveal('ada', 'market/prod-ada', ['DATABASE_URL']), { DATABASE_URL: 'postgres://ada' });
  const running = await signer();
  assert.deepEqual(await signed(running), []);
  // The first minute's check.
  assert.deepEqual(await signed(running, true), []);
});

/** What each secret's row says of its current value, by environment and key. */
async function natures(): Promise<Record<string, string | null>> {
  const found = await rowsOf<{ name: string; nature: string | null }>(vault.owner, sql`SELECT e.slug || ' ' || s.key AS name, s.nature FROM secrets s JOIN environments e ON e.id = s.environment_id`);
  return Object.fromEntries(found.map(({ name, nature }) => [name, nature]));
}

test("a secret's row says what its current value opened as, whatever the rows said before the adoption", async () => {
  const w = await upgraded();
  // Loosened behind 0.14 or after the migration, rows the adoption would seal as it finds them: a sensitive key, a
  // secret and an erased one marked plain, and a version marked as one 0.16 wrote, which the adoption does not open.
  await vault.owner.execute(sql`UPDATE secrets SET nature = 'plain' WHERE id IN (${w.stripe.id}, ${w.database.id}, ${w.erased.id})`);
  await vault.owner.execute(sql`UPDATE secret_versions SET envelope_version = 2 WHERE secret_id = ${w.own.id}`);
  // And an older version of another nature than the current one, which is the one the row takes: plain, as its column is its value.
  await vault.owner.execute(sql`UPDATE secret_versions SET plaintext = 'postgres://old' WHERE secret_id = ${w.database.id} AND version = 1`);
  assert.equal(await adopting(), true);
  assert.deepEqual(await natures(), { 'prod DATABASE_URL': 'secret', 'prod FLAG': 'plain', 'prod STRIPE_KEY': 'sensitive', 'prod ERASED': 'sensitive', 'prod-ada DATABASE_URL': 'sensitive' });
  assert.equal(await unsealed(), 0);
});

/**
 * The adoption run with a writer's transaction open beside it: `hold` before
 * it starts, then `then` once it waits on a row that writer holds, then the
 * writer's commit. What the adoption answers.
 */
async function racing(hold: (tx: Transaction) => Promise<unknown>, then: (tx: Transaction) => Promise<unknown>): Promise<boolean> {
  const [running] = await vault.owner.transaction(async (tx) => {
    await hold(tx);
    const adoption = adopting();
    let settled = false;
    adoption.then(() => (settled = true), () => (settled = true));
    for (;;) {
      const [{ waiting }] = await rowsOf<{ waiting: number }>(tx, sql`SELECT count(*)::int AS waiting FROM pg_locks WHERE NOT granted AND pg_backend_pid() = ANY(pg_blocking_pids(pid))`);
      if (waiting > 0 || settled) break;
    }
    await then(tx);
    // In an array, so that the transaction commits without waiting for the adoption, which waits for it.
    return [adoption];
  });
  return running!;
}

const sealedRow = async (id: string) => {
  const [row] = await vault.owner.select().from(secrets).where(sql`${secrets.id} = ${id}`);
  return sealedBy(vault.keys, secrets, row!) !== undefined;
};

test("a row a writer changes while the adoption runs is sealed with its current value's nature, or not at all", async () => {
  const w = await upgraded();
  // STRIPE_KEY shows no current value as the adoption begins, and its sensitive version once the adoption has passed
  // it by, marked plain: the row it seals says sensitive.
  await vault.owner.execute(sql`UPDATE secrets SET current_version = NULL, nature = NULL WHERE id = ${w.stripe.id}`);
  assert.equal(
    await racing(
      (tx) => tx.execute(sql`UPDATE projects SET name = name WHERE id = ${w.market.id}`),
      (tx) => tx.execute(sql`UPDATE secrets SET current_version = 1, nature = 'plain' WHERE id = ${w.stripe.id}`),
    ),
    true,
  );
  assert.equal((await natures())['prod STRIPE_KEY'], 'sensitive');
  assert.equal(await sealedRow(w.stripe.id), true);

  // DATABASE_URL shows its older version, plain, and a writer brings back its newer one, keeping that nature, between
  // the adoption's read of the row and its write: the row is left with a MAC over what it no longer holds.
  await emptyDatabase(vault.owner);
  store = memoryStore();
  const again = await upgraded();
  await vault.owner.execute(sql`UPDATE secret_versions SET plaintext = 'postgres://old' WHERE secret_id = ${again.database.id} AND version = 1`);
  await vault.owner.execute(sql`UPDATE secrets SET versions = 1, current_version = 1, nature = 'plain' WHERE id = ${again.database.id}`);
  assert.equal(
    await racing(
      (tx) => tx.execute(sql`UPDATE secrets SET versions = 2, current_version = 2 WHERE id = ${again.database.id}`),
      async () => {},
    ),
    true,
  );
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT current_version, nature FROM secrets WHERE id = ${again.database.id}`), [{ current_version: 2, nature: 'plain' }]);
  assert.equal(await sealedRow(again.database.id), false);
});

test('a fresh database is adopted with the roles as they ship and the Owners the configuration names, then served', async () => {
  assert.equal(await adopting(), true);
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT id, role, status FROM principals`), [{ id: root, role: 'owner', status: 'active' }]);
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT service_accounts, workloads_frozen_at FROM policy`), [{ service_accounts: '{"projects":"all","environments":"all"}', workloads_frozen_at: null }]);
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT id, name FROM roles WHERE NOT instance AND id = 'viewer'`), [{ id: 'viewer', name: ROLES.viewer.name }]);
  assert.equal(await unsealed(), 0);
  const [first] = await rowsOf<{ detail: { archive: null } }>(vault.owner, sql`SELECT body::jsonb -> 'detail' AS detail FROM log_pending`);
  assert.equal(first!.detail.archive, null);
  const running = await signer();
  assert.deepEqual(await signed(running), []);

  const market = project('market');
  const prod = environment(market, 'prod');
  await write(vault, ...rows('projects', market), ...rows('environments', prod), ...rows('secrets', await value(vault, secret(prod, 'API_KEY'), 'k')), ...rows('credentials', credential('root', root)));
  assert.deepEqual(await reveal('root', 'market/prod', ['API_KEY']), { API_KEY: 'k' });
  assert.deepEqual(await signed(running), []);
  assert.deepEqual(await signed(running, true), []);
});

/** Nothing adopted: no role, no entry, every key as 0.14 wrapped it, every row unsealed. */
async function untouched(): Promise<void> {
  assert.equal(await count('roles'), 0);
  assert.equal(await count('policy'), 0);
  assert.equal(await count('log_pending'), 0);
  assert.equal(await count('secret_versions', sql`envelope_version <> 1`), 0);
  assert.equal(await count('principals', sql`octet_length(mac) <> 0`), 0);
  assert.ok((await signer()).blank);
}

test("a policy.change in the vault's name it did not write stops the adoption, and so does a settings.change", async () => {
  await upgraded();
  await vault.owner.execute(sql`UPDATE audit_archive SET metadata = ${JSON.stringify({ policy: { roles: {}, instanceRoles: {}, protected: [] } })} WHERE action = 'policy.change'`);
  await assert.rejects(adopting(), /newest policy\.change, entry \d+ of audit_archive, does not carry its vault's MAC/);
  await untouched();

  await emptyDatabase(vault.owner);
  await upgraded();
  await archived('settings.change', { serviceAccounts: { projects: 'all', environments: 'all' } }, { forged: true });
  await assert.rejects(adopting(), /newest settings\.change, entry \d+ of audit_archive, does not carry its vault's MAC/);
  await untouched();
});

test('a value marked plain that is not its plaintext column stops the adoption, and so does a value that does not open as its row says', async () => {
  const w = await upgraded();
  await vault.owner.execute(sql`UPDATE secret_versions SET plaintext = 'postgres://prod' WHERE secret_id = ${w.database.id} AND version = 1`);
  await assert.rejects(adopting(), /version 1 of secret .* is marked plain, and its value is not its plaintext column/);
  await untouched();

  // Its sensitivity is in 0.14's wrap: relabelled, it does not open.
  await vault.owner.execute(sql`UPDATE secret_versions SET plaintext = NULL, sensitive = false WHERE secret_id = ${w.stripe.id}`);
  await vault.owner.execute(sql`UPDATE secret_versions SET plaintext = NULL WHERE secret_id = ${w.database.id}`);
  await assert.rejects(adopting(), /version 1 of secret .* does not open/);
  await untouched();

  // A ciphertext moved under another version's key does not decrypt.
  await vault.owner.execute(sql`UPDATE secret_versions SET sensitive = true WHERE secret_id = ${w.stripe.id}`);
  await vault.owner.execute(sql`UPDATE secret_versions v SET ciphertext = o.ciphertext, iv = o.iv, auth_tag = o.auth_tag FROM secret_versions o WHERE v.secret_id = ${w.database.id} AND o.secret_id = v.secret_id AND o.version <> v.version`);
  await assert.rejects(adopting(), /version \d of secret .* does not open: .*(authenticate|auth)/i);
  await untouched();
});

test('a database is adopted once: again, it changes nothing, and two vaults at once adopt it once', async () => {
  await upgraded();
  assert.equal(await adopting(), true);
  const before = await rowsOf(vault.owner, sql`SELECT body FROM log_pending`);
  assert.equal(await adopting(), false);
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT body FROM log_pending`), before);
  assert.deepEqual(await signed(), []);
  assert.equal(await adopting(), false);

  await emptyDatabase(vault.owner);
  store = memoryStore();
  await upgraded();
  assert.deepEqual((await Promise.all([adopting(), adopting()])).sort(), [false, true]);
  assert.equal(await count('log_pending'), 1);
  assert.deepEqual(await signed(), []);
});

test('a signer that died before signing the adoption finds its entry, and only fills its mirror and signs it', async () => {
  await upgraded();
  assert.equal(await adopting(), true);
  const dying = await signer();
  store.down = true;
  await assert.rejects(dying.run(false), /storage is down/);
  store.down = false;
  assert.equal(await adopted(vault.db), false);
  // Signed by a read without the rows, the mirror would hold none of them.
  const quick = await signer();
  await assert.rejects(quick.sign(await quick.read(false)), /signed by a run that reads the rows it sealed/);

  const next = await signer();
  assert.deepEqual(await signed(next), []);
  assert.equal(await adopted(vault.db), true);
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT body::jsonb ->> 'action' AS action FROM log`), [{ action: 'vault.adopt' }]);
  await amend(vault, 'principals', sql`id = ${ada}`, { role: 'auditor' });
  assert.deepEqual(await signed(next), []);
  assert.deepEqual(await signed(next, true), []);

  // A row the writer changes since is found at the next check, as any.
  await vault.owner.execute(sql`UPDATE principals SET mac = (SELECT mac FROM principals WHERE id = ${root}) WHERE id = ${ada}`);
  assert.deepEqual((await signed(next, true)).map((each) => each.found), ['row']);
});

/** Everything the log is, gone: what a database writer can do, and not to the signer's storage. */
const emptied = () => vault.owner.execute(sql`TRUNCATE log, log_pending, log_head, log_tiles, log_index`);

test('a database whose log was emptied behind its signer is not adopted again, and what was planted in it stays unsealed', async () => {
  await upgraded();
  assert.equal(await adopting(), true);
  const running = await signer();
  assert.deepEqual(await signed(running), []);
  // The writer plants an Owner and their session, then makes the database look as the upgrade leaves it.
  const mallory = user('mallory');
  await vault.owner.insert(principals).values(principal(mallory, { role: 'owner' }));
  await vault.owner.insert(credentials).values(credential('mallory', mallory));
  await emptied();
  await vault.owner.execute(sql`DELETE FROM roles; DELETE FROM policy`);
  await assert.rejects(adopting(running), /its signer has signed one or is told of one: someone emptied it/);
  await assert.rejects(adopting(), /someone emptied it/);
  assert.equal(await count('principals', sql`id = ${mallory} AND octet_length(mac) = 0`), 1);
  assert.equal(await count('roles'), 0);
  assert.equal(await adopted(vault.db), false);

  // Emptied between the commit and the signature: the signer was told of the entry.
  await emptyDatabase(vault.owner);
  store = memoryStore();
  await upgraded();
  assert.equal(await adopting(), true);
  await emptied();
  await assert.rejects(adopting(), /someone emptied it/);

  // Emptied before the signature, and the signer's run has reported the entry missing since: told of it, all the same.
  await emptyDatabase(vault.owner);
  store = memoryStore();
  await upgraded();
  const told = await signer();
  assert.equal(await adopting(told), true);
  await emptied();
  await vault.owner.execute(sql`DELETE FROM roles; DELETE FROM policy`);
  await vault.owner.insert(principals).values(principal(mallory, { role: 'owner' }));
  await vault.owner.insert(credentials).values(credential('mallory', mallory));
  assert.deepEqual((await signed(told)).map((each) => each.found), ['missing']);
  await assert.rejects(adopting(told), /someone emptied it/);
  await assert.rejects(adopting(), /someone emptied it/);
  assert.equal(await count('principals', sql`id = ${mallory} AND octet_length(mac) = 0`), 1);
  assert.equal(await adopted(vault.db), false);
});

test('an entry that waited before the adoption is refused, and the adoption follows', async () => {
  await upgraded();
  await vault.owner.execute(sql`INSERT INTO log_pending (kept, body, mac) VALUES (true, '{}', ${randomBytes(36)})`);
  // Something waits: the log may have begun, and only the signer can tell.
  assert.equal(await adopting(), false);
  const running = await signer();
  assert.deepEqual((await signed(running)).map((each) => each.found), ['forged']);
  // Its refusal leaves a head of no entry, which is no adoption.
  assert.equal(await count('log_head'), 1);
  assert.equal(await adopted(vault.db), false);
  assert.equal(await adopting(running), true);
  assert.deepEqual(await signed(running), []);
  assert.equal(await adopted(vault.db), true);
});

test('a full read that fails with the adoption waiting fails the run with its own error, and the next run signs it', async () => {
  await upgraded();
  const running = await signer();
  assert.equal(await adopting(running), true);
  const read = running.read.bind(running);
  running.read = (full) => (full ? Promise.reject(new Error('a table flooded')) : read(full));
  await assert.rejects(running.run(true), /a table flooded/);
  assert.equal(running.dead, false);
  assert.equal(await adopted(vault.db), false);
  running.read = read;
  assert.deepEqual(await signed(running), []);
  assert.equal(await adopted(vault.db), true);
});
