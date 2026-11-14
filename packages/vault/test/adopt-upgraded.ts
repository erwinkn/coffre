import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { KekRegistry, keyCheckOf, LocalKekProvider } from '@coffre/core/kek';
import { openDatabase } from '@coffre/db/connect';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { adopt, adopted } from '../src/adopt.ts';
import { keyOf, shapeOf } from '../src/rows.ts';
import { MIRRORED, Signer } from '../src/signer.ts';
import { memoryOf, use, type Value } from '../src/use.ts';
import { memoryStore, type TestVault } from './database.ts';
import { vaultWorker } from './workers/boot.ts';
import { amend, ask, credential, environment, project, rows, secret, user, value, write } from './world.ts';

/**
 * The vault's adoption of the two databases scripts/test-upgrade.sh leaves
 * on its cluster: `coffre_upgraded`, 0.14's rows as the upgrade converted
 * them (packages/db/test/upgrade/from-0.14.ts, whose keys these are), and
 * `coffre_fresh`, migrated from nothing. Each is adopted, its first entry
 * signed, a use and a change made through the new engine, and the signer's
 * first minute's check finds nothing. Then a copy of `coffre_upgraded`,
 * made before either is adopted, is adopted by the vault Worker in workerd
 * at its first call, as a deployment's is. `DATABASE_URL` is the cluster's
 * owner's.
 */
const cluster = new URL(process.env.DATABASE_URL ?? '');
const urlOf = (database: string, login?: string) => {
  const url = new URL(cluster);
  url.pathname = `/${database}`;
  if (login !== undefined) [url.username, url.password] = login.split(':') as [string, string];
  return url.toString();
};
const SEED = Buffer.alloc(32, 8);
const keks = new KekRegistry(new LocalKekProvider(Buffer.alloc(32, 7), 'k'));
const ADA = 'user:ada@acme.example';

/** `coffre_upgraded` as the upgrade left it, for the vault Worker to adopt: copied before any test here adopts it. */
const WORKERS = 'coffre_upgraded_workers';
{
  const cluster = await openDatabase(urlOf('postgres'));
  await cluster.db.execute(sql.raw(`DROP DATABASE IF EXISTS ${WORKERS}`));
  await cluster.db.execute(sql.raw(`CREATE DATABASE ${WORKERS} TEMPLATE coffre_upgraded`));
  await cluster.close();
}

async function vaultOn(database: string): Promise<TestVault> {
  const [owner, own] = await Promise.all([openDatabase(urlOf(database)), openDatabase(urlOf(database, 'coffre_vault_runtime:local-vault-only'))]);
  const woken: Buffer[] = [];
  let now = Date.now();
  const vault: TestVault = {
    db: own.db, owner: owner.db, keys: [keyOf(SEED)], keks, cap: { count: 1000, windowMs: 15 * 60_000 }, workloads: { noReads: false, useOnly: false }, memory: memoryOf(2), refused: new Map(), owners: [],
    about: { kek: { provider: 'local', id: 'k' }, previous: [], checks: [keyCheckOf(SEED)] },
    now: () => now, tick: (ms) => void (now += ms), wake: (hash) => void woken.push(hash), woken,
    close: async () => void (await Promise.all([owner.close(), own.close()])),
  };
  after(() => vault.close());
  return vault;
}

/** Adopted, and its first entry signed: a signer, run once, that found nothing. */
async function adoptedOn(vault: TestVault): Promise<Signer> {
  const signer = await Signer.open({ db: vault.db, keys: vault.keys, now: vault.now, store: memoryStore(), keepUsesDays: 90 });
  assert.equal(await adopt(signer, vault, { keks, owners: ['root@acme.example'], signingKeys: [SEED] }), true);
  for (const table of MIRRORED) assert.deepEqual(await rowsOf(vault.owner, sql`SELECT count(*)::int AS n FROM ${table} WHERE octet_length(mac) = 0`), [{ n: 0 }], shapeOf(table).name);
  assert.deepEqual(await runOf(signer, vault), []);
  assert.equal(await adopted(vault.db), true);
  return signer;
}
async function runOf(signer: Signer, vault: TestVault, full = false) {
  for (const hash of vault.woken.splice(0)) await signer.wake(hash);
  await signer.run(full);
  return signer.take();
}
async function reveal(vault: TestVault, token: Buffer, place: string, keys: string[]) {
  const answer = await use(vault, { ...ask('', place, keys), token });
  assert.ok(!('refused' in answer), JSON.stringify(answer));
  return Object.fromEntries(answer.values.map((each: Value) => [each.key, 'value' in each ? each.value.toString() : `refused: ${each.refused}`]));
}

test('a database upgraded from 0.14 is adopted, then served by the new engine and checked by the signer', async () => {
  const vault = await vaultOn('coffre_upgraded');
  const signer = await adoptedOn(vault);
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT p.slug || '/' || e.slug AS place FROM environments e JOIN projects p ON p.id = e.project_id WHERE e.protected`), [{ place: 'market/dev' }]);
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT name FROM roles WHERE NOT instance AND id = 'viewer'`), [{ name: 'Reader' }]);
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT service_accounts, workloads_frozen_at FROM policy`), [{ service_accounts: '{"projects":"all","environments":{"only":["dev"]}}', workloads_frozen_at: null }]);
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT envelope_version AS format, count(*)::int AS n FROM secret_versions GROUP BY 1 ORDER BY 1`), [{ format: 1, n: 1 }, { format: 2, n: 10 }]);
  // The adoption wraps each data key again, and leaves a version's ciphertext, IV and tag: 0.14's restores are still told
  // apart by them, and each version's first date is still the first among its key's versions with its IV and tag.
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT v.id FROM secret_versions v
    WHERE v.first_written_at <> (SELECT min(w.created_at) FROM secret_versions w WHERE w.secret_id = v.secret_id AND w.iv = v.iv AND w.auth_tag = v.auth_tag)`), []);
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT count(DISTINCT (ciphertext, iv, auth_tag))::int AS values, count(DISTINCT wrapped_dek)::int AS keys FROM secret_versions v JOIN secrets s ON s.id = v.secret_id WHERE s.key = 'RESTORED'`), [{ values: 2, keys: 4 }]);
  const [{ archive }] = await rowsOf<{ archive: { seq: number } }>(vault.owner, sql`SELECT body::jsonb -> 'detail' -> 'archive' AS archive FROM log WHERE seq = 0`);
  assert.equal(archive.seq, (await rowsOf<{ seq: number }>(vault.owner, sql`SELECT max(seq)::int AS seq FROM audit_archive`))[0]!.seq);

  // Ada's CLI session, as 0.14 issued it: its token hashes to 51 repeated.
  const ada = Buffer.alloc(32, 51);
  assert.deepEqual(await reveal(vault, ada, 'market/prod', ['DATABASE_URL', 'STRIPE_KEY']), { DATABASE_URL: 'refused: sensitive', STRIPE_KEY: 'pk_live' });
  await amend(vault, 'principals', sql`id = ${ADA}`, { role: 'owner' });
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT role FROM principals WHERE id = ${ADA}`), [{ role: 'owner' }]);
  assert.deepEqual(await runOf(signer, vault), []);
  assert.deepEqual(await runOf(signer, vault, true), []);
});

test('a fresh database is adopted with its Owners, then served by the new engine and checked by the signer', async () => {
  const vault = await vaultOn('coffre_fresh');
  const signer = await adoptedOn(vault);
  const root = user('root');
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT id, role FROM principals`), [{ id: root, role: 'owner' }]);
  const market = project('market');
  const prod = environment(market, 'prod');
  await write(vault, ...rows('projects', market), ...rows('environments', prod), ...rows('secrets', await value(vault, secret(prod, 'API_KEY'), 'k')), ...rows('credentials', credential('root', root)));
  assert.deepEqual(await reveal(vault, ask('root', 'market/prod', null).token, 'market/prod', ['API_KEY']), { API_KEY: 'k' });
  assert.deepEqual(await runOf(signer, vault), []);
  assert.deepEqual(await runOf(signer, vault, true), []);
});

test('in workerd, the vault Worker adopts a database upgraded from 0.14 at its first call, a 0.14 service token\'s use, then serves it', { timeout: 120_000 }, async () => {
  const vault = await vaultOn(WORKERS);
  const worker = await vaultWorker(urlOf(WORKERS, 'coffre_vault_runtime:local-vault-only'), { id: 'k', key: Buffer.alloc(32, 7).toString('base64'), signingKey: SEED.toString('base64') });
  try {
    assert.equal((await worker.status()).adopted, false);
    // CI's service token, as 0.14 issued it, which has since expired: its token hashes to 52 repeated. Answered as such, once the database is adopted.
    const first = await worker.reveal(`sha256:${Buffer.alloc(32, 52).toString('hex')}`, 'market/dev', null);
    assert.deepEqual([first.status, first.body], [401, { refused: 'unauthenticated' }]);
    const status = await worker.status();
    assert.deepEqual([status.adopted, status.adoption, status.standing], [true, null, []]);
    for (const table of MIRRORED) assert.deepEqual(await rowsOf(vault.owner, sql`SELECT count(*)::int AS n FROM ${table} WHERE octet_length(mac) = 0`), [{ n: 0 }], shapeOf(table).name);
    assert.deepEqual(await rowsOf(vault.owner, sql`SELECT body::jsonb ->> 'action' AS action FROM log ORDER BY seq`), [{ action: 'vault.adopt' }]);
    assert.equal(await adopted(vault.db), true);
    // Ada's CLI session, as 0.14 issued it: the value reads.
    const read = await worker.reveal(`sha256:${Buffer.alloc(32, 51).toString('hex')}`, 'market/prod', ['DATABASE_URL', 'STRIPE_KEY']);
    assert.deepEqual([read.status, read.body.values.map((each) => ('value' in each ? [each.key, each.value] : [each.key, each.refused]))], [200, [['DATABASE_URL', 'sensitive'], ['STRIPE_KEY', 'pk_live']]]);
  } finally {
    await worker.stop();
  }
});
