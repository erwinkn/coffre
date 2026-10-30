// What 0.15's cutover from 0.14 costs (docs/design/0.15-plan.md, PR 9), on an instance of `keys` keys and `grants`
// grants over `members` service accounts, kept by 0.14's log alone: the members admitted and granted through the
// vault's own decisions, so that every row is as 0.14 accepts it, and the keys written as rows, each with a version
// (the cutover opens none). Then a 0.15 vault cuts it over, the app vouching for nothing (no credential, binding or
// deleted place), twice: once with 0.14's chain checkpointed to its head first, as a deployment's scheduled beat
// keeps it, once without (the walk from its first entry). Each run on a database of its own, made by
// scripts/setup-test-database.sh; on a Postgres of your own, never the shared one.
//
//   COFFRE_TEST_DATABASE=<name> ./scripts/setup-test-database.sh
//   node --conditions=coffre:source packages/vault/scripts/cutover-bench.ts <owner url> <vault url> [keys] [grants] [members] [checkpointed]
import { randomBytes, randomUUID } from 'node:crypto';

import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import { createDatabase } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';

import type { ResolvedVaultConfig } from '../src/config.ts';
import { openLocalVault } from '../src/local.ts';

const [ownerUrl, vaultUrl, keysArg, grantsArg, membersArg, checkpointedArg] = process.argv.slice(2);
if (ownerUrl === undefined || vaultUrl === undefined) throw new Error('usage: cutover-bench.ts <owner url> <vault url> [keys] [grants] [members] [checkpointed]');
const keys = Number(keysArg ?? 10_000);
const grants = Number(grantsArg ?? 20_000);
const members = Number(membersArg ?? 1_000);
const checkpointed = (checkpointedArg ?? 'true') === 'true';
const ROOT = 'user:root@acme.example';
const PROJECTS = 100;
const ENVIRONMENTS = 3;

const config: ResolvedVaultConfig = {
  keks: new KekRegistry(LocalKekProvider.generate('bench')),
  owners: ['root@acme.example'],
  signingKeys: [randomBytes(32)],
  bulkLimit: { count: 1000, windowMs: 15 * 60_000 },
};
const owner = postgresClient(ownerUrl, { max: 4 });
const database = createDatabase(postgresClient(vaultUrl, { max: 8 }));
const ms = (from: bigint) => Number(process.hrtime.bigint() - from) / 1e6;

// The places: projects, each with dev, staging and prod.
const places: { project: string; environment: string }[] = [];
for (let p = 0; p < PROJECTS; p++) {
  const project = randomUUID();
  await owner.unsafe('INSERT INTO projects (id, slug, name) VALUES ($1, $2, $3)', [project, `p${p}`, `P${p}`]);
  for (const slug of ['dev', 'staging', 'prod'].slice(0, ENVIRONMENTS)) {
    const environment = randomUUID();
    await owner.unsafe('INSERT INTO environments (id, project_id, slug, name) VALUES ($1, $2, $3, $3)', [environment, project, slug]);
    places.push({ project, environment });
  }
}

// The keys, as rows: a version each, current, its wrapped key random bytes.
let started = process.hrtime.bigint();
await owner.unsafe(`
  WITH made AS (
    SELECT gen_random_uuid() AS id, gen_random_uuid() AS version, i FROM generate_series(1, $1) AS i
  ), placed AS (
    SELECT m.*, (SELECT e.id FROM environments e ORDER BY e.id OFFSET (m.i % $2) LIMIT 1) AS environment FROM made m
  ), keyed AS (
    INSERT INTO secrets (id, project_id, environment_id, key)
    SELECT p.id, e.project_id, e.id, 'KEY_' || p.i FROM placed p JOIN environments e ON e.id = p.environment
    RETURNING id
  ), versioned AS (
    INSERT INTO secret_versions (id, secret_id, version, envelope_version, ciphertext, iv, auth_tag, wrapped_dek, kek_provider, kek_id, kek_version, created_by, sensitive)
    SELECT p.version, p.id, 1, 1, '\\x00'::bytea, '\\x000000000000000000000000'::bytea, '\\x00000000000000000000000000000000'::bytea, decode(md5(random()::text) || md5(random()::text), 'hex'), 'local', 'bench', '1', $3, false
      FROM placed p WHERE p.id IN (SELECT id FROM keyed)
    RETURNING id, secret_id
  )
  UPDATE secrets s SET current_version_id = v.id, current_version = 1 FROM versioned v WHERE v.secret_id = s.id`, [keys, places.length, ROOT]);
console.log(`${keys} keys written in ${ms(started).toFixed(0)} ms`);

// The members, each admitted with their grants in one decision of 0.14's, so their rows and entries are 0.14's own.
const old = await openLocalVault(database, config, { log: '0.14' });
if ((await old.access(ROOT)).role !== 'owner') throw new Error('the deployment names root its Owner');
started = process.hrtime.bigint();
const each = Math.ceil(grants / members);
for (let m = 0; m < members; m++) {
  const changes = Array.from({ length: Math.min(each, places.length) }, (_, g) => places[(m * each + g) % places.length]!)
    .map(({ project, environment }) => ({ projectId: project, environmentId: environment, role: 'viewer', expiresAt: null }));
  const outcome = await old.setAccess({ actor: ROOT, caller: 'person', principal: `token:svc-${m}`, admit: true, changes });
  if (!outcome.ok) throw new Error(JSON.stringify(outcome));
}
console.log(`${members} members, ${members * Math.min(each, places.length)} grants, decided in ${ms(started).toFixed(0)} ms`);
if (checkpointed) {
  started = process.hrtime.bigint();
  for (let signed = await old.checkpoint(); ; signed = await old.checkpoint()) {
    if (!signed.ok) throw new Error(JSON.stringify(signed));
    const [head] = await owner.unsafe<{ next_seq: string }[]>('SELECT next_seq FROM audit_chain_head');
    if (BigInt(signed.checkpoint.seq) >= BigInt(head!.next_seq) - 2n) break;
  }
  console.log(`0.14's chain checkpointed to its head in ${ms(started).toFixed(0)} ms`);
}
const [{ entries }] = await owner.unsafe<{ entries: string }[]>('SELECT count(*) AS entries FROM audit_log');

// The cutover: the app's two calls, timed apart, and the whole.
const vault = await openLocalVault(database, config, { log: '0.15', sealThrough: async () => ({}) as never });
started = process.hrtime.bigint();
const asked = await vault.cutover!();
if (!asked.ok || asked.done) throw new Error(JSON.stringify(asked));
const askedMs = ms(started);
const [head] = await owner.unsafe<{ next_seq: string; head_hash: Buffer }[]>('SELECT next_seq, head_hash FROM audit_chain_head');
const to = { seq: (BigInt(head!.next_seq) - 1n).toString(), hash: Buffer.from(head!.head_hash).toString('hex') };
started = process.hrtime.bigint();
const outcome = await vault.cutover!({ checked: { from: asked.from, to }, credentials: [], bindings: [], connections: [], deleted: [] });
const cutMs = ms(started);
if (!outcome.ok) throw new Error(JSON.stringify(outcome));
const [{ sealed }] = await owner.unsafe<{ sealed: string }[]>("SELECT count(*) AS sealed FROM log_changes WHERE payload::jsonb ->> 'op' = 'genesis'");
console.log(JSON.stringify({ keys, grants: members * Math.min(each, places.length), members, environments: places.length, entries: Number(entries), checkpointed, sealed: Number(sealed), askMs: Math.round(askedMs), cutoverMs: Math.round(cutMs) }));
await owner.end();
process.exit(0);
