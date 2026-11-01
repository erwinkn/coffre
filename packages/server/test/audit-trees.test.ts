// GET /audit/trees: 0.15's log as the vault's verifier finds it (docs/design/0.15-plan.md, PR 8), for whoever reads the
// whole log. With 0.14's log alone there is nothing more to check; with 0.15's, the app's writes are changes sealed by
// a checkpointer that runs here, and a checkpoint the database's writer forges is named.
import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

import { tablesOf } from '@coffre/db';
import { derivedSigningKey } from '@coffre/vault';
import { runCheckpointer, type RunningCheckpointer } from '@coffre/vault/node';
import { desc, eq } from 'drizzle-orm';

import { clientFor, openTestDatabase, resetDatabase, testDeps, testVault } from './api-fixture.ts';
import { openVaultDatabase } from './db/engine.ts';

const db = await openTestDatabase();
const scratch = mkdtempSync(join(tmpdir(), 'coffre-trees-'));
const running: RunningCheckpointer[] = [];
beforeEach(async () => {
  for (const checkpointer of running.splice(0)) await checkpointer.stop();
  await resetDatabase(db.owner);
  const { logUses, logBulk, logCheckpoints, logTiles } = tablesOf(db.owner);
  for (const table of [logUses, logBulk, logCheckpoints, logTiles]) await db.owner.delete(table);
});
after(async () => {
  for (const checkpointer of running.splice(0)) await checkpointer.stop();
  await resetDatabase(db.owner);
  await db.close();
  rmSync(scratch, { recursive: true, force: true });
});

/** An instance whose vault keeps 0.15's log, each change sealed by a checkpointer over the vault's login before it answers. */
async function sealedInstance() {
  const kek = randomBytes(32);
  const checkpointer = await runCheckpointer({
    database: await openVaultDatabase(),
    signingKeys: [derivedSigningKey(kek)],
    memory: join(scratch, `memory-${running.length}-${Date.now()}`),
    intervalMs: 60_000,
  });
  running.push(checkpointer);
  const vault = testVault(['root@acme.example'], {}, { kek }, {}, { log: '0.15', sealThrough: checkpointer.sealThrough, heldOutside: checkpointer.heldOutside });
  return testDeps(db.runtime, ['root@acme.example'], { vault });
}

test("GET /audit/trees: nothing to check with 0.14's log alone", async () => {
  const deps = testDeps(db.runtime, ['root@acme.example'], { vault: testVault(['root@acme.example'], {}, { kek: randomBytes(32) }, {}, { log: '0.14' }) });
  const root = clientFor(deps, 'root@acme.example');
  await root.me();
  assert.deepEqual(await root.audit.verifyTrees(), { kept: false });
});

test("GET /audit/trees: 0.15's log verified from its newest checkpoint, then a forged checkpoint named; only for whoever reads the whole log", async () => {
  const deps = await sealedInstance();
  const root = clientFor(deps, 'root@acme.example');
  await root.me();
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod');

  // The newest checkpoint, which sealed each change before it answered, and the entries above it.
  const checked = await root.audit.verifyTrees();
  assert.ok(checked.kept && checked.ok && checked.checkpoint !== null, JSON.stringify(checked));

  // Someone who reads part of the log cannot check it.
  await root.members.add('user:ada@acme.example', {});
  await assert.rejects(clientFor(deps, 'ada@acme.example').audit.verifyTrees(), (error: { status?: number }) => error.status === 403);

  // Last, as no change seals over it after: the database's writer swaps the newest checkpoint's notes for an older
  // one's, not the pair the log signed there.
  const { logCheckpoints } = tablesOf(db.owner);
  const [newest, older] = await db.owner.select().from(logCheckpoints).orderBy(desc(logCheckpoints.upto)).limit(2);
  await db.owner.update(logCheckpoints).set({ changesNote: older!.changesNote }).where(eq(logCheckpoints.upto, newest!.upto));
  const broken = await root.audit.verifyTrees();
  assert.ok(broken.kept && !broken.ok && broken.problems.length > 0, JSON.stringify(broken));
});
