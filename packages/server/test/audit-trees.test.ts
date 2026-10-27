// GET /audit/trees: 0.15's log as the vault's verifier finds it (docs/design/0.15-plan.md, PR 8), for whoever reads the
// whole log. With 0.14's log alone there is nothing more to check; with 0.15's, the app's writes are changes sealed by
// a checkpointer that runs here, and a row the app's database writer changes is named.
import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

import { tablesOf } from '@coffre/db';
import { derivedSigningKey } from '@coffre/vault';
import { runCheckpointer, type RunningCheckpointer } from '@coffre/vault/node';
import { eq } from 'drizzle-orm';

import { clientFor, openTestDatabase, resetDatabase, testDeps, testVault } from './api-fixture.ts';
import { openVaultDatabase } from './db/engine.ts';

const db = await openTestDatabase();
const scratch = mkdtempSync(join(tmpdir(), 'coffre-trees-'));
const running: RunningCheckpointer[] = [];
beforeEach(async () => {
  for (const checkpointer of running.splice(0)) await checkpointer.stop();
  await resetDatabase(db.owner);
  const { logUses, logBulk, logCheckpoints, logTiles, logReplays } = tablesOf(db.owner);
  for (const table of [logUses, logBulk, logCheckpoints, logTiles, logReplays]) await db.owner.delete(table);
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
    seed: derivedSigningKey(kek),
    memory: join(scratch, `memory-${running.length}-${Date.now()}`),
    intervalMs: 60_000,
  });
  running.push(checkpointer);
  const vault = testVault(['root@acme.example'], {}, { kek }, {}, { log: '0.15', sealThrough: checkpointer.sealThrough });
  return testDeps(db.runtime, ['root@acme.example'], { vault });
}

test("GET /audit/trees: nothing to check with 0.14's log alone", async () => {
  const deps = testDeps(db.runtime, ['root@acme.example'], { vault: testVault(['root@acme.example'], {}, { kek: randomBytes(32) }, {}, {}) });
  const root = clientFor(deps, 'root@acme.example');
  await root.me();
  assert.deepEqual(await root.audit.verifyTrees(), { kept: false });
});

test("GET /audit/trees: 0.15's log verified, then a row changed around the app named; only for whoever reads the whole log", async () => {
  const deps = await sealedInstance();
  const root = clientFor(deps, 'root@acme.example');
  await root.me();
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod');

  const checked = await root.audit.verifyTrees();
  assert.ok(checked.kept && checked.ok && checked.done, JSON.stringify(checked));
  assert.ok(checked.sealed > 0);
  // The whole walk, from the first entry: the same verdict.
  const whole = await root.audit.verifyTreesWhole();
  assert.ok(whole.kept && whole.ok && whole.done && whole.from === null, JSON.stringify(whole));

  // The database's writer renames `prod` out from under its seal: a slug-scoped role decides on it.
  const { environments } = tablesOf(db.owner);
  await db.owner.update(environments).set({ slug: 'staging' }).where(eq(environments.slug, 'prod'));
  const broken = await root.audit.verifyTrees();
  assert.ok(broken.kept && !broken.ok);
  assert.ok(broken.problems.some((p) => /^the environment [0-9a-f-]{36}: its rows are not the object the log makes$/.test(p)), broken.problems.join('\n'));

  // Someone who reads part of the log cannot check it whole.
  await root.members.add('user:ada@acme.example', {});
  await assert.rejects(clientFor(deps, 'ada@acme.example').audit.verifyTrees(), (error: { status?: number }) => error.status === 403);
});
