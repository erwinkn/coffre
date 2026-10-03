import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import test, { after, before } from 'node:test';

import { clientFor, openTestDatabase, resetDatabase, testDeps } from './api-fixture.ts';
import { SyncRunner } from '../src/api/syncs.ts';
import { environments, secrets, syncs } from './db/tables.ts';

const ROOT = 'admin@acme.example';
let db: Awaited<ReturnType<typeof openTestDatabase>>;
before(async () => { db = await openTestDatabase(); });
after(async () => { await db.close(); });

function gate() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

for (const custom of [false, true]) {
  test(`reset waits for a secret-triggered sync with ${custom ? 'custom' : 'default'} waitUntil`, async (t) => {
    await resetDatabase(db.owner);
    const background: Promise<unknown>[] = [];
    const run = SyncRunner.prototype.runForEnvironment;
    t.mock.method(SyncRunner.prototype, 'runForEnvironment', function (this: SyncRunner, id: string) {
      const promise = run.call(this, id);
      background.push(promise);
      return promise;
    });
    const observed: Promise<unknown>[] = [];
    const deps = testDeps(db.runtime, [ROOT], custom ? { waitUntil: (promise) => { observed.push(promise); } } : {});
    const root = clientFor(deps, ROOT);
    await root.projects.create('market', { name: 'Market' });
    await root.environments.create('market/prod', { name: 'Production' });
    await root.secrets.set('market/prod', { TOKEN: 'fake' });
    await Promise.all(background.splice(0));
    const [credential] = await db.owner.select().from(secrets);
    const syncId = randomUUID();
    await db.owner.insert(syncs).values({
      id: syncId,
      projectId: credential.projectId,
      environmentId: credential.environmentId,
      provider: 'github-actions',
      config: JSON.stringify({ owner: 'acme', repo: 'app' }),
      credentialSecretId: credential.id,
      createdBy: ROOT,
    });

    // The real runner has taken its lease and captured the environment. Its
    // missing grant produces an app audit entry when this vault call returns.
    const started = gate();
    const release = gate();
    const access = deps.vault.access;
    t.mock.method(deps.vault, 'access', async (principal: string) => {
      if (principal === `sync:${syncId}`) {
        started.resolve();
        await release.promise;
      }
      return access(principal);
    });
    await root.secrets.set('market/prod', { VALUE: 'changed' });
    await started.promise;

    let deleting = false;
    const finished = Promise.all(background);
    const owner = new Proxy(db.owner, {
      get(target, property) {
        if (property !== 'delete') return Reflect.get(target, property);
        return async (table: unknown) => {
          deleting = true;
          // Force the old ordering to expose the late audit entry, rather
          // than let SQL/network scheduling decide whether it lands in time.
          if (table === environments) await finished;
          return Reflect.apply(target.delete, target, [table]);
        };
      },
    });
    const resetting = resetDatabase(owner);
    try {
      await setImmediate();
      assert.equal(deleting, false, 'no table may be cleared while the sync is in flight');
    } finally {
      release.resolve();
      await finished;
      await resetting;
    }
    assert.deepEqual(await db.owner.select().from(environments), []);
    if (custom) assert.equal(observed.length, 2, 'the custom observer still receives both tasks');
  });
}
