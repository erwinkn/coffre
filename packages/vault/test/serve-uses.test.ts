// `serveVault` hands its options to the vault it runs (T230): a deployment's `uses` took no effect on Node, where the
// vault in its own process kept the default admission, the hot pool's size, whatever it set.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { versioned, type NamedUseInput, type NamedUseOutcome } from '@coffre/core/vault';

import { connectVault, serveVault, type VaultOptions } from '../src/node.ts';
import { type TestDatabase, openTestDatabase } from './database.ts';
import { namedWorld } from './named-world.ts';
import { emptyLog, KEK, SIGNING_KEY, useDatabases } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());
beforeEach(emptyLog);

/** `outcome`'s answer as a word: `ok`, `busy:<why>` or the refusal's code. */
function codeOf(outcome: NamedUseOutcome): string {
  assert.equal(outcome.served, true);
  const { outcome: used } = outcome as Extract<NamedUseOutcome, { served: true }>;
  return used.ok ? 'ok' : 'busy' in used ? `busy:${used.busy}` : used.code;
}

/** `asks`, all at once, to a vault `serveVault` runs over the world's database with `options`; what each is answered. */
async function burst(asks: () => NamedUseInput[], options?: VaultOptions): Promise<string[]> {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-vault-socket-'));
  const served = await serveVault({
    socket: join(dir, 'vault.sock'),
    database: db.vault,
    hotDatabase: await db.hot(),
    checkpointer: { memory: join(dir, 'memory') },
    kek: KEK,
    signingKey: SIGNING_KEY.toString('base64'),
    owners: ['root@acme.example'],
  }, options);
  try {
    const entry = versioned(connectVault(served.socket));
    // The vault's first call opens its state: the burst is after it, as a vault's in service is.
    await entry.about();
    return await Promise.all(asks().map(async (ask) => codeOf(await entry.useNamed!(ask))));
  } finally {
    await served.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

test('the uses a vault served over its socket may have in flight are the deployment\'s, not the hot pool\'s size', { timeout: 60_000 }, async () => {
  const w = await namedWorld(db);
  const name = await w.nameOf(await w.key('value'));
  const asks = () => Array.from({ length: 50 }, () => w.ask(name));

  // None in flight allowed: every use is refused before anything is read.
  assert.deepEqual(await burst(asks, { uses: { inFlight: 0 } }), Array(50).fill('busy:overloaded'));
  // Raised past a burst of fifty at once (the hot pool's ten otherwise, which refused most of it): none is refused.
  assert.deepEqual(await burst(asks, { uses: { inFlight: 5000 } }), Array(50).fill('ok'));
});
