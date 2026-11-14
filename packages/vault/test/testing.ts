// What another package's tests need of the vault's own: the suite's
// database written as a vault of a given configuration writes it, and that
// vault in process. `@coffre/vault/testing`, for the workspace's sources
// alone: it is not built, and a published package has none.
import type { Vault } from '@coffre/core/vault';

import { resolveVaultConfig, type VaultConfig } from '../src/config.ts';
import { openLocalVault } from '../src/local.ts';
import { Signer } from '../src/signer.ts';
import { prepareVault } from '../src/vault.ts';
import { memoryStore, openTestVault, type TestVault } from './database.ts';

export { APP_URL, emptyDatabase, slowPostgres, VAULT_URL, type TestVault } from './database.ts';
export * from './world.ts';

/**
 * The suite's database as a vault of `config` writes it, under its keys and
 * by the real clock, and that vault in process, through JSON as over any
 * transport. A Worker's vault of the same configuration reads what `world`
 * writes.
 */
export async function openConfiguredVault(config: VaultConfig): Promise<{ world: TestVault; vault: Vault }> {
  const prepared = prepareVault(resolveVaultConfig(config));
  const world = await openTestVault({ ...prepared, now: Date.now });
  return { world, vault: openLocalVault(world.db, prepared, { wake: world.wake, now: world.now }) };
}

/**
 * The signer over `world`'s database, as a deployment runs one beside the
 * vault, with its storage in memory and nothing pruned: `sign` tells it
 * what the vault committed since, and runs it until nothing waits. Rows a
 * test wrote with `write` are no change it signed, and what it finds of
 * them is left untaken: it signs the entries all the same.
 */
export async function signerOf(world: TestVault): Promise<{ sign(): Promise<void> }> {
  const signer = await Signer.open({ db: world.db, keys: world.keys, now: world.now, store: memoryStore(), keepUsesDays: null });
  return {
    async sign() {
      for (const hash of world.woken.splice(0)) await signer.wake(hash);
      while (await signer.run(false));
    },
  };
}

/** A log entry as the vault appends one to `log_pending`: for the load rig (packages/server/test/bench/load), which grows the log through the signer. */
export { pending } from '../src/entry.ts';
