// What another package's tests need of the vault's own: the suite's
// database written as a vault of a given configuration writes it, and that
// vault in process. `@coffre/vault/testing`, for the workspace's sources
// alone: it is not built, and a published package has none.
import type { Vault } from '@coffre/core/vault';

import { resolveVaultConfig, type VaultConfig } from '../src/config.ts';
import { openLocalVault } from '../src/local.ts';
import { prepareVault } from '../src/vault.ts';
import { openTestVault, type TestVault } from './database.ts';

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
