import type { Vault } from '@coffre/core/vault';

import type { ResolvedVaultConfig } from './config.ts';
import { nodeSqlite } from './sqlite-node.ts';
import { openVault, type VaultOptions } from './vault.ts';

/** Every call the vault answers, in the order of the `Vault` interface. */
export const METHODS = [
  'unwrap',
  'wrap',
  'rewrap',
  'access',
  'members',
  'setAccess',
  'admit',
  'remove',
  'checkpoint',
  'latestCheckpoint',
  'log',
] as const satisfies readonly (keyof Vault)[];

export type LocalVault = Vault & { close(): void };

/**
 * The vault in this process, over a SQLite file of its own. Every argument
 * and result goes through JSON on the way, as it would over RPC or a socket,
 * so what works here does not rely on sharing objects with the caller.
 */
export async function openLocalVault(
  path: string,
  config: ResolvedVaultConfig,
  options: VaultOptions = {},
): Promise<LocalVault> {
  const db = nodeSqlite(path);
  const vault = await openVault(db, config, options).catch((error: unknown) => {
    db.close();
    throw error;
  });
  const local = Object.fromEntries(
    METHODS.map((name) => [
      name,
      async (...args: unknown[]) =>
        json(await (vault[name] as (...args: unknown[]) => Promise<unknown>)(...(json(args) as unknown[]))),
    ]),
  ) as unknown as Vault;
  return Object.assign(local, { close: () => db.close() });
}

function json(value: unknown): unknown {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}
