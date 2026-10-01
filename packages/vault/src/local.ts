import type { Vault } from '@coffre/core/vault';
import type { Database } from '@coffre/db';

import type { ResolvedVaultConfig } from './config.ts';
import { openVault, prepareVault, type VaultOptions } from './vault.ts';

/** Every call the vault answers, in the order of the `Vault` interface. */
export const METHODS = [
  'unwrap',
  'wrap',
  'rewrap',
  'access',
  'setAccess',
  'admit',
  'remove',
  'checkpoint',
  'about',
  'log',
  'verifyLog',
] as const satisfies readonly (keyof Vault)[];

export type LocalVault = Vault & { close(): Promise<void> };

/**
 * The vault in this process, over `db`. Every argument and result goes
 * through JSON on the way, as it would over RPC or a socket, so what works
 * here does not rely on sharing objects with the caller. `close` is
 * whatever lets go of the database, when the vault opened it.
 */
export async function openLocalVault(
  db: Database,
  config: ResolvedVaultConfig,
  options: VaultOptions = {},
  close: () => Promise<void> = async () => {},
): Promise<LocalVault> {
  const vault = openVault(db, await prepareVault(config, options));
  const local = Object.fromEntries(
    METHODS.map((name) => [
      name,
      async (...args: unknown[]) =>
        json(await (vault[name] as (...args: unknown[]) => Promise<unknown>)(...(json(args) as unknown[]))),
    ]),
  ) as unknown as Vault;
  return Object.assign(local, { close });
}

function json(value: unknown): unknown {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}
