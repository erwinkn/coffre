import { loadVaultConfig, type VaultConfig } from './config.ts';
import { libsqlStorage } from './libsql.ts';
import type { Vault } from './types.ts';
import { openVault, type VaultOptions } from './vault.ts';

const METHODS = [
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
 * The vault in this process, over a libSQL file of its own: for tests, and
 * for anything that runs coffre outside Workers. Every argument and result
 * goes through JSON on the way, as it would over RPC, so what works here
 * does not rely on sharing objects with the caller.
 */
export async function localVault(
  path: string,
  config: VaultConfig | Readonly<Record<string, string | undefined>>,
  options: VaultOptions = {},
): Promise<LocalVault> {
  const storage = libsqlStorage(path);
  const vault = await openVault(storage, 'keks' in config ? (config as VaultConfig) : loadVaultConfig(config), options);
  const local = Object.fromEntries(
    METHODS.map((name) => [
      name,
      async (...args: unknown[]) =>
        json(await (vault[name] as (...args: unknown[]) => Promise<unknown>)(...(json(args) as unknown[]))),
    ]),
  ) as unknown as Vault;
  return Object.assign(local, { close: () => storage.close() });
}

function json(value: unknown): unknown {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}
