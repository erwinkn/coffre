import { gated, VAULT_METHODS, versioned, type Vault, type VaultEntry } from '@coffre/core/vault';
import type { Database } from '@coffre/db';

import type { ResolvedVaultConfig } from './config.ts';
import { openVault, prepareVault, type VaultOptions } from './vault.ts';

/** Every call the vault answers, in the order of the `Vault` interface (`VAULT_METHODS` in @coffre/core/vault). */
export const METHODS = VAULT_METHODS;

/** The vault in this process: its one entry, `call`, gated as the Worker's is, and what lets go of its database. */
export type LocalVault = VaultEntry & { close(): Promise<void> };

/**
 * The vault in this process, over `db`, and `hot` for 0.15's uses (vault.ts,
 * `openVault`), behind the version gate's one entry (`gated`): a call on
 * another release runs nothing. Every argument and result goes through JSON
 * on the way, as it would over RPC or a socket, so what works here does not
 * rely on sharing objects with the caller; and every answer through the
 * envelope, as a Worker's does. The app speaks to it through `versioned`.
 * `close` is whatever lets go of the database, when the vault opened it.
 */
export async function openLocalVault(
  db: Database,
  config: ResolvedVaultConfig,
  options: VaultOptions = {},
  close: () => Promise<void> = async () => {},
  hot?: Database,
): Promise<LocalVault> {
  const vault: Required<Vault> = openVault(db, await prepareVault(config, options), hot);
  return {
    call: (release, method, args) => gated(release, method, args, async (name, given) => json(await (vault[name] as (...args: unknown[]) => Promise<unknown>)(...(json(given) as unknown[])))),
    close,
  };
}

function json(value: unknown): unknown {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

/** A vault in this process as code beside it speaks to it: the app's side of the envelope (`versioned`), with its entry and `close` kept. */
export type SpokenVault = Required<Vault> & LocalVault;

/**
 * `local`, spoken to through the version gate's envelope as the app speaks
 * to its vault (`versioned`): each method one gated `call`. For what holds a
 * vault in its own process, as the suites and benches do.
 */
export function spoken(local: LocalVault): SpokenVault {
  return Object.assign(Object.create(null) as object, versioned(local), { call: local.call, close: local.close }) as SpokenVault;
}
