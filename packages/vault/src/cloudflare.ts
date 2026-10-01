/**
 * The vault as a Worker, behind an entrypoint the app's `VAULT` service
 * binding calls over RPC. It has no route and no HTTP surface. It decides
 * in the database the app uses, through a Hyperdrive binding of its own,
 * whose login is the vault's:
 *
 *   import { postgres, vault } from '@coffre/vault/cloudflare';
 *
 *   export default vault((env: Env) => ({
 *     database: postgres(env.HYPERDRIVE),
 *     kek: { id: 'kek-1', key: env.KEK }, // or awsKms({ keyArn, credentials })
 *     rootAdmins: ['admin@acme.example'],
 *     signingKey: env.SIGNING_KEY,
 *   }));
 *
 * Any number of isolates run it side by side: every decision locks what it
 * is about in the database, so they share one log and one bulk limit.
 */
import type {
  AdmitInput,
  CheckpointInput,
  LogInput,
  RemoveInput,
  RewrapInput,
  SetAccessInput,
  UnwrapInput,
  Vault,
  VerifyLogInput,
  WrapInput,
} from '@coffre/core/vault';
import { createDatabase } from '@coffre/db';
import { HyperdrivePool, type PostgresDatabase } from '@coffre/db/hyperdrive';
import { WorkerEntrypoint } from 'cloudflare:workers';

import { resolveVaultConfig, type VaultConfig } from './config.ts';
import { openVault, prepareVault, type PreparedVault } from './vault.ts';

export type { Vault, VaultConfig };
export { postgres, type PostgresDatabase } from '@coffre/db/hyperdrive';
export * from './index.ts';

/** What the vault Worker's `vault(env => …)` returns. */
export type WorkersVaultConfig = VaultConfig & { database: PostgresDatabase };

/** Set when the Worker's module runs `vault(…)`, before any call comes in. */
let configure: ((env: never) => WorkersVaultConfig) | null = null;

/** The configuration, checked and made ready once per `env`, which the isolate keeps. */
const ready = new WeakMap<object, Promise<{ database: PostgresDatabase; prepared: PreparedVault }>>();

/**
 * What the app's `VAULT` service binding calls. Each call gets a database of
 * its own, since a Worker's connections belong to the call that made them.
 */
export class VaultEntrypoint extends WorkerEntrypoint implements Vault {
  async #vault(): Promise<Vault> {
    const env = this.env as object;
    let entry = ready.get(env);
    if (entry === undefined) {
      if (configure === null) throw new Error('the vault Worker must export default vault(…)');
      const config = configure(env as never);
      entry = prepareVault(resolveVaultConfig(config)).then((prepared) => ({ database: config.database, prepared }));
      ready.set(env, entry);
      entry.catch(() => ready.delete(env));
    }
    const { database, prepared } = await entry;
    return openVault(createDatabase(new HyperdrivePool(database.hyperdrive.connectionString)), prepared);
  }

  async unwrap(input: UnwrapInput) { return (await this.#vault()).unwrap(input); }
  async wrap(input: WrapInput) { return (await this.#vault()).wrap(input); }
  async rewrap(input: RewrapInput) { return (await this.#vault()).rewrap(input); }
  async access(principal: string) { return (await this.#vault()).access(principal); }
  async members() { return (await this.#vault()).members(); }
  async setAccess(input: SetAccessInput) { return (await this.#vault()).setAccess(input); }
  async admit(input: AdmitInput) { return (await this.#vault()).admit(input); }
  async remove(input: RemoveInput) { return (await this.#vault()).remove(input); }
  async checkpoint(input: CheckpointInput) { return (await this.#vault()).checkpoint(input); }
  async latestCheckpoint() { return (await this.#vault()).latestCheckpoint(); }
  async log(input: LogInput) { return (await this.#vault()).log(input); }
  async verifyLog(input: VerifyLogInput) { return (await this.#vault()).verifyLog(input); }

  /** No HTTP surface: only the app's service binding reaches the vault. */
  fetch() {
    return new Response('not found', { status: 404 });
  }
}

/** The vault Worker's default export, `VaultEntrypoint`, configured from its `env`. */
export function vault<Env>(configure_: (env: Env) => WorkersVaultConfig): typeof VaultEntrypoint {
  configure = configure_ as (env: never) => WorkersVaultConfig;
  return VaultEntrypoint;
}
