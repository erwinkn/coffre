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
 *     kek: { id: env.VAULT_KEY_ID, key: env.VAULT_KEY }, // or awsKms({ keyArn, credentials }), with a signingKey
 *     rootAdmins: ['admin@acme.example'],
 *   }));
 *
 * Any number of isolates run it side by side: every decision locks what it
 * is about in the database, so they share one log and one bulk limit.
 */
import type {
  AdmitInput,
  RemoveInput,
  ReferenceInput,
  EndReferencesInput,
  RewrapInput,
  SetAccessInput,
  SetSettingsInput,
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

/**
 * The configuration, checked and made ready once per `env`, which the
 * isolate keeps: the ready value itself, never the work of making it, which
 * would belong to the call that started it (vault.ts, `PreparedVault`).
 */
const ready = new WeakMap<object, { database: PostgresDatabase; prepared: PreparedVault }>();

/**
 * What the app's `VAULT` service binding calls. Each call gets a database of
 * its own, one client that its queries take turns on, since a Worker's
 * connections belong to the call that made them; it is closed once the
 * call is done.
 */
export class VaultEntrypoint extends WorkerEntrypoint implements Vault {
  async #call<T>(run: (vault: Vault) => Promise<T>): Promise<T> {
    const { prepared, database } = await this.#ready();
    const pool = new HyperdrivePool(database.hyperdrive.connectionString);
    try {
      return await run(openVault(createDatabase(pool), prepared));
    } finally {
      this.ctx.waitUntil(pool.end());
    }
  }

  async #ready(): Promise<{ database: PostgresDatabase; prepared: PreparedVault }> {
    const env = this.env as object;
    let entry = ready.get(env);
    if (entry === undefined) {
      if (configure === null) throw new Error('the vault Worker must export default vault(…)');
      const config = configure(env as never);
      const prepared = await prepareVault(resolveVaultConfig(config));
      // Calls that raced here each made one; the first kept serves them all from now on.
      entry = ready.get(env) ?? { database: config.database, prepared };
      ready.set(env, entry);
    }
    return entry;
  }

  async unwrap(input: UnwrapInput) { return this.#call((vault) => vault.unwrap(input)); }
  async wrap(input: WrapInput) { return this.#call((vault) => vault.wrap(input)); }
  async rewrap(input: RewrapInput) { return this.#call((vault) => vault.rewrap(input)); }
  async reference(input: ReferenceInput) { return this.#call((vault) => vault.reference(input)); }
  async endReferences(input: EndReferencesInput) { return this.#call((vault) => vault.endReferences(input)); }
  async access(principal: string) { return this.#call((vault) => vault.access(principal)); }
  async setAccess(input: SetAccessInput) { return this.#call((vault) => vault.setAccess(input)); }
  async admit(input: AdmitInput) { return this.#call((vault) => vault.admit(input)); }
  async remove(input: RemoveInput) { return this.#call((vault) => vault.remove(input)); }
  async settings() { return this.#call((vault) => vault.settings()); }
  async setSettings(input: SetSettingsInput) { return this.#call((vault) => vault.setSettings(input)); }
  async checkpoint() { return this.#call((vault) => vault.checkpoint()); }
  async about() { return this.#call((vault) => vault.about()); }
  async keyChecks() { return this.#call((vault) => vault.keyChecks()); }
  async verifyLog(input: VerifyLogInput) { return this.#call((vault) => vault.verifyLog(input)); }

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
