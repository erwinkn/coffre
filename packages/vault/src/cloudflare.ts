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
 *     owners: ['admin@acme.example'],
 *   }));
 *
 * It exports its signer too, and binds it (`CoffreSigner`, below): the
 * vault tells it of each entry it writes.
 *
 * Any number of isolates run it side by side. A use takes no lock, and a
 * change takes one in the database, so they share one log and one bulk
 * limit.
 */
import type { Asked, Change, Presented, UseInput, Vault } from '@coffre/core/vault';
import { createDatabase } from '@coffre/db';
import { HyperdrivePool, type PostgresDatabase } from '@coffre/db/hyperdrive';
import { WorkerEntrypoint } from 'cloudflare:workers';

import { signerObject, signerOf, type SignerNamespace } from './cloudflare-signer.ts';
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
 * isolate keeps with the vault's short memory (vault.ts, `PreparedVault`).
 */
const ready = new WeakMap<object, { database: PostgresDatabase; prepared: PreparedVault }>();

/**
 * What the app's `VAULT` service binding calls. Each call gets a database of
 * its own, one client that its queries take turns on, since a Worker's
 * connections belong to the call that made them; it is closed once the
 * call is done. The signer's stub is the call's own too.
 */
export class VaultEntrypoint extends WorkerEntrypoint implements Vault {
  async #call<T>(run: (vault: Vault) => Promise<T>): Promise<T> {
    const { prepared, database } = this.#ready();
    const { SIGNER } = this.env as { SIGNER?: SignerNamespace };
    if (SIGNER === undefined) throw new Error('the vault Worker binds its signer: a durable_objects binding SIGNER to CoffreSigner, which it exports (docs/design/0.16.md, "The signer")');
    const pool = new HyperdrivePool(database.hyperdrive.connectionString);
    // The reply does not wait for the signer, and the call lives on until it has heard. One that fails costs the entry
    // its announcement, never the caller their answer: the minute's run signs it all the same.
    const wake = (hash: Buffer) =>
      this.ctx.waitUntil(
        (async () => {
          try {
            // A copy of its own: what crosses is the bytes' whole buffer.
            await signerOf(SIGNER).wake(Uint8Array.from(hash));
          } catch (error) {
            console.error('coffre: the signer was not told of an entry', error);
          }
        })(),
      );
    try {
      return await run(openVault(createDatabase(pool), prepared, { wake }));
    } finally {
      this.ctx.waitUntil(pool.end());
    }
  }

  #ready(): { database: PostgresDatabase; prepared: PreparedVault } {
    const env = this.env as object;
    let entry = ready.get(env);
    if (entry === undefined) {
      if (configure === null) throw new Error('the vault Worker must export default vault(…)');
      const config = configure(env as never);
      entry = { database: config.database, prepared: prepareVault(resolveVaultConfig(config)) };
      ready.set(env, entry);
    }
    return entry;
  }

  async use(input: UseInput) { return this.#call((vault) => vault.use(input)); }
  async peek(input: UseInput) { return this.#call((vault) => vault.peek(input)); }
  async caller(input: Presented) { return this.#call((vault) => vault.caller(input)); }
  async change<O extends Change['op']>(input: Asked<O>) { return this.#call((vault) => vault.change(input)); }

  /** No HTTP surface: only the app's service binding reaches the vault. */
  fetch() {
    return new Response('not found', { status: 404 });
  }
}

/**
 * The signer's Durable Object (cloudflare-signer.ts), configured as the
 * vault is. The vault Worker exports it beside its default export, and
 * binds it:
 *
 *   export { CoffreSigner } from '@coffre/vault/cloudflare';
 *
 *   "durable_objects": { "bindings": [{ "name": "SIGNER", "class_name": "CoffreSigner" }] },
 *   "migrations": [{ "tag": "signer", "new_sqlite_classes": ["CoffreSigner"] }]
 */
export const CoffreSigner = signerObject((env: object) => {
  if (configure === null) throw new Error('the vault Worker must export default vault(…)');
  const config = configure(env as never);
  const { signingKeys, keepUsesDays } = resolveVaultConfig(config);
  return { database: config.database, signingKeys, keepUsesDays, alert: config.alert };
});

/** The vault Worker's default export, `VaultEntrypoint`, configured from its `env`. */
export function vault<Env>(configure_: (env: Env) => WorkersVaultConfig): typeof VaultEntrypoint {
  configure = configure_ as (env: never) => WorkersVaultConfig;
  return VaultEntrypoint;
}
