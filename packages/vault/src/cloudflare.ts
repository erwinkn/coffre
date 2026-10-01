/**
 * The vault as a Worker: one Durable Object, so one SQLite database and one
 * thread for every decision, behind an entrypoint the app's `VAULT` service
 * binding calls over RPC. It has no route and no HTTP surface.
 *
 *   import { vault } from '@coffre/vault/cloudflare';
 *   export { VaultObject } from '@coffre/vault/cloudflare';
 *
 *   export default vault((env: Env) => ({
 *     kek: { id: 'kek-1', key: env.KEK },
 *     rootAdmins: ['admin@acme.example'],
 *     signingKey: env.SIGNING_KEY,
 *   }));
 *
 * The Worker's config binds the Durable Object as `VAULT_OBJECT`.
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
  WrapInput,
} from '@coffre/core/vault';
import { DurableObject, WorkerEntrypoint } from 'cloudflare:workers';

import { resolveVaultConfig, type VaultConfig } from './config.ts';
import { durableObjectSqlite } from './sqlite-durable-object.ts';
import { openVault } from './vault.ts';

export type { Vault, VaultConfig };

/** The bindings the vault needs of its Worker; the deployment's own come on top. */
export type VaultBindings = { VAULT_OBJECT: DurableObjectNamespace<VaultObject> };

/** Set when the Worker's module runs `vault(…)`, before any request reaches the object. */
let configure: ((env: never) => VaultConfig) | null = null;

/**
 * The vault itself. Its SQLite is the vault's store, migrated before the
 * first call is let in.
 */
export class VaultObject extends DurableObject<VaultBindings> implements Vault {
  #vault!: Vault;

  constructor(ctx: DurableObjectState, env: VaultBindings) {
    super(ctx, env);
    if (configure === null) throw new Error('the vault Worker must export default vault(…)');
    const config = resolveVaultConfig(configure(env as never));
    void ctx.blockConcurrencyWhile(async () => {
      this.#vault = await openVault(durableObjectSqlite(ctx.storage), config);
    });
  }

  unwrap(input: UnwrapInput) { return this.#vault.unwrap(input); }
  wrap(input: WrapInput) { return this.#vault.wrap(input); }
  rewrap(input: RewrapInput) { return this.#vault.rewrap(input); }
  access(principal: string) { return this.#vault.access(principal); }
  members() { return this.#vault.members(); }
  setAccess(input: SetAccessInput) { return this.#vault.setAccess(input); }
  admit(input: AdmitInput) { return this.#vault.admit(input); }
  remove(input: RemoveInput) { return this.#vault.remove(input); }
  checkpoint(input: CheckpointInput) { return this.#vault.checkpoint(input); }
  latestCheckpoint() { return this.#vault.latestCheckpoint(); }
  log(input: LogInput) { return this.#vault.log(input); }
}

/**
 * What the app's `VAULT` service binding calls: each call passed to the one
 * Durable Object as it is.
 */
export class VaultEntrypoint extends WorkerEntrypoint<VaultBindings> implements Vault {
  get #object() {
    return this.env.VAULT_OBJECT.get(this.env.VAULT_OBJECT.idFromName('vault'));
  }

  unwrap(input: UnwrapInput) { return this.#object.unwrap(input); }
  wrap(input: WrapInput) { return this.#object.wrap(input); }
  rewrap(input: RewrapInput) { return this.#object.rewrap(input); }
  access(principal: string) { return this.#object.access(principal); }
  members() { return this.#object.members(); }
  setAccess(input: SetAccessInput) { return this.#object.setAccess(input); }
  admit(input: AdmitInput) { return this.#object.admit(input); }
  remove(input: RemoveInput) { return this.#object.remove(input); }
  checkpoint(input: CheckpointInput) { return this.#object.checkpoint(input); }
  latestCheckpoint() { return this.#object.latestCheckpoint(); }
  log(input: LogInput) { return this.#object.log(input); }

  /** No HTTP surface: only the app's service binding reaches the vault. */
  fetch() {
    return new Response('not found', { status: 404 });
  }
}

/**
 * The vault Worker's default export, `VaultEntrypoint`. `configure` reads
 * the Worker's secrets into the vault's configuration when the Durable
 * Object starts.
 */
export function vault<Env extends VaultBindings>(configure_: (env: Env) => VaultConfig): typeof VaultEntrypoint {
  configure = configure_ as (env: never) => VaultConfig;
  return VaultEntrypoint;
}
