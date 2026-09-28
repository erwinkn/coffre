import { DurableObject, WorkerEntrypoint } from 'cloudflare:workers';

import { loadVaultConfig } from '../../../packages/vault/src/config.ts';
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
} from '../../../packages/vault/src/types.ts';
import { openVault } from '../../../packages/vault/src/vault.ts';

type Env = Readonly<Record<`COFFRE_${string}`, string | undefined>> & {
  VAULT_OBJECT: DurableObjectNamespace<VaultObject>;
};

/**
 * The vault itself: one Durable Object, so one SQLite database and one
 * thread for every decision. Its storage is the vault's store, migrated
 * before the first call is let in.
 */
export class VaultObject extends DurableObject<Env> implements Vault {
  #vault!: Vault;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const { VAULT_OBJECT: _, ...vars } = env;
    void ctx.blockConcurrencyWhile(async () => {
      this.#vault = await openVault(ctx.storage, loadVaultConfig(vars));
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
 * What the app's `VAULT` service binding calls: the `Vault` interface over
 * RPC, each call passed to the one Durable Object as it is.
 */
export class VaultEntrypoint extends WorkerEntrypoint<Env> implements Vault {
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
}

/** No HTTP surface: only the app's service binding reaches the vault. */
export default {
  fetch: () => new Response('not found', { status: 404 }),
} satisfies ExportedHandler<Env>;
