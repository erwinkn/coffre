// T169: the vault's entrypoint and its checkpointer's object as
// log-worker.ts has them, the object's tick bounded at `TICK_BOUND_MS` ms
// rather than 10 s, so that a test waits for a stall no longer than that.
import { checkpointerObject } from '../../src/checkpointer-workers.ts';
import { resolveVaultConfig } from '../../src/config.ts';

export { Vault, default } from './log-worker.ts';

type Env = { VAULT_HYPERDRIVE: { connectionString: string }; KEK: string; SIGNING_KEY: string; TICK_BOUND_MS: string };

export const CoffreCheckpointer = checkpointerObject((env: Env) => ({
  hyperdrive: env.VAULT_HYPERDRIVE,
  signingKeys: resolveVaultConfig({ kek: JSON.parse(env.KEK) as { id: string; key: string }, signingKey: env.SIGNING_KEY, owners: ['root@acme.example'] }).signingKeys,
  tickBoundMs: Number(env.TICK_BOUND_MS),
}));
