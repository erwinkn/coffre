// The vault Worker `pnpm dev` runs beside the app, as examples/workers does.
import { checkpointer, postgres, vault, type ObjectNamespace } from '@coffre/vault/cloudflare';

type Env = {
  VAULT_HYPERDRIVE: { connectionString: string };
  CHECKPOINTER: ObjectNamespace;
  COFFRE_VAULT_KEY_ID: string;
  COFFRE_VAULT_KEY: string;
  COFFRE_OWNERS: string;
};

export default vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE),
  checkpointer: env.CHECKPOINTER,
  kek: { id: env.COFFRE_VAULT_KEY_ID, key: env.COFFRE_VAULT_KEY },
  owners: env.COFFRE_OWNERS.split(','),
}));
export const CoffreCheckpointer = checkpointer();
