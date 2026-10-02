// The vault Worker `pnpm dev` runs beside the app, as examples/workers does.
import { postgres, vault } from '@coffre/vault/cloudflare';

type Env = {
  VAULT_HYPERDRIVE: { connectionString: string };
  COFFRE_VAULT_KEY_ID: string;
  COFFRE_VAULT_KEY: string;
  COFFRE_ROOT_ADMINS: string;
};

export default vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE),
  kek: { id: env.COFFRE_VAULT_KEY_ID, key: env.COFFRE_VAULT_KEY },
  rootAdmins: env.COFFRE_ROOT_ADMINS.split(','),
}));
