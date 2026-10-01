// The vault Worker `pnpm dev` runs beside the app, as examples/workers does.
import { postgres, vault } from '@coffre/vault/cloudflare';

type Env = {
  VAULT_HYPERDRIVE: { connectionString: string };
  COFFRE_KEK_ID: string;
  COFFRE_KEK_LOCAL: string;
  COFFRE_ROOT_ADMINS: string;
  COFFRE_VAULT_SIGNING_KEY: string;
};

export default vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE),
  kek: { id: env.COFFRE_KEK_ID, key: env.COFFRE_KEK_LOCAL },
  rootAdmins: env.COFFRE_ROOT_ADMINS.split(','),
  signingKey: env.COFFRE_VAULT_SIGNING_KEY,
}));
