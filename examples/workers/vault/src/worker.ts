// The vault Worker: the keys, and the members and grants, which it decides
// on in the app's database through its own login. It has no route of its
// own; only the app Worker's service binding reaches it.
import { postgres, vault } from '@coffre/vault/cloudflare';

type Env = {
  VAULT_HYPERDRIVE: Hyperdrive;
  KEK_ID: string;
  KEK: string;
  SIGNING_KEY: string;
  ROOT_ADMINS: string;
};

export default vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE),
  kek: { id: env.KEK_ID, key: env.KEK },
  // After a rotation, the KEKs before it, so the data keys they wrapped
  // still open: previousKeks: [{ id: 'kek-2026-09', key: env.KEK_2026_09 }],
  rootAdmins: env.ROOT_ADMINS.split(',').map((email) => email.trim()),
  signingKey: env.SIGNING_KEY,
}));
