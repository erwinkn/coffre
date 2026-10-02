// The vault Worker: the keys, and the members and grants, which it decides
// on in the app's database through its own login. It has no route of its
// own; only the app Worker's service binding reaches it.
import { postgres, vault } from '@coffre/vault/cloudflare';

type Env = {
  VAULT_HYPERDRIVE: Hyperdrive;
  VAULT_KEY_ID: string;
  VAULT_KEY: string;
  ROOT_ADMINS: string;
};

export default vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE),
  kek: { id: env.VAULT_KEY_ID, key: env.VAULT_KEY },
  // After a rotation, the vault keys before it, so the data keys they wrapped
  // still open and the records signed under them before it still verify:
  // previousKeks: [{ id: 'vault-2026-04-01-k7q2xm', key: env.OLD_VAULT_KEY }],
  rootAdmins: env.ROOT_ADMINS.split(',').map((email) => email.trim()),
  // The vault derives its signing key from the vault key. With a key a key
  // service holds, such as awsKms(…), it needs one of its own: signingKey: env.SIGNING_KEY.
}));
