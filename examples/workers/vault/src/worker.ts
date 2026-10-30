// The vault Worker: the keys, and the members and grants, which it decides
// on in the app's database through its own login. It has no route of its
// own; only the app Worker's service binding reaches it. Beside it, its
// checkpointer, a Durable Object that signs the audit log every half second.
import { checkpointer, postgres, vault } from '@coffre/vault/cloudflare';

type Env = {
  VAULT_HYPERDRIVE: Hyperdrive;
  HOT_HYPERDRIVE: Hyperdrive;
  CHECKPOINTER: DurableObjectNamespace;
  VAULT_KEY_ID: string;
  VAULT_KEY: string;
  OWNERS: string;
};

export default vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE),
  // The uses' own login, coffre_vault_hot, whose timeouts bound each one.
  hotDatabase: postgres(env.HOT_HYPERDRIVE),
  // A change answers once the checkpointer has sealed it in a signed checkpoint.
  checkpointer: env.CHECKPOINTER,
  kek: { id: env.VAULT_KEY_ID, key: env.VAULT_KEY },
  // After a rotation, the vault keys before it, so the data keys they wrapped
  // still open and the records signed under them before it still verify:
  // previousKeks: [{ id: 'vault-2026-04-01-k7q2xm', key: env.OLD_VAULT_KEY }],
  // The Owners of the whole instance, whatever its database says: nobody demotes them while listed.
  owners: env.OWNERS.split(',').map((email) => email.trim()),
  // The vault derives its signing key from the vault key. With a key a key
  // service holds, such as awsKms(…), it needs one of its own: signingKey: env.SIGNING_KEY.
}));

// The checkpointer's Durable Object class, configured by vault(…) above.
export const CoffreCheckpointer = checkpointer();
