// The vault Worker: the keys, grants and members, in a Durable Object. It
// has no route of its own; only the app Worker's service binding reaches it.
import { vault, type VaultBindings } from '@coffre/vault/cloudflare';

export { VaultObject } from '@coffre/vault/cloudflare';

type Env = VaultBindings & {
  KEK_ID: string;
  KEK: string;
  SIGNING_KEY: string;
  ROOT_ADMINS: string;
};

export default vault((env: Env) => ({
  kek: { id: env.KEK_ID, key: env.KEK },
  // After a rotation, the KEKs before it, so the data keys they wrapped
  // still open: previousKeks: [{ id: 'kek-2026-09', key: env.KEK_2026_09 }],
  rootAdmins: env.ROOT_ADMINS.split(',').map((email) => email.trim()),
  signingKey: env.SIGNING_KEY,
}));
