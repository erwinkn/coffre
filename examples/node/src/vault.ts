// The vault: the keys, and the members and grants, which it keeps in the
// server's database through a login of its own. It answers only on a Unix
// socket, which it makes 0660: run it as its own user, sharing a group with
// the server's, and nothing that faces the network can read the KEK.
// Settings come from vault.env.
import { serveVault } from '@coffre/vault/node';

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set; see vault.env.example`);
  return value;
}

const vault = await serveVault({
  socket: env('VAULT_SOCKET'),
  database: env('DATABASE_URL'),
  kek: { id: env('KEK_ID'), key: env('KEK') },
  // After a rotation, the KEKs before it, so the data keys they wrapped
  // still open: previousKeks: [{ id: 'kek-1', key: env('KEK_1') }],
  rootAdmins: env('ROOT_ADMINS').split(',').map((email) => email.trim()),
  signingKey: env('SIGNING_KEY'),
});
console.log(`the vault is listening on ${vault.socket}`);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => void vault.close().then(() => process.exit(0)));
}
