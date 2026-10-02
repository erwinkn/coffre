// The vault: the keys, and the members and grants, which it keeps in the
// server's database through a login of its own. It answers only on a Unix
// socket, which it makes 0660: run it as its own user, sharing a group with
// the server's, and nothing that faces the network can read the vault key.
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
  kek: { id: env('VAULT_KEY_ID'), key: env('VAULT_KEY') },
  // After a rotation, the vault keys before it, so the data keys they wrapped
  // still open and the records signed under them before it still verify:
  // previousKeks: [{ id: 'vault-2026-04-01-k7q2xm', key: env('OLD_VAULT_KEY') }],
  rootAdmins: env('ROOT_ADMINS').split(',').map((email) => email.trim()),
  // The vault derives its signing key from the vault key. With a key a key
  // service holds, such as awsKms(…), it needs one of its own: signingKey: env('SIGNING_KEY').
});
console.log(`the vault is listening on ${vault.socket}`);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => void vault.close().then(() => process.exit(0)));
}
