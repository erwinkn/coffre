// coffre on Workers as a deployment runs it, its tunnel included: the app's
// `createCoffre(…)` with the credential proxy, its `Sockets` Durable Object,
// and the vault as an entrypoint of the same Worker, each over Hyperdrive to
// the suite's database. The suite seeds that database from Node with the
// same vault key and audit key, and the tunnel's admission, rechecks and log
// entries run here, as deployed.
import { github, signin } from '@coffre/core/identity';
import { checkpointer, postgres as vaultDatabase, vault, type ObjectNamespace } from '@coffre/vault/cloudflare';

import { createCoffre, postgres, type SocketsNamespace, type VaultEntry as VaultBinding } from '../../src/cloudflare.ts';
import type { CoffrePlugin } from '../../src/plugins.ts';
import { credentialProxy, postgres as tunnel } from '../../src/plugins/credential-proxy.ts';

type Env = {
  HYPERDRIVE: { connectionString: string };
  VAULT_HYPERDRIVE: { connectionString: string };
  HOT_HYPERDRIVE: { connectionString: string };
  CHECKPOINTER: ObjectNamespace;
  APP_KEY: string;
  VAULT_KEY: string;
  VAULT: VaultBinding;
  SOCKETS: SocketsNamespace;
};

export const Vault = vault((env: Env) => ({
  database: vaultDatabase(env.VAULT_HYPERDRIVE as never),
  hotDatabase: vaultDatabase(env.HOT_HYPERDRIVE as never),
  checkpointer: env.CHECKPOINTER,
  kek: { id: 'test-kek-1', key: env.VAULT_KEY },
  owners: ['admin@acme.example'],
}));
export const CoffreCheckpointer = checkpointer();

// What a plugin's WebSocket admission is handed to dial a host an Owner typed, a UI tunnel's database: the object's
// `connect()` (cloudflare-handler.ts), which the suite asks for under `/probe`.
const probe: CoffrePlugin = {
  name: 'probe',
  routes: {
    prefix: '/probe',
    fetch: async () => new Response('a WebSocket only', { status: 404 }),
    socket: async (_, context) => Response.json({ connect: typeof context.publicConnect }),
  },
};

const coffre = createCoffre((env: Env) => ({
  publicUrl: 'https://secrets.acme.example',
  database: postgres(env.HYPERDRIVE as never),
  vault: env.VAULT,
  auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }),
  auditChainKey: env.APP_KEY,
  // The suite's database is on loopback; R at its floor, 3 s, a check every 1.5 s, so the suite sees one.
  plugins: [credentialProxy({ credentials: {}, tunnels: { db: tunnel('DATABASE_URL') }, insecureUpstreams: true }), probe],
  deployment: { proxy: { revokedWithinSeconds: 3 } },
  sockets: env.SOCKETS,
}));

export default {
  fetch: (request: Request, env: Env) => coffre.upgrade(request, env) ?? new Response('no tunnel here', { status: 404 }),
};

export const CoffreSockets = coffre.Sockets;
