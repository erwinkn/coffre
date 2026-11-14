// coffre on Workers as a deployment runs it on the 0.16 contract: the app's
// `createCoffre(…)`, and the vault as an entrypoint of the same Worker
// behind the app's `VAULT` service binding, with its signer, each over a
// Hyperdrive binding of its own to the suite's database. Its fetch answers
// as a deployment's Start app does: coffre's middleware around every
// request, coffre's routes for coffre's paths, and a page for `/page`.
import { github, signin } from '@coffre/core/identity';
import { postgres as vaultDatabase, vault } from '@coffre/vault/cloudflare';

import { createCoffre, postgres, type Vault as VaultBinding, type WaitUntil } from '../../src/cloudflare.ts';

export { CoffreSigner } from '@coffre/vault/cloudflare';

type Env = {
  HYPERDRIVE: { connectionString: string };
  VAULT_HYPERDRIVE: { connectionString: string };
  APP_KEY: string;
  VAULT_KEY: string;
  VAULT: VaultBinding;
};

export const Vault = vault((env: Env) => ({
  database: vaultDatabase(env.VAULT_HYPERDRIVE as never),
  kek: { id: 'app-workers-test', key: env.VAULT_KEY },
  owners: ['root@acme.example'],
}));

const coffre = createCoffre((env: Env) => ({
  publicUrl: 'https://secrets.acme.example',
  database: postgres(env.HYPERDRIVE as never),
  vault: env.VAULT,
  auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }),
  auditChainKey: env.APP_KEY,
}));

export default {
  fetch(request: Request, env: Env, ctx: WaitUntil): Promise<Response> {
    const scope = coffre.request(env, ctx).coffre;
    return scope.respond(request, async (page) => {
      if (new URL(request.url).pathname !== '/page') return scope.route(request);
      // A page's render: two loaders ask who the visitor is, side by side.
      const [first, second] = await Promise.all([page.client.me(), page.client.me()]);
      return Response.json({ who: first.principal.id, same: JSON.stringify(first) === JSON.stringify(second) });
    });
  },
};
