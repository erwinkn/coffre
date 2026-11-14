// coffre on Workers as a deployment runs it on the 0.16 contract: the app's
// `createCoffre(…)`, and the vault as an entrypoint of the same Worker
// behind the app's `VAULT` service binding, with its signer, each over a
// Hyperdrive binding of its own to the suite's database. Its fetch answers
// as a deployment's Start app does: coffre's middleware around every
// request, coffre's routes for coffre's paths, and a page for `/page`. Each
// service's workload gate is its Durable Object, `GATES`. Its credential
// proxy has one credential, `echo`, whose upstream is a fake inside the
// Worker (its `egress`): it answers what it was sent, the key reversed so
// that the proxy's redaction leaves it, so a request through the proxy goes
// all the way but for the network.
import { github, signin } from '@coffre/core/identity';
import { postgres as vaultDatabase, vault } from '@coffre/vault/cloudflare';

import { createCoffre, postgres, type GatesNamespace, type Vault as VaultBinding, type WaitUntil } from '../../src/cloudflare.ts';
import { credentialProxy, header } from '../../src/plugins/credential-proxy.ts';
import { processLimits } from '../../src/workloads/limits.ts';

export { CoffreSigner } from '@coffre/vault/cloudflare';

type Env = {
  HYPERDRIVE: { connectionString: string };
  VAULT_HYPERDRIVE: { connectionString: string };
  APP_KEY: string;
  VAULT_KEY: string;
  VAULT: VaultBinding;
  GATES: GatesNamespace;
};

export const Vault = vault((env: Env) => ({
  database: vaultDatabase(env.VAULT_HYPERDRIVE as never),
  kek: { id: 'app-workers-test', key: env.VAULT_KEY },
  owners: ['root@acme.example'],
  workloads: {},
}));

const coffre = createCoffre((env: Env) => ({
  publicUrl: 'https://secrets.acme.example',
  database: postgres(env.HYPERDRIVE as never),
  vault: env.VAULT,
  auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits() } }),
  auditChainKey: env.APP_KEY,
  gates: env.GATES,
  plugins: [
    credentialProxy({
      credentials: {
        echo: {
          upstream: 'https://api.echo.example/v1',
          inject: header('authorization', 'Bearer {API_KEY}'),
          egress: { fetch: async (url, init) => Response.json({ path: url.pathname, reversed: [...(new Headers(init.headers).get('authorization') ?? '')].reverse().join('') }) },
        },
      },
    }),
  ],
}));

export const CoffreGates = coffre.Gates;

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
