// The app Worker of the proxy run (W422's credential proxy, S4 PR 3 on), as
// the Workers test's app (test/workers/app-worker.ts) but for the vault, a
// Worker of its own: coffre's middleware and routes, each service's gate a
// Durable Object (`GATES`), and the credential proxy with one credential,
// `echo`, whose upstream is a fake inside the Worker, so a request goes all
// the way but for the network. It bundles only on a tree that has the
// proxy (run.ts --app proxy).
import { github, signin } from '@coffre/core/identity';

import { createCoffre, postgres, type GatesNamespace, type Vault as VaultBinding, type WaitUntil } from '../../../../src/cloudflare.ts';
import { credentialProxy, header } from '../../../../src/plugins/credential-proxy.ts';
import { processLimits } from '../../../../src/workloads/limits.ts';

type Env = { HYPERDRIVE: { connectionString: string }; APP_KEY: string; VAULT: VaultBinding; GATES: GatesNamespace };

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
    return scope.respond(request, async () => scope.route(request));
  },
};
