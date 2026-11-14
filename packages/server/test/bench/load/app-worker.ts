// The app Worker of the load rig, as a deployment's: coffre's middleware and
// routes around each request, the vault reached over the `VAULT` service
// binding to a Worker of its own (vault-worker.ts).
import { github, signin } from '@coffre/core/identity';

import { createCoffre, postgres, type Vault as VaultBinding, type WaitUntil } from '../../../src/cloudflare.ts';

type Env = { HYPERDRIVE: { connectionString: string }; APP_KEY: string; VAULT: VaultBinding };

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
    return scope.respond(request, async () => scope.route(request));
  },
};
