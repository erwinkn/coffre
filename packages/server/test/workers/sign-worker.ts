// A raw sign in workerd, as on Cloudflare (`credential-proxy-sign-workers.test.ts`): the credential proxy's own route,
// with an `hmac()` signer whose `maxBytes` is the ceiling, 12 MiB, and a stand-in for coffre's side that opens
// the secret the suite gives it (`SUMSUB_SECRET_KEY`) for any handle. The body is read as the platform gives it.
import type { PluginContext } from '../../src/plugins.ts';
import { credentialProxy, hmac } from '../../src/plugins/credential-proxy.ts';

type Env = { SUMSUB_SECRET_KEY: string };

const proxy = credentialProxy({ credentials: {}, signers: { 'sumsub-key': hmac('SUMSUB_SECRET_KEY', { encoding: 'hex', maxBytes: 12 * 1024 * 1024 }) } });

const contextOf = (env: Env) =>
  ({
    publicUrl: 'https://secrets.acme.example',
    // A handle's request is no workload's.
    workload: async () => null,
    use: async () => ({
      values: { SUMSUB_SECRET_KEY: env.SUMSUB_SECRET_KEY },
      plain: [],
      keys: ['SUMSUB_SECRET_KEY'],
      environment: { path: 'market/dev', personal: false },
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    }),
  }) as unknown as PluginContext;

export default {
  fetch: (request: Request, env: Env) => proxy.routes!.fetch(request, contextOf(env)),
};
