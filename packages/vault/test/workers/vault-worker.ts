// The vault's entrypoint in workerd, called over a service binding to
// itself as the app calls it: each fetch is a request of its own, so a
// burst of them is a page load's worth of concurrent calls.
import { postgres, vault } from '../../src/cloudflare.ts';

type Env = { VAULT_HYPERDRIVE: { connectionString: string }; VAULT_KEY: string; VAULT: Record<string, (...args: unknown[]) => Promise<unknown>> };

export const Vault = vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE as never),
  kek: { id: 'vault-workers-test', key: env.VAULT_KEY },
  rootAdmins: ['root@acme.example'],
}));

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { method, args } = (await request.json()) as { method: string; args: unknown[] };
    try {
      return Response.json({ ok: true, result: await env.VAULT[method]!(...args) });
    } catch (error) {
      return Response.json({ ok: false, error: error instanceof Error ? error.message : String(error) }, { status: 500 });
    }
  },
};
