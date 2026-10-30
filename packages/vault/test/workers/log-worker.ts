// The vault's entrypoint in workerd with 0.15's log switched on, as a
// deployment would configure it before the flip: its hot path's Hyperdrive
// and its checkpointer's Durable Object, which seals each change before it
// answers (R51). Called over a service binding to itself, as the app calls it.
import { checkpointer, postgres, startCheckpointer, vault } from '../../src/cloudflare.ts';

type Env = {
  VAULT_HYPERDRIVE: { connectionString: string };
  HOT_HYPERDRIVE: { connectionString: string };
  KEK: string;
  SIGNING_KEY: string;
  CHECKPOINTER: Parameters<typeof startCheckpointer>[0];
  VAULT: Record<string, (...args: unknown[]) => Promise<unknown>>;
};

export const Vault = vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE as never),
  hotDatabase: postgres(env.HOT_HYPERDRIVE as never),
  kek: JSON.parse(env.KEK) as { id: string; key: string },
  signingKey: env.SIGNING_KEY,
  owners: ['root@acme.example'],
  log: '0.15',
  checkpointer: env.CHECKPOINTER,
}));
export const CoffreCheckpointer = checkpointer();

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { method, args } = (await request.json()) as { method: string; args: unknown[] };
    try {
      if (method === 'startCheckpointer') return Response.json({ ok: true, result: await startCheckpointer(env.CHECKPOINTER) });
      return Response.json({ ok: true, result: await env.VAULT[method]!(...args) });
    } catch (error) {
      return Response.json({ ok: false, error: error instanceof Error ? error.message : String(error) }, { status: 500 });
    }
  },
};
