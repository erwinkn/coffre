// The vault's entrypoint in workerd, as a deployment configures it: its hot
// path's Hyperdrive and its checkpointer's Durable Object, which seals each
// change before it answers (R51). Called over a service binding to itself,
// as the app calls it.
import { checkpointer, checkpointerStatus, postgres, startCheckpointer, vault } from '../../src/cloudflare.ts';

type Env = {
  VAULT_HYPERDRIVE: { connectionString: string };
  HOT_HYPERDRIVE: { connectionString: string };
  KEK: string;
  SIGNING_KEY: string;
  CHECKPOINTER: Parameters<typeof startCheckpointer>[0];
  /** Set by a test: each start of the checkpointer's object waits this many ms first, as one far away or busy would. */
  SLOW_CHECKPOINTER?: string;
  VAULT: Record<string, (...args: unknown[]) => Promise<unknown>>;
};

/** The object's namespace, each start of it delayed `ms`, and nothing else: a call that skipped its start meets the log before it. */
function slow(namespace: Env['CHECKPOINTER'], ms: number): Env['CHECKPOINTER'] {
  return {
    idFromName: (name) => namespace.idFromName(name),
    get: (id) => {
      const object = namespace.get(id);
      return {
        fetch: async (request) => {
          if (((await request.clone().json()) as { op?: string }).op === 'start') await new Promise((resolve) => setTimeout(resolve, ms));
          return object.fetch(request);
        },
      };
    },
  };
}

export const Vault = vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE as never),
  hotDatabase: postgres(env.HOT_HYPERDRIVE as never),
  kek: JSON.parse(env.KEK) as { id: string; key: string },
  signingKey: env.SIGNING_KEY,
  owners: ['root@acme.example'],
  checkpointer: env.SLOW_CHECKPOINTER === undefined ? env.CHECKPOINTER : slow(env.CHECKPOINTER, Number(env.SLOW_CHECKPOINTER)),
}));
export const CoffreCheckpointer = checkpointer();

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { method, args } = (await request.json()) as { method: string; args: unknown[] };
    try {
      if (method === 'checkpointerStatus') return Response.json({ ok: true, result: await checkpointerStatus(env.CHECKPOINTER) });
      return Response.json({ ok: true, result: await env.VAULT[method]!(...args) });
    } catch (error) {
      return Response.json({ ok: false, error: error instanceof Error ? error.message : String(error) }, { status: 500 });
    }
  },
};
