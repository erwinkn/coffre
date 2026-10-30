// The vault's entrypoint in workerd, called over a service binding to
// itself as the app calls it: each fetch is a request of its own, so a
// burst of them is a page load's worth of concurrent calls.
import { createDatabase } from '@coffre/db';
import { HyperdrivePool } from '@coffre/db/hyperdrive';
import { sql } from 'drizzle-orm';

import { checkpointer, postgres, startCheckpointer, vault } from '../../src/cloudflare.ts';

type Env = {
  VAULT_HYPERDRIVE: { connectionString: string };
  HOT_HYPERDRIVE: { connectionString: string };
  CHECKPOINTER: Parameters<typeof startCheckpointer>[0];
  VAULT_KEY: string;
  VAULT: Record<string, (...args: unknown[]) => Promise<unknown>>;
};

export const Vault = vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE as never),
  hotDatabase: postgres(env.HOT_HYPERDRIVE as never),
  checkpointer: env.CHECKPOINTER,
  kek: { id: 'vault-workers-test', key: env.VAULT_KEY },
  owners: ['root@acme.example'],
}));
export const CoffreCheckpointer = checkpointer();

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { method, args } = (await request.json()) as { method: string; args: unknown[] };
    // The checkpointer's object started from outside the vault, its connection opened before the calls counted.
    if (method === 'startCheckpointer') return Response.json({ ok: true, result: await startCheckpointer(env.CHECKPOINTER) });
    // A query on the database inside its own transaction, as no code may make: refused at once, here in workerd too.
    if (method === 'queryOutsideTransaction') {
      const pool = new HyperdrivePool(env.VAULT_HYPERDRIVE.connectionString);
      const db = createDatabase(pool);
      try {
        await db.transaction(async () => db.execute(sql`select 1`));
        return Response.json({ ok: false, error: 'the query ran' });
      } catch (error) {
        return Response.json({ ok: true, result: error instanceof Error ? `${error.name}: ${error.message}` : String(error) });
      } finally {
        await pool.end();
      }
    }
    try {
      return Response.json({ ok: true, result: await env.VAULT[method]!(...args) });
    } catch (error) {
      // Its code too, as the app reads it on the other side of the binding (`isUnavailable`).
      const code = (error as { code?: unknown }).code;
      return Response.json({ ok: false, error: error instanceof Error ? error.message : String(error), ...(typeof code === 'string' ? { code } : {}) }, { status: 500 });
    }
  },
};
