// The checkpointer's Durable Object alone, no witness, for the seal bench (bench/seal.ts): what a change waits for.
// Deployed for a run on Cloudflare, `TOKEN` guards it; `rtt` times plain statements through the Hyperdrive.
import { createDatabase } from '@coffre/db';
import { HyperdrivePool } from '@coffre/db/hyperdrive';
import { sql } from 'drizzle-orm';

import { checkpointer, checkpointerStatus, durableSealThrough, postgres, startCheckpointer, vault } from '../../src/cloudflare.ts';

type Namespace = Parameters<typeof startCheckpointer>[0];
type Env = { VAULT_HYPERDRIVE: { connectionString: string }; VAULT_KEY: string; SIGNING_KEY: string; CHECKPOINTER: Namespace; TOKEN?: string };

export const Vault = vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE as never),
  hotDatabase: postgres(env.VAULT_HYPERDRIVE as never),
  checkpointer: env.CHECKPOINTER,
  kek: { id: 'seal-bench', key: env.VAULT_KEY },
  signingKey: env.SIGNING_KEY,
  owners: ['root@acme.example'],
}));
export const CoffreCheckpointer = checkpointer();

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (env.TOKEN !== undefined && request.headers.get('x-token') !== env.TOKEN) return new Response('no', { status: 403 });
    const { op, number } = (await request.json()) as { op: string; number?: string };
    try {
      if (op === 'start') {
        await startCheckpointer(env.CHECKPOINTER);
        return Response.json({ ok: true });
      }
      if (op === 'seal') {
        const t0 = performance.now();
        await durableSealThrough(env.CHECKPOINTER)(BigInt(number!));
        return Response.json({ ms: performance.now() - t0 });
      }
      if (op === 'status') return Response.json(await checkpointerStatus(env.CHECKPOINTER));
      if (op === 'rtt') {
        const pool = new HyperdrivePool(env.VAULT_HYPERDRIVE.connectionString);
        const db = createDatabase(pool);
        const ms: number[] = [];
        for (let i = 0; i < 21; i += 1) {
          const t = performance.now();
          await db.execute(sql`SELECT ${i}::int`);
          ms.push(performance.now() - t);
        }
        await pool.end();
        return Response.json({ colo: (request as { cf?: { colo?: string } }).cf?.colo, first: ms[0], rest: ms.slice(1).sort((a, b) => a - b) });
      }
      return new Response('unknown op', { status: 400 });
    } catch (error) {
      return Response.json({ error: (error as Error).message }, { status: 500 });
    }
  },
};
