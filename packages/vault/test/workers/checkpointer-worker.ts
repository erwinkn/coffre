// 0.15's checkpointer in workerd, as a deployment would bind it beside the
// vault: its Durable Object, the witness's, and an R2 archive, configured by
// the vault's own `vault(env => …)`. Each fetch asks one thing of them.
import { checkpointer, checkpointerAlarms, checkpointerStatus, durableSealThrough, durableWitness, postgres, r2Archive, startCheckpointer, vault, witness } from '../../src/cloudflare.ts';

type Namespace = Parameters<typeof startCheckpointer>[0];
type Env = {
  VAULT_HYPERDRIVE: { connectionString: string };
  VAULT_KEY: string;
  SIGNING_KEY: string;
  WITNESS_KEY: string;
  LOG_KEYS: string;
  CHECKPOINTER: Namespace;
  WITNESS: Namespace;
  ARCHIVE: Parameters<typeof r2Archive>[0] & { list(options?: { prefix?: string }): Promise<{ objects: { key: string }[] }> };
};

export const Vault = vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE as never),
  kek: { id: 'checkpointer-workers-test', key: env.VAULT_KEY },
  signingKey: env.SIGNING_KEY,
  owners: ['root@acme.example'],
  witnesses: [durableWitness(env.WITNESS), r2Archive(env.ARCHIVE)],
}));
export const CoffreCheckpointer = checkpointer();
export const CoffreWitness = witness((env: Env) => ({ name: 'witness.test', key: env.WITNESS_KEY, log: JSON.parse(env.LOG_KEYS) }));

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { op, number } = (await request.json()) as { op: string; number?: string };
    try {
      if (op === 'start') {
        await startCheckpointer(env.CHECKPOINTER);
        return Response.json({ ok: true });
      }
      if (op === 'seal') {
        const t0 = Date.now();
        const s = await durableSealThrough(env.CHECKPOINTER)(BigInt(number!));
        return Response.json({ ms: Date.now() - t0, notes: s.notes, witnessed: s.witnessed, failures: s.failures, cosigned: s.cosigned.length, tree: s.proof.tree, number: String(s.proof.number) });
      }
      if (op === 'alarms') return Response.json(await checkpointerAlarms(env.CHECKPOINTER));
      if (op === 'status') return Response.json(await checkpointerStatus(env.CHECKPOINTER));
      if (op === 'archive') return Response.json((await env.ARCHIVE.list({ prefix: 'audit/' })).objects.map((o) => o.key));
      return new Response('unknown op', { status: 400 });
    } catch (error) {
      return Response.json({ error: (error as Error).message }, { status: 500 });
    }
  },
};
