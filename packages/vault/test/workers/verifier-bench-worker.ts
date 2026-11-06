// The verifier alone in workerd, for its bench (bench/verifier.ts): one check of 0.15's log a request, on a connection of
// its own through the Hyperdrive, as the vault's `verifyTrees` makes it; `noop` answers and does nothing, the floor.
// Local only: it answers the token bench/verifier.ts gives it.
import { decodePair } from '@coffre/core/merkle';
import { createDatabase } from '@coffre/db';
import { HyperdrivePool } from '@coffre/db/hyperdrive';

import { verifierKeys, verifyTrees, type VerifierKeys } from '../../src/verifier.ts';

type Env = { VAULT_HYPERDRIVE: { connectionString: string }; SIGNING_KEY: string; TOKEN: string };

/** The keys, derived once an isolate, as the vault keeps them: a settled value, never a pending one. */
let derived: VerifierKeys | null = null;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (typeof env.TOKEN !== 'string' || env.TOKEN.length < 16 || request.headers.get('x-token') !== env.TOKEN) return new Response('no', { status: 403 });
    const { op, anchor } = (await request.json()) as { op: string; anchor?: string };
    if (op === 'noop') return Response.json({});
    if (op !== 'verify' || anchor === undefined) return new Response('unknown op', { status: 400 });
    try {
      derived ??= await verifierKeys([Uint8Array.from(atob(env.SIGNING_KEY), (c) => c.charCodeAt(0))]);
      const pool = new HyperdrivePool(env.VAULT_HYPERDRIVE.connectionString);
      try {
        const walked = await verifyTrees(createDatabase(pool), derived, { anchors: [decodePair(anchor)!] });
        return Response.json({ ok: walked.ok, unsealed: walked.unsealed, capped: walked.capped });
      } finally {
        await pool.end();
      }
    } catch (error) {
      return Response.json({ error: (error as Error).message }, { status: 500 });
    }
  },
};
