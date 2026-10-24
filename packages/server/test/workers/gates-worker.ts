// The workload gate in workerd, as on Cloudflare: the class a deployment
// exports, `CoffreGates`, bound as `GATES`, asked through `workersGates`
// as coffre's runtime asks it. Each request names a workload and what to
// ask its gate; one that names none asks nothing, a bench's floor
// (test/bench/gate.ts).
import type { GateCount } from '@coffre/core/identity';

import { CoffreGates, workersGates, type GatesNamespace } from '../../src/cloudflare-gates.ts';

type Env = { GATES: GatesNamespace };
type Ask = { principal?: string; nonce?: true; replay?: { session: string; jti: string; nonce: string }; counts?: GateCount[] };

export { CoffreGates };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { principal, nonce, ...admit } = (await request.json()) as Ask;
    if (principal === undefined) return Response.json({});
    const gate = workersGates(env.GATES)(principal);
    return Response.json(nonce ? { nonce: await gate.nonce() } : await gate.admit(admit));
  },
};
