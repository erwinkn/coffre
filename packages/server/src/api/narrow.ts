// `narrow()` (docs/design/workload-access.md, section 8.4): a workload's
// session making a child with less authority, bound to another key.
// `POST /api/auth/workload/narrow`, beside the exchange; declared, and not
// built yet.
import { errorResponse } from '../http.ts';
import type { CoffreRuntime } from '../runtime.ts';
import { notBuilt } from './errors.ts';

export async function narrowWorkload(_request: Request, _runtime: CoffreRuntime, _sourceIp: string | null): Promise<Response> {
  return errorResponse(notBuilt('narrowing a session', 'PR 4'));
}
