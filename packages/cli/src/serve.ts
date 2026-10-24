// `coffre serve` (docs/design/workload-access.md, section 9.3): a
// workload's sidecar, holding its session and key, and forwarding what the
// app sends it on a local listener, signed. Declared in `coffre help` by
// that design's PR 0; PR 5 builds it, here.
import { parse } from './manage.ts';

/** `coffre serve --service <name> --proof <proof> [--listen <address>]`. */
export async function serve(args: string[]): Promise<void> {
  parse(args, { service: { type: 'string' }, proof: { type: 'string' }, listen: { type: 'string' }, tunnel: { type: 'string', multiple: true } }, []);
  throw new Error('coffre serve is not built yet: docs/design/workload-access.md, PR 5, brings it');
}
