// `coffre freeze` and `coffre unfreeze` (docs/design/workload-access.md,
// section 8.2): every use under a target refused from its next request, and
// lifted. Declared in `coffre help` by that design's PR 0; PR 4 builds them,
// here.
import { parse } from './manage.ts';

/** `coffre freeze [<target> --reason <text>]`: alone, what is frozen. */
export async function freeze(args: string[]): Promise<void> {
  parse(args, { reason: { type: 'string' } }, ['<target>'], 1);
  throw new Error('coffre freeze is not built yet: docs/design/workload-access.md, PR 4, brings it');
}

/** `coffre unfreeze <target>`. */
export async function unfreeze(args: string[]): Promise<void> {
  parse(args, {}, ['<target>']);
  throw new Error('coffre unfreeze is not built yet: docs/design/workload-access.md, PR 4, brings it');
}
