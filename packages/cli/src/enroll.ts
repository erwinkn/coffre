// `coffre enroll` and `coffre approve` (docs/design/workload-access.md,
// section 4.4): a deploy's enrollment code, minted, listed or promoted, and
// a session approved. Declared in `coffre help` by that design's PR 0; PR 3
// builds them, here.
import { parse } from './manage.ts';

/** `coffre enroll <service> [--binding <id>] [--promote <code-id> [--now] | --list [--json]]`. */
export async function enroll(args: string[]): Promise<void> {
  parse(args, {
    binding: { type: 'string' },
    promote: { type: 'string' },
    now: { type: 'boolean' },
    list: { type: 'boolean' },
    json: { type: 'boolean' },
  }, ['<service>']);
  throw new Error('coffre enroll is not built yet: docs/design/workload-access.md, PR 3, brings it');
}

/** `coffre approve <service> <session-id>`. */
export async function approve(args: string[]): Promise<void> {
  parse(args, {}, ['<service>', '<session-id>']);
  throw new Error('coffre approve is not built yet: docs/design/workload-access.md, PR 3, brings it');
}
