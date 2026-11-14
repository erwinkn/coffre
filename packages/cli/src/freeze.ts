// `coffre freeze` and `coffre unfreeze` (docs/design/workload-access.md,
// section 8.2): every use under a target refused from its next request, and
// lifted; alone, what is frozen. Each one request (`GET /freezes`,
// `POST /freezes`, `DELETE /freezes/:target`).
import { shownMember, type CoffreClient } from '@coffre/client';

import { parse, UsageError, type Io } from './manage.ts';

const STDIO: Io = { out: process.stdout, err: process.stderr };

/** A target as people name it: `service:api-prod`, where the server spells it `token:api-prod`. */
const shown = (target: string) => (target.startsWith('token:') ? shownMember(target) : target);

/** `coffre freeze [<target> --reason <text>]`: alone, what is frozen. */
export async function freeze(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, { reason: { type: 'string' } }, ['<target>'], 1);
  const target = positionals[0];
  if (target === undefined) {
    if (values.reason !== undefined) throw new UsageError('--reason goes with a target: coffre freeze <target> --reason <text>');
    const { freezes } = await connect().freezes.list();
    if (freezes.length === 0) {
      io.out.write('Nothing is frozen\n');
      return;
    }
    for (const standing of freezes) io.out.write(`${shown(standing.target)}  frozen since ${standing.frozenAt}\n`);
    return;
  }
  if (values.reason === undefined || values.reason.trim() === '') throw new UsageError('say why, for the log: coffre freeze <target> --reason <text>');
  const frozen = await connect().freezes.freeze(target, values.reason);
  io.out.write(`froze ${shown(frozen.target)}: every use under it is refused from its next request, until \`coffre unfreeze ${shown(frozen.target)}\`\n`);
}

/** `coffre unfreeze <target>`. */
export async function unfreeze(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { positionals } = parse(args, {}, ['<target>']);
  const lifted = await connect().freezes.unfreeze(positionals[0]!);
  io.out.write(`unfroze ${shown(lifted.target)}\n`);
}
