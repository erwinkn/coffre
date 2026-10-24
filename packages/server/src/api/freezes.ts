// Freezes (docs/design/workload-access.md, section 8.2): what stops every
// use under a target at its next request, and lifts it, derived from the
// log. Declared in every map of the API by that design's PR 0; PR 4 serves
// them, here.
import { z } from 'zod';

import type { ApiContext } from './context.ts';
import { notBuilt } from './errors.ts';

/** `POST /freezes`: the target, in any spelling `freezeTarget` canonicalizes, and why, for the log and the alert. */
export const freezeInput = z.object({ target: z.string().max(400), reason: z.string().trim().min(1).max(400) }).strict();

export async function listFreezes(_ctx: ApiContext): Promise<never> {
  throw notBuilt('listing freezes', 'PR 4');
}

export async function freeze(_ctx: ApiContext, _input: z.output<typeof freezeInput>): Promise<never> {
  throw notBuilt('freezing', 'PR 4');
}

export async function unfreeze(_ctx: ApiContext, _target: string): Promise<never> {
  throw notBuilt('lifting a freeze', 'PR 4');
}
