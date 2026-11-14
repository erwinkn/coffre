import type { Answers, Asked, Change, McpUnasked, Unasked, WorkloadsUnasked } from '@coffre/core/vault';

import type { ApiContext } from './context.ts';
import { refusal } from './errors.ts';

/**
 * A change of the vault's, worded: its answer, or its refusal thrown with
 * `what` it was about (`market/prod`). What every area's change route
 * does with the one call it makes. Every change sent here is asked, with
 * what the request showed; TypeScript cannot narrow `Asked<O>` for an `O`
 * it does not know yet, so the input is cast to it.
 */
export async function changed<O extends Exclude<Change['op'], Unasked>>(ctx: ApiContext, change: Extract<Change, { op: O }>, what: string): Promise<Answers[O]> {
  const answer = await ctx.vault.change<O>({ ...ctx.shown, ...change } as Asked<O>);
  if ('refused' in answer) throw refusal(answer.refused, what);
  return answer.answer;
}

/** A change weighed (`vault.weigh`), and nothing written: what it would answer, or its refusal thrown as `changed` throws it. */
export async function weighed<O extends Exclude<Change['op'], Unasked | WorkloadsUnasked | McpUnasked>>(ctx: ApiContext, change: Extract<Change, { op: O }>, what: string): Promise<Answers[O]> {
  const answer = await ctx.vault.weigh<O>({ ...ctx.shown, ...change } as Asked<O>);
  if ('refused' in answer) throw refusal(answer.refused, what);
  return answer.answer;
}
