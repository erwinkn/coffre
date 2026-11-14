import { runsInstance } from '@coffre/core/access';
import { freezeTarget } from '@coffre/core/identity';
import type { Frozen } from '@coffre/core/vault';
import { z } from 'zod';

import { freezes } from '../../db/queries/freezes.ts';
import { changed } from '../change.ts';
import { ApiError, badRequest } from '../errors.ts';
import { route } from '../route.ts';
import { manages } from './bindings.ts';
import { wellFormed } from './members.ts';

/**
 * Freezes (docs/design/workload-access.md, section 8.2): every workload's
 * use under a target stopped at its next request, and let go again, its
 * sessions, codes and bindings kept, so lifting it restores service with no
 * new sign-in. Each is one change of the vault's (`workload.freeze`,
 * `workload.unfreeze`), which decides who may, and no statement. A target
 * comes in any spelling `freezeTarget` takes, `service:api` for
 * `token:api` included, and is answered in its one spelling. Listing the
 * freezes standing is `caller` and one statement.
 */

/** The most freezes a listing answers: past it, it is refused 409 `too_many_to_list`, never cut short. */
export const LISTED_MOST = 1000;

/** A freeze standing: its target in its one spelling, the service account it is of (null for the instance's), and since when. */
export type FreezeView = { target: string; service: string | null; frozenAt: string };

/** A target in its one spelling, or a bad request; an upstream credential's freeze is its environment's, not served here yet. */
function targetOf(raw: string): string {
  const target = freezeTarget(raw);
  if (target === null) throw badRequest('a freeze names instance, token:<name>, binding:<id>, session:<id> or credential:<environment id>/<name>');
  if (target.startsWith('credential:')) throw new ApiError('not_implemented', "freezing an upstream credential is its environment's (upstream.freeze), and is not served yet");
  return target;
}

export const freezeRoutes = {
  /**
   * The freezes standing that the caller may know of: every workload's,
   * which stops everyone's, for anyone; a service account's, one of its
   * bindings' or one of its workloads' sessions', for whoever manages it
   * (`manages`, as its bindings' page weighs it). The instance's first,
   * then by service account and target. Of what is still there to stop: a
   * freeze kept on a removed service account, a revoked binding or an ended
   * session is not listed. A listing; it decides nothing.
   *
   *   → { "freezes": [{ "target": "token:api-prod", "service": "token:api-prod", "frozenAt": "2026-11-14T09:12:03.000Z" }] }
   */
  ...route('GET /freezes', {
    run: async (ctx): Promise<{ freezes: FreezeView[] }> => {
      const who = await ctx.caller();
      const runs = runsInstance(who.holds);
      const found = await freezes(ctx.db, { weighed: !runs, most: LISTED_MOST, now: new Date() });
      if (found.freezes.length > LISTED_MOST) {
        throw new ApiError('conflict', `more than ${LISTED_MOST.toLocaleString('en-US')} freezes stand: lift some to list them`, 'too_many_to_list');
      }
      const seen = (service: string | null) => {
        if (service === null || runs) return true;
        const of = found.services[service];
        return of !== undefined && manages(who, { ...of, setting: found.setting });
      };
      return { freezes: found.freezes.filter((freeze) => seen(freeze.service)) };
    },
  }),
  /**
   * Freeze a target, saying why, which the log keeps: an Owner of the whole
   * instance freezes `instance`, every workload's use; whoever manages a
   * service account freezes it, one of its bindings, or one of its
   * workloads' sessions. A target frozen already keeps its time.
   *
   *   { "target": "token:api-prod", "reason": "the key leaked in a build log" }
   *   → { "target": "token:api-prod", "frozenAt": "2026-11-14T09:12:03.000Z" }
   */
  ...route('POST /freezes', {
    input: z.object({ target: z.string().max(400), reason: z.string().trim().min(1).max(400).refine((reason) => !reason.includes('\0') && wellFormed(reason), 'a reason is well-formed text, with no NUL') }).strict(),
    run: async (ctx, { input }): Promise<Frozen> => {
      const target = targetOf(input.target);
      return changed(ctx, { op: 'workload.freeze', target, reason: input.reason }, target);
    },
  }),
  /** Lift a freeze, by whoever may make it: `frozenAt` null. A target not frozen stays so. */
  ...route('DELETE /freezes/:target', {
    run: async (ctx, { params }): Promise<Frozen> => {
      if (params.target.length > 400) throw badRequest('a freeze names its target in 400 characters at most');
      const target = targetOf(params.target);
      return changed(ctx, { op: 'workload.unfreeze', target }, target);
    },
  }),
};
