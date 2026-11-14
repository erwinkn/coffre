import { freezeTarget } from '@coffre/core/identity';
import { z } from 'zod';

import { changed } from '../change.ts';
import { ApiError, badRequest } from '../errors.ts';
import { route } from '../route.ts';

/**
 * Freezes (docs/design/workload-access.md, section 8.2): every workload's
 * use under a target stopped at its next request, and let go again, its
 * sessions, codes and bindings kept, so lifting it restores service with no
 * new sign-in. Each is one change of the vault's (`workload.freeze`,
 * `workload.unfreeze`), which decides who may, and no statement. A target
 * comes in any spelling `freezeTarget` takes, `service:api` for
 * `token:api` included, and is answered in its one spelling.
 */

/** A target in its one spelling, or a bad request; an upstream credential's freeze is its environment's, not served here yet. */
function targetOf(raw: string): string {
  const target = freezeTarget(raw);
  if (target === null) throw badRequest('a freeze names instance, token:<name>, binding:<id>, session:<id> or credential:<environment id>/<name>');
  if (target.startsWith('credential:')) throw new ApiError('not_implemented', "freezing an upstream credential is its environment's (upstream.freeze), and is not served yet");
  return target;
}

export const freezeRoutes = {
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
    input: z.object({ target: z.string().max(400), reason: z.string().trim().min(1).max(400) }).strict(),
    run: async (ctx, { input }) => {
      const target = targetOf(input.target);
      return changed(ctx, { op: 'workload.freeze', target, reason: input.reason }, target);
    },
  }),
  /** Lift a freeze, by whoever may make it: `frozenAt` null. A target not frozen stays so. */
  ...route('DELETE /freezes/:target', {
    run: async (ctx, { params }) => {
      if (params.target.length > 400) throw badRequest('a freeze names its target in 400 characters at most');
      const target = targetOf(params.target);
      return changed(ctx, { op: 'workload.unfreeze', target }, target);
    },
  }),
};
