import { runsInstance } from '@coffre/core/access';
import { environmentPath, secretKey, slug } from '@coffre/core/schemas';
import type { About } from '@coffre/core/vault';
import { z } from 'zod';

import { listAudit, type AuditPage } from '../audit.ts';
import { badRequest, forbidden } from '../errors.ts';
import { parsePath, type Path } from '../paths.ts';
import { route } from '../route.ts';

/**
 * The audit page (docs/design/0.16.md, "Pages"): a stretch of the log,
 * each entry it shows proven against the head the vault vouched for in the
 * page's own call, in 0.14.7's shapes with what 0.16 adds (`proof`, `head`,
 * `holes`, `next`). One call to the vault, `caller` with the head, and at
 * most three statements.
 */
export const auditRoutes = {
  ...route('GET /audit', {
    input: z.object({
      // A project, an environment, or a secret: `market/prod/DATABASE_URL` for who read or changed it.
      path: z.string().max(400).optional(),
      actor: z.string().max(330).optional(),
      decision: z.enum(['allow', 'deny']).optional(),
      // `?detail=1` includes sign-ins and technical steps, `DETAIL_ACTIONS`.
      detail: z.enum(['1', 'true']).optional(),
      // Entries below this seq: a page's `next`, 0 included, below which nothing is.
      before: z.coerce.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
      limit: z.coerce.number().int().min(1).max(500).default(100),
    }),
    run: (ctx, { input: { path, detail, ...rest } }): Promise<AuditPage> =>
      listAudit(ctx, { ...rest, detail: detail !== undefined, ...(path === undefined ? {} : { path: placeNamed(path) }) }),
  }),
  /**
   * What the keys an operator keeps are checked against (`coffre verify
   * keys`, Settings › Keys): the vault's `about`, for whoever runs the
   * instance, as 0.14.7 served it. No secret, and no statement: two calls
   * to the vault, `caller` and `about`.
   */
  ...route('GET /audit/keys', {
    run: async (ctx): Promise<About> => {
      if (!runsInstance((await ctx.caller()).holds)) throw forbidden('only an admin or owner of the whole instance may read what the keys are checked against');
      return ctx.vault.about();
    },
  }),
};

/** A path whose every part is one a place or a key may be called: no other names one, and none reaches a statement. */
function placeNamed(text: string): Path {
  const path = parsePath(text);
  const named = slug.safeParse(path.project).success
    && (path.environment === undefined || environmentPath.safeParse(path.environment).success)
    && (path.key === undefined || secretKey.safeParse(path.key).success);
  if (!named) throw badRequest('name a project, an environment or a key by its name: market, market/prod, market/prod/DATABASE_URL');
  return path;
}
