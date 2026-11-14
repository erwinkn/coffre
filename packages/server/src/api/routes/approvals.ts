import { z } from 'zod';

import { decide, viewApproval, type ApprovalView, type Decision } from '../../mcp/approvals.ts';
import { route } from '../route.ts';
import { secretValue } from './secrets.ts';

export type { ApprovalView, Decision } from '../../mcp/approvals.ts';

const SHA256 = /^[0-9a-f]{64}$/;

/**
 * A change an MCP client asked for, on the page where its person decides it
 * (docs/design/0.16.md, "An MCP client's changes"): only theirs, on their
 * browser session, from coffre's own page (`mcp/approvals.ts`).
 */
export const approvalRoutes = {
  /** What the page shows: `caller`, one statement, and the reads of what the change would do and replace, as the person. */
  ...route('GET /approvals/:id', {
    run: async (ctx, { params }): Promise<{ approval: ApprovalView }> => ({ approval: await viewApproval(ctx, params.id) }),
  }),
  /**
   * The person's decision, with the digest of the ask the page rendered and
   * the basis of what it replaces: refused before the vault is asked
   * anything if either differs now. Approved, the change is the route's own,
   * its one `change` naming the connection; the approval's row is read,
   * decided and given its outcome, a statement each.
   */
  ...route('POST /approvals/:id', {
    input: z.object({
      approve: z.boolean(),
      digest: z.string().regex(SHA256),
      basis: z.string().regex(SHA256).nullable().optional(),
      // What the person typed, for a change that asks for a value.
      value: secretValue.optional(),
    }).strict(),
    run: (ctx, { params, input }): Promise<Decision> => decide(ctx, params.id, input),
  }),
};
