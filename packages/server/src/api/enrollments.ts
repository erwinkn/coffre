// Enrollment codes (docs/design/workload-access.md, section 4.4): minting
// one for a binding, listing a binding's, promoting one to supersede the
// rest, and approving a session an `approve` binding holds. Declared in
// every map of the API by that design's PR 0; PR 3 serves them, here.
import { z } from 'zod';

import type { ApiContext } from './context.ts';
import { notBuilt } from './errors.ts';

/** `POST /members/:member/bindings/:id/enrollments`: what a code is minted with. */
export const mintInput = z.object({}).strict();

/** `POST …/enrollments/:enrollment/promote`: `now` ends the older codes' sessions at once, rather than letting them drain. */
export const promoteInput = z.object({ now: z.boolean().optional() }).strict();

type Binding = { member: string; id: string };

export async function listEnrollments(_ctx: ApiContext, _binding: Binding): Promise<never> {
  throw notBuilt("a binding's enrollment codes", 'PR 3');
}

export async function mintEnrollment(_ctx: ApiContext, _binding: Binding, _input: z.output<typeof mintInput>): Promise<never> {
  throw notBuilt('minting an enrollment code', 'PR 3');
}

export async function promoteEnrollment(_ctx: ApiContext, _code: Binding & { enrollment: string }, _input: z.output<typeof promoteInput>): Promise<never> {
  throw notBuilt('promoting an enrollment code', 'PR 3');
}

export async function approveSession(_ctx: ApiContext, _session: { member: string; id: string }): Promise<never> {
  throw notBuilt("approving a workload's session", 'PR 3');
}
