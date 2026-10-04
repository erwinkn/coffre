// The app Worker `pnpm dev` runs: Start's handler, with coffre in each
// request's context, and coffre's scheduled job.
import handler from '@tanstack/react-start/server-entry';

import { coffre, type Env } from './coffre';

export default {
  fetch: (request: Request, env: Env, ctx: ExecutionContext) => handler.fetch(request, { context: coffre.request(env, ctx) }),
  scheduled: coffre.scheduled,
};
