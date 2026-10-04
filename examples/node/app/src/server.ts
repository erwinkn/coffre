// The server: Start's handler, with coffre in each request's context, and
// coffre's scheduled job, the heartbeat and audit checkpoints, every five
// minutes from the start. `vite build app` builds it into
// app/dist/server/server.js, which `pnpm start` runs.
import handler from '@tanstack/react-start/server-entry';

import { coffre } from './coffre';

coffre.schedule();

export default {
  fetch: (request: Request) => handler.fetch(request, { context: coffre.request(request) }),
};
