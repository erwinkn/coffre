import { createFileRoute } from '@tanstack/react-router';
import { auditReadiness } from '../server/heartbeat.ts';
import { jsonResponse } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';

export const Route = createFileRoute('/readyz')({
  server: {
    handlers: {
      GET: async () => {
        const runtime = getRuntime();
        const readiness = await auditReadiness(runtime.db);
        return jsonResponse(readiness, readiness.ok ? 200 : 503);
      },
    },
  },
});
