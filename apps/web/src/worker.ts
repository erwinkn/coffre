import handler from '@tanstack/react-start/server-entry';

import { writeAuditHeartbeat } from './server/heartbeat.ts';
import {
  getRuntime,
  runWithWorkerRuntime,
  type WorkerBindings,
} from './server/runtime.ts';

function runtimeLogger() {
  return {
    warn(value: unknown, message: string) {
      console.warn(message, value);
    },
  };
}

export default {
  fetch(request, bindings, _context) {
    return runWithWorkerRuntime(bindings, () =>
      handler.fetch(request));
  },

  async scheduled(_controller, bindings, context) {
    context.waitUntil(
      runWithWorkerRuntime(bindings, async () => {
        const written = await writeAuditHeartbeat(getRuntime().pool, runtimeLogger());
        if (!written) {
          throw new Error('scheduled audit heartbeat failed');
        }
      }),
    );
  },
} satisfies ExportedHandler<WorkerBindings>;
