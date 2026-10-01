import handler from '@tanstack/react-start/server-entry';

import {
  getRuntime,
  runWithWorkerRuntime,
  type WorkerBindings,
} from './server/runtime.ts';
import { cspNonce, withSecurityHeaders } from './server/security-headers.ts';

function runtimeLogger() {
  return {
    warn(value: unknown, message: string) {
      console.warn(message, value);
    },
  };
}

export default {
  fetch(request, bindings, context) {
    return runWithWorkerRuntime(bindings, async () => {
      // The router puts it on every script it renders; see router.tsx.
      const nonce = cspNonce();
      const response = await handler.fetch(request, { context: { cspNonce: nonce } });
      const auth = getRuntime().auth;
      return withSecurityHeaders(request, response, {
        nonce,
        formOrigins: auth.mode === 'cloudflare' ? [auth.access.issuer] : [],
      });
    }, context);
  },

  async scheduled(_controller, bindings, context) {
    context.waitUntil(
      runWithWorkerRuntime(bindings, async () => {
        const runtime = getRuntime();
        // Independent: a destination that is down must not stop the heartbeat,
        // and a failed heartbeat must not hold back pending syncs.
        const [heartbeat, syncs] = await Promise.allSettled([
          runtime.audit.writeHeartbeat(runtimeLogger()),
          runtime.syncs.reconcile(),
        ]);
        if (syncs.status === 'rejected') console.error('scheduled syncs failed', syncs.reason);
        if (heartbeat.status === 'rejected' || !heartbeat.value) {
          throw new Error('scheduled audit heartbeat failed');
        }
      }, context),
    );
  },
} satisfies ExportedHandler<WorkerBindings>;
