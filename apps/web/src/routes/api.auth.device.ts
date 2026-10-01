import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { trustedSourceIp } from '../server/auth.ts';
import { ApiError, notFound } from '../server/api/errors.ts';
import { errorResponse, jsonResponse, methodNotAllowed, readJson } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';

const body = z.object({ client_label: z.string().trim().max(120).optional() });

/**
 * Start a device login (RFC 8628): the CLI gets a code for the person to
 * approve in a signed-in browser, and a device code to poll with.
 */
export const Route = createFileRoute('/api/auth/device')({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const runtime = getRuntime();
        if (runtime.signin === null) return errorResponse(notFound('device login needs signin mode'));
        try {
          const input = body.parse(await readJson(request, {}));
          const started = await runtime.signin.startDevice({
            clientLabel: input.client_label ?? null,
            sourceIp: trustedSourceIp(request, runtime.auth),
          });
          return jsonResponse({
            device_code: started.deviceCode,
            user_code: started.userCode,
            verification_uri: started.verificationUri,
            verification_uri_complete: started.verificationUriComplete,
            expires_in: started.expiresIn,
            interval: started.interval,
          });
        } catch (error) {
          if (error instanceof ApiError && error.code === 'too_many_requests') {
            return jsonResponse({ error: 'slow_down', message: error.message }, 429);
          }
          return errorResponse(error);
        }
      },
      ANY: () => methodNotAllowed(['POST']),
    },
  },
});
