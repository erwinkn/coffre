import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { trustedSourceIp } from '../server/auth.ts';
import { apiErrorResponse, jsonResponse, methodNotAllowed, parseOptionalJson } from '../server/http.ts';
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
        if (runtime.signin === null) return jsonResponse({ error: 'not_found' }, 404);
        try {
          const input = await parseOptionalJson(request, (value) => body.parse(value));
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
          const status = (error as { statusCode?: number }).statusCode;
          if (status === 429) return jsonResponse({ error: 'slow_down' }, 429);
          return apiErrorResponse(error);
        }
      },
      ANY: () => methodNotAllowed(['POST']),
    },
  },
});
