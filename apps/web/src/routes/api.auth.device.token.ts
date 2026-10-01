import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { trustedSourceIp } from '../server/auth.ts';
import { apiErrorResponse, jsonResponse, methodNotAllowed, parseJson } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';

const body = z.object({ device_code: z.string().min(1).max(128) });

/**
 * The CLI's poll. Errors use RFC 8628's names so any device-flow client
 * understands them; success returns a CLI session token, once.
 */
export const Route = createFileRoute('/api/auth/device/token')({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const runtime = getRuntime();
        if (runtime.signin === null) return jsonResponse({ error: 'not_found' }, 404);
        try {
          const { device_code } = await parseJson(request, (value) => body.parse(value));
          const polled = await runtime.signin.pollDevice(device_code, {
            requestId: crypto.randomUUID(),
            sourceIp: trustedSourceIp(request, runtime.auth),
          });
          switch (polled.status) {
            case 'pending':
              return jsonResponse({ error: 'authorization_pending' }, 400);
            case 'denied':
              return jsonResponse({ error: 'access_denied' }, 400);
            case 'expired':
              return jsonResponse({ error: 'expired_token' }, 400);
            case 'approved':
              return jsonResponse({
                access_token: polled.credential.token,
                token_type: 'Bearer',
                expires_at: polled.credential.expiresAt,
                principal: polled.principal,
              });
          }
        } catch (error) {
          return apiErrorResponse(error);
        }
      },
      ANY: () => methodNotAllowed(['POST']),
    },
  },
});
