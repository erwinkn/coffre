import { createFileRoute } from '@tanstack/react-router';
import { jsonResponse } from '../server/http.ts';

export const Route = createFileRoute('/livez')({
  server: {
    handlers: {
      GET: () => jsonResponse({ ok: true }),
    },
  },
});
