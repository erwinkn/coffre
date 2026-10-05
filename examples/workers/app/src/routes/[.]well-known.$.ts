import { createFileRoute } from '@tanstack/react-router';
import { wellKnown } from '@coffre/server/routes';

export const Route = createFileRoute('/.well-known/$')({ ...wellKnown });
