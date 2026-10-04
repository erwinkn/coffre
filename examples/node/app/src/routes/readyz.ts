import { createFileRoute } from '@tanstack/react-router';
import { readyz } from '@coffre/server/routes';

export const Route = createFileRoute('/readyz')({ ...readyz });
