import { createFileRoute } from '@tanstack/react-router';
import { livez } from '@coffre/server/routes';

export const Route = createFileRoute('/livez')({ ...livez });
