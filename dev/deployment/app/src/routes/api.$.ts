import { createFileRoute } from '@tanstack/react-router';
import { api } from '@coffre/server/routes';

export const Route = createFileRoute('/api/$')({ ...api });
