import { createFileRoute } from '@tanstack/react-router';
import { auth } from '@coffre/server/routes';

export const Route = createFileRoute('/auth/$')({ ...auth });
