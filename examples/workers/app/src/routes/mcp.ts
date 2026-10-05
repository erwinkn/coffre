import { createFileRoute } from '@tanstack/react-router';
import { mcp } from '@coffre/server/routes';

export const Route = createFileRoute('/mcp')({ ...mcp });
