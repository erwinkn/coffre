// coffre's nav, around the signed-in pages in _coffre/.
import { createFileRoute } from '@tanstack/react-router';
import { shell } from '@coffre/ui';

export const Route = createFileRoute('/_coffre')({ ...shell });
