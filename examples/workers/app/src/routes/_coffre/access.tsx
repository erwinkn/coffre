import { createFileRoute } from '@tanstack/react-router';
import { access } from '@coffre/ui';

export const Route = createFileRoute('/_coffre/access')({ ...access });
