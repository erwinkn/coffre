import { createFileRoute } from '@tanstack/react-router';
import { home } from '@coffre/ui';

export const Route = createFileRoute('/_coffre/')({ ...home });
