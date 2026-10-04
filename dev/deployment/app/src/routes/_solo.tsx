// The bare frame of coffre's sign-in pages in _solo/.
import { createFileRoute } from '@tanstack/react-router';
import { solo } from '@coffre/ui';

export const Route = createFileRoute('/_solo')({ ...solo });
