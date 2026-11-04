import { createFileRoute } from '@tanstack/react-router';
import { passkey } from '@coffre/ui';
import { PasskeyPage } from '@coffre/ui/pages/passkey';

export const Route = createFileRoute('/_solo/auth/passkey')({ ...passkey, component: PasskeyPage });
