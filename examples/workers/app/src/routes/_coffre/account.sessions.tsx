import { createFileRoute } from '@tanstack/react-router';
import { accountSessions } from '@coffre/ui';
import { AccountSessionsPage } from '@coffre/ui/pages/account';

export const Route = createFileRoute('/_coffre/account/sessions')({ ...accountSessions, component: AccountSessionsPage });
