import { createFileRoute } from '@tanstack/react-router';
import { account } from '@coffre/ui';
import { AccountPage } from '@coffre/ui/pages/account';

export const Route = createFileRoute('/_coffre/account')({ ...account, component: AccountPage });
