import { createFileRoute } from '@tanstack/react-router';
import { accountPasskeys } from '@coffre/ui';
import { AccountPasskeysPage } from '@coffre/ui/pages/account';

export const Route = createFileRoute('/_coffre/account/passkeys')({ ...accountPasskeys, component: AccountPasskeysPage });
