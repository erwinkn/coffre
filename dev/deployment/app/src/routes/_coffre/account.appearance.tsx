import { createFileRoute } from '@tanstack/react-router';
import { accountAppearance } from '@coffre/ui';
import { AccountAppearancePage } from '@coffre/ui/pages/account';

export const Route = createFileRoute('/_coffre/account/appearance')({ ...accountAppearance, component: AccountAppearancePage });
