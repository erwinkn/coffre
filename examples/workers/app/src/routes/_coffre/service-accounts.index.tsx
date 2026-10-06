import { createFileRoute } from '@tanstack/react-router';
import { serviceAccounts } from '@coffre/ui';
import { ServiceAccountsPage } from '@coffre/ui/pages/service-accounts';

export const Route = createFileRoute('/_coffre/service-accounts/')({ ...serviceAccounts, component: ServiceAccountsPage });
