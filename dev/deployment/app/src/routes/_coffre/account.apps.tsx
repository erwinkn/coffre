import { createFileRoute } from '@tanstack/react-router';
import { accountApps } from '@coffre/ui';
import { AccountAppsPage } from '@coffre/ui/pages/account';

export const Route = createFileRoute('/_coffre/account/apps')({ ...accountApps, component: AccountAppsPage });
