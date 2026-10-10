import { createFileRoute } from '@tanstack/react-router';
import { userApps } from '@coffre/ui';
import { UserAppsPage } from '@coffre/ui/pages/user';

export const Route = createFileRoute('/_coffre/users/$user/apps')({ ...userApps, component: UserAppsPage });
