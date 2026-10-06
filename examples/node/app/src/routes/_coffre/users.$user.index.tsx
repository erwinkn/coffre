import { createFileRoute } from '@tanstack/react-router';
import { userAccess } from '@coffre/ui';
import { UserAccessPage } from '@coffre/ui/pages/user';

export const Route = createFileRoute('/_coffre/users/$user/')({ ...userAccess, component: UserAccessPage });
