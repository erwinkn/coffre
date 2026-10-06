import { createFileRoute } from '@tanstack/react-router';
import { userActivity } from '@coffre/ui';
import { UserActivityPage } from '@coffre/ui/pages/user';

export const Route = createFileRoute('/_coffre/users/$user/activity')({ ...userActivity, component: UserActivityPage });
