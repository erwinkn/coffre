import { createFileRoute } from '@tanstack/react-router';
import { user } from '@coffre/ui';
import { UserLayout } from '@coffre/ui/pages/user';

export const Route = createFileRoute('/_coffre/users/$user')({ ...user, component: UserLayout });
