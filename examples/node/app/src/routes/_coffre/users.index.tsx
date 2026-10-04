import { createFileRoute } from '@tanstack/react-router';
import { users } from '@coffre/ui';
import { UsersPage } from '@coffre/ui/pages/users';

export const Route = createFileRoute('/_coffre/users/')({ ...users, component: UsersPage });
