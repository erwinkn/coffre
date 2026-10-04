import { createFileRoute } from '@tanstack/react-router';
import { login } from '@coffre/ui';
import { LoginPage } from '@coffre/ui/pages/login';

export const Route = createFileRoute('/_solo/login')({ ...login, component: LoginPage });
