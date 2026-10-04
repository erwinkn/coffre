import { createFileRoute } from '@tanstack/react-router';
import { deviceLogin } from '@coffre/ui';
import { DevicePage } from '@coffre/ui/pages/device-login';

export const Route = createFileRoute('/_solo/auth/device')({ ...deviceLogin, component: DevicePage });
