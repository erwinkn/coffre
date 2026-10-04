import { createFileRoute } from '@tanstack/react-router';
import { settings } from '@coffre/ui';
import { SettingsPage } from '@coffre/ui/pages/settings';

export const Route = createFileRoute('/_coffre/settings')({ ...settings, component: SettingsPage });
