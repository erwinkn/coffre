import { createFileRoute } from '@tanstack/react-router';
import { projectSettings } from '@coffre/ui';
import { ProjectSettingsPage } from '@coffre/ui/pages/project-settings';

export const Route = createFileRoute('/_coffre/projects/$project/settings')({ ...projectSettings, component: ProjectSettingsPage });
