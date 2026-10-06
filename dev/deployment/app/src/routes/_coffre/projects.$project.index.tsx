import { createFileRoute } from '@tanstack/react-router';
import { projectEnvironments } from '@coffre/ui';
import { ProjectEnvironmentsPage } from '@coffre/ui/pages/project-environments';

export const Route = createFileRoute('/_coffre/projects/$project/')({ ...projectEnvironments, component: ProjectEnvironmentsPage });
