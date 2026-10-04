import { createFileRoute } from '@tanstack/react-router';
import { projects } from '@coffre/ui';
import { ProjectsPage } from '@coffre/ui/pages/projects';

export const Route = createFileRoute('/_coffre/projects/')({ ...projects, component: ProjectsPage });
