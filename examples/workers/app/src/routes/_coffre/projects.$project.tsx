import { createFileRoute } from '@tanstack/react-router';
import { project } from '@coffre/ui';
import { ProjectLayout } from '@coffre/ui/pages/project';

export const Route = createFileRoute('/_coffre/projects/$project')({ ...project, component: ProjectLayout });
