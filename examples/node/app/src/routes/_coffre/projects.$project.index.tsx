import { createFileRoute } from '@tanstack/react-router';
import { project } from '@coffre/ui';
import { ProjectPage } from '@coffre/ui/pages/project';

export const Route = createFileRoute('/_coffre/projects/$project/')({ ...project, component: ProjectPage });
