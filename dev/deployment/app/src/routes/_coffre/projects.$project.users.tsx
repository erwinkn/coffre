import { createFileRoute } from '@tanstack/react-router';
import { projectUsers } from '@coffre/ui';
import { ProjectUsersPage } from '@coffre/ui/pages/project-access';

export const Route = createFileRoute('/_coffre/projects/$project/users')({ ...projectUsers, component: ProjectUsersPage });
