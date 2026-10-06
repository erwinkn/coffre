import { createFileRoute } from '@tanstack/react-router';
import { projectServiceAccounts } from '@coffre/ui';
import { ProjectServiceAccountsPage } from '@coffre/ui/pages/project-access';

export const Route = createFileRoute('/_coffre/projects/$project/service-accounts')({ ...projectServiceAccounts, component: ProjectServiceAccountsPage });
