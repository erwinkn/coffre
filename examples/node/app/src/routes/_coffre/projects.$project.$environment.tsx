import { createFileRoute } from '@tanstack/react-router';
import { environment } from '@coffre/ui';
import { EnvironmentPage } from '@coffre/ui/pages/environment';

export const Route = createFileRoute('/_coffre/projects/$project/$environment')({ ...environment, component: EnvironmentPage });
