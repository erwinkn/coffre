import { createFileRoute } from '@tanstack/react-router';
import { environmentProxy } from '@coffre/ui';
import { EnvironmentProxyPage } from '@coffre/ui/pages/environment-proxy';

export const Route = createFileRoute('/_coffre/projects/$project_/$environment_/proxy')({ ...environmentProxy, component: EnvironmentProxyPage });
