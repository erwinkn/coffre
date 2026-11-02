// The Proxy tab, a prototype (W260, DO NOT MERGE): beside the environment's
// page rather than under it, and on the dev deployment alone, with the
// store src/proxy-prototype.ts keeps.
import { createFileRoute } from '@tanstack/react-router';
import { environmentProxy } from '@coffre/ui';
import { EnvironmentProxyPage } from '@coffre/ui/pages/environment-proxy';

import { proxyStore } from '../../proxy-prototype';

export const Route = createFileRoute('/_coffre/projects/$project_/$environment_/proxy')({
  ...environmentProxy(proxyStore),
  component: () => <EnvironmentProxyPage store={proxyStore} />,
});
