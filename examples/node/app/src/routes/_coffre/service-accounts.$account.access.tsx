import { createFileRoute } from '@tanstack/react-router';
import { serviceAccountAccess } from '@coffre/ui';
import { ServiceAccountAccessPage } from '@coffre/ui/pages/service-account';

export const Route = createFileRoute('/_coffre/service-accounts/$account/access')({ ...serviceAccountAccess, component: ServiceAccountAccessPage });
