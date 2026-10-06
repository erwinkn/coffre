import { createFileRoute } from '@tanstack/react-router';
import { serviceAccount } from '@coffre/ui';
import { ServiceAccountLayout } from '@coffre/ui/pages/service-account';

export const Route = createFileRoute('/_coffre/service-accounts/$account')({ ...serviceAccount, component: ServiceAccountLayout });
