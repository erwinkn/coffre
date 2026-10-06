import { createFileRoute } from '@tanstack/react-router';
import { serviceAccountActivity } from '@coffre/ui';
import { ServiceAccountActivityPage } from '@coffre/ui/pages/service-account';

export const Route = createFileRoute('/_coffre/service-accounts/$account/activity')({ ...serviceAccountActivity, component: ServiceAccountActivityPage });
