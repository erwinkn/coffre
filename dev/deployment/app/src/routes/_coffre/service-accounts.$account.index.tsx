import { createFileRoute } from '@tanstack/react-router';
import { serviceAccountSignIn } from '@coffre/ui';
import { ServiceAccountSignInPage } from '@coffre/ui/pages/service-account';

export const Route = createFileRoute('/_coffre/service-accounts/$account/')({ ...serviceAccountSignIn, component: ServiceAccountSignInPage });
