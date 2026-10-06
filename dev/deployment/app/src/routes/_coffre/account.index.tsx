import { createFileRoute } from '@tanstack/react-router';
import { accountProfile } from '@coffre/ui';
import { AccountProfilePage } from '@coffre/ui/pages/account';

export const Route = createFileRoute('/_coffre/account/')({ ...accountProfile, component: AccountProfilePage });
