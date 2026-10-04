import { createFileRoute } from '@tanstack/react-router';
import { token } from '@coffre/ui';
import { TokenPage } from '@coffre/ui/pages/token';

export const Route = createFileRoute('/_coffre/tokens/$token')({ ...token, component: TokenPage });
