import { createFileRoute } from '@tanstack/react-router';
import { tokens } from '@coffre/ui';
import { TokensPage } from '@coffre/ui/pages/tokens';

export const Route = createFileRoute('/_coffre/tokens/')({ ...tokens, component: TokensPage });
