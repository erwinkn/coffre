import { createFileRoute } from '@tanstack/react-router';
import { oauthAuthorize } from '@coffre/ui';
import { OauthAuthorizePage } from '@coffre/ui/pages/oauth-authorize';

export const Route = createFileRoute('/_solo/oauth/authorize')({ ...oauthAuthorize, component: OauthAuthorizePage });
