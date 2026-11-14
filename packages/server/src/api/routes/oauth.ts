import { hashToken } from '@coffre/core/identity';
import { grantedScopes } from '@coffre/core/mcp';
import type { Called } from '@coffre/core/vault';
import { z } from 'zod';

import { connectedApps, consentRead, registeredClient, type ConnectedApp } from '../../db/queries/mcp.ts';
import { checkAuthorization, mcpOf, readyView, redirectTo, type AuthorizationView } from '../../mcp/oauth.ts';
import { changed } from '../change.ts';
import type { ApiContext } from '../context.ts';
import { ApiError, badRequest, notFound, refusal } from '../errors.ts';
import { route } from '../route.ts';

export type { AuthorizationView } from '../../mcp/oauth.ts';
export type { ConnectedApp } from '../../db/queries/mcp.ts';

/** An authorization request's parameters, as OAuth names them: each a string, at most once; any other a client adds is left out. */
const authorization = z.object({
  client_id: z.string().max(2048).optional(),
  redirect_uri: z.string().max(2048).optional(),
  response_type: z.string().max(64).optional(),
  code_challenge: z.string().max(128).optional(),
  code_challenge_method: z.string().max(16).optional(),
  state: z.string().max(4096).optional(),
  scope: z.string().max(256).optional(),
  resource: z.string().max(2048).optional(),
});

/** A person, as themselves, on a session of theirs: whom `mcp.connect` takes, and so whom the consent page shows a request. */
const onOwnSession = (who: Called) => who.principal.startsWith('user:') && who.holds.credentialScope == null;

/** The deployment's MCP, or a 404 for one that turns it off. */
function mcpFor(ctx: ApiContext) {
  const mcp = mcpOf(ctx.auth);
  if (mcp === null) throw notFound("this instance serves no MCP: the deployment's signin({ mcp }) turns it on");
  return mcp;
}

/**
 * MCP clients a person connects, on coffre's own pages (docs/design/0.16.md,
 * "MCP connections"): the consent page, which reads an authorization
 * request and sends the person's answer, and Connected apps, which lists
 * the connections and ends one. The OAuth endpoints a client calls itself
 * are paths outside the API (`mcp/http.ts`).
 */
export const oauthRoutes = {
  /**
   * What the consent page shows for an authorization request, every
   * parameter checked: `caller`, then one statement (the client's
   * registration, and the person's connections of it), and the client's
   * metadata document fetched when it is not kept. Refused to another
   * site's page, before anything is fetched.
   */
  ...route('GET /oauth/authorizations', {
    input: authorization,
    run: async (ctx, { input }): Promise<AuthorizationView> => {
      const mcp = mcpFor(ctx);
      if (ctx.crossSite) throw new ApiError('cross_origin', 'an app connects on coffre\'s own page, opened in its own tab');
      const who = await ctx.caller();
      if (!onOwnSession(who)) throw refusal('no_access');
      const { registered, connections } = await consentRead(ctx.db, who.principal, input.client_id ?? '', new Date());
      const checked = await checkAuthorization(mcp, ctx, input, registered, ctx.shown.ip);
      return checked.status === 'ready' ? readyView(mcp, checked, connections) : checked;
    },
  }),
  /**
   * The person's answer, the request checked again: nothing is kept between
   * the page and this. Approved: a connection, the vault's `mcp.connect`,
   * and the redirect that carries its code. Denied: the redirect that says
   * so, and nothing written. `caller` first, then a registration's row,
   * one statement, or the client's metadata document as for the page.
   */
  ...route('POST /oauth/authorizations', {
    input: z.object({ request: authorization, approve: z.boolean(), scopes: z.array(z.string().max(32)).max(8).optional() }).strict(),
    run: async (ctx, { input }): Promise<{ redirect: string }> => {
      const mcp = mcpFor(ctx);
      const who = await ctx.caller();
      // A personal token connecting one would make a connection with all its person holds.
      if (!onOwnSession(who)) throw refusal('no_access');
      const { request } = input;
      const registered = await registeredClient(ctx.db, request.client_id ?? '');
      const checked = await checkAuthorization(mcp, ctx, request, registered, ctx.shown.ip);
      if (checked.status === 'invalid') throw badRequest(checked.message);
      if (checked.status === 'refused') return { redirect: checked.redirect };
      const back = (params: Record<string, string>) => ({ redirect: redirectTo(mcp.publicUrl, checked.redirectUri, request.state, params) });
      if (!input.approve) return back({ error: 'access_denied', error_description: 'the person did not approve the connection' });
      const { client } = checked;
      // The code: 32 random bytes, which the client holds for a minute; the vault keeps its SHA-256.
      const code = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
      await changed(ctx, {
        op: 'mcp.connect',
        client: { id: client.clientId, name: client.name, host: client.host, registration: client.registration, redirectUri: checked.redirectUri },
        scopes: grantedScopes(input.scopes ?? []),
        code: hashToken(code).toString('hex'),
        challenge: checked.challenge,
      }, client.name);
      return back({ code });
    },
  }),
  /** The caller's connected apps, newest first: `caller` and one statement; none where the deployment serves no MCP. */
  ...route('GET /apps', {
    run: async (ctx): Promise<{ apps: ConnectedApp[] }> => {
      const who = await ctx.caller();
      if (mcpOf(ctx.auth) === null) return { apps: [] };
      return { apps: await connectedApps(ctx.db, who.principal, new Date()) };
    },
  }),
  /** One of the caller's connected apps disconnected, and every access token under it: one `change`, no statement. An owner may end anyone's. */
  ...route('DELETE /apps/:id', {
    run: async (ctx, { params }): Promise<{ disconnected: true }> => {
      await changed(ctx, { op: 'credential.end', credential: params.id, of: null }, 'that app');
      return { disconnected: true };
    },
  }),
};
