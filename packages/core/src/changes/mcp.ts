import type { McpScope } from '../mcp.ts';

/**
 * The changes of MCP connections and of the OAuth clients that make them
 * (`packages/vault/src/ops/mcp.ts`, docs/design/0.16.md, "MCP
 * connections"). A connection is a credential of kind `mcp` of the person
 * who approved it: its row holds the code until the client redeems it, then
 * the refresh token. Each access token is a credential of its own, of an
 * hour, under it (`ancestors`): it stands while its connection does, so
 * ending the connection ends them all, with no write of theirs.
 */
export type McpChanges = McpConnect | McpToken | OauthRegister;

export type McpAnswers = {
  /** The connection, and when its code stops being good, ISO 8601. */
  'mcp.connect': { connection: string; expiresAt: string };
  /**
   * The tokens made: the access token's credential, its member, when it
   * ends (ISO 8601), and the scopes it holds. Or, for a code or a refresh
   * token presented again, the connection it ended (`ended`), which the
   * app answers `invalid_grant`.
   */
  'mcp.token': { ended: false; principal: string; connection: string; credential: string; expiresAt: string; scopes: McpScope[] } | { ended: true; connection: string };
  /** The client registered, and when, ISO 8601. */
  'oauth.register': { client: string; createdAt: string };
};

/**
 * The changes nobody asks: a client redeems what it holds (a code with its
 * PKCE verifier, a refresh token), and anyone may register a client.
 */
export type McpUnasked = 'mcp.token' | 'oauth.register';

/**
 * A client as the person approved it: its id (a metadata document's URL,
 * or a registration's id), its name and host as the consent page showed
 * them, how it is known (`cimd`, a document the app fetched; `dcr`, a
 * registration, whose row the vault reads and holds the redirect and the
 * name to), and the redirect the code goes to.
 */
export type McpClient = { id: string; name: string; host: string | null; registration: 'cimd' | 'dcr'; redirectUri: string };

/**
 * A person, on a session of theirs, approves an MCP client
 * (`POST /oauth/authorizations`): a connection, whose code the client
 * redeems within a minute (`CODE_SECONDS`) with its PKCE verifier. The app
 * draws the code and sends its SHA-256 (`code`), with the S256 challenge
 * the client sent (`challenge`, RFC 7636) and the scopes the person ticked
 * (`read` always among them).
 *
 * A token, a workload's session or an MCP connection is refused
 * `no_access`: a personal token connecting one would make a connection
 * with all its person holds. A person with `MAX_CONNECTIONS` connections
 * that stand, codes waiting included, is refused `too_many_connections`.
 * A registered client (`dcr`) is its row's: refused `unknown_client` for
 * one not there, or revoked, and `wrong_redirect` for a redirect it did not
 * register; its name is the row's, whatever the app says.
 */
export type McpConnect = { op: 'mcp.connect'; client: McpClient; scopes: McpScope[]; code: string; challenge: string };

/**
 * A client redeems what it holds for an access token and the next refresh
 * token (`POST /api/oauth/token`). The app draws both and sends their
 * SHA-256 (`tokens`). The access token lasts an hour
 * (`ACCESS_TOKEN_MINUTES`), never past its connection.
 *
 * - `authorization_code`: the code's SHA-256, its PKCE verifier and the
 *   redirect it was sent to, within its minute. The connection then lasts
 *   `minutes` (365 days at most), and the person's earlier connections of
 *   the same client that it grants all of and more end (`supersedes` in
 *   @coffre/core/mcp).
 * - `refresh_token`: the refresh token's SHA-256, and the scopes the client
 *   narrows the access token to, or null for all the connection holds.
 *
 * Refused, writing nothing: `unknown_grant` for a code or a refresh token
 * that is not there, or whose connection ended; `expired`, a code past its
 * minute or a connection past its end; `wrong_client`, `wrong_redirect`,
 * `wrong_verifier`; `invalid_scope` for a refresh that widens; `deactivated`
 * for a person removed since they connected it; `tampered` for a row
 * written behind the vault; `adopting` before the vault adopted the
 * database. A code or a refresh token presented after it was replaced is a
 * copy someone else holds: the connection ends, in a change that is made
 * (`ended: true`), since a refusal writes nothing.
 */
export type McpToken = { op: 'mcp.token'; client: string; tokens: { access: string; refresh: string } } & (
  | { grant: 'authorization_code'; code: string; verifier: string; redirectUri: string; minutes: number }
  | { grant: 'refresh_token'; refresh: string; scopes: McpScope[] | null }
);

/**
 * Anyone registers a client (RFC 7591, `POST /api/oauth/register`): a
 * public one, its name as it claims it and the redirects the app kept
 * (`registrationRedirects` in @coffre/core/mcp). The app's limiter counts
 * who asks; the table holds `MAX_CLIENTS` rows at most, refused `full`
 * past that, and the vault's upkeep deletes those no connection names a
 * week after they were made. Its entry ages out.
 */
export type OauthRegister = { op: 'oauth.register'; name: string; redirectUris: string[] };
