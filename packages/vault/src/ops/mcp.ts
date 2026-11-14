import { createHash, randomUUID } from 'node:crypto';

import { ACCESS_TOKEN_MINUTES, CODE_SECONDS, isMcpScope, MAX_CLIENTS, MAX_CONNECTIONS, MCP_SCOPES, redirectKind, redirectMatches, scopeString, supersedes, type McpScope } from '@coffre/core/mcp';
import type { Answers, Asked, McpChanges, McpClient, Presented } from '@coffre/core/vault';
import { credentials, oauthClients, principals } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { callerParts, ID, mcpClientOf, refusedTo } from '../caller.ts';
import { amended, part, put, WRITE_MS, type Operation, type Parts, type Seen, type Unsealed, type Write } from '../change.ts';
import type { Fresh, Row } from '../rows.ts';
import type { Deciding } from '../vault.ts';
import { asking, NOWHERE } from './asking.ts';
import type { Operations } from './index.ts';
import { HASH, long, presented, text, traced } from './input.ts';
import { onSession } from './services.ts';
import { adopted, by, instancePart, VAULT } from './signin.ts';

/**
 * MCP connections and the OAuth clients that make them
 * (docs/design/0.16.md, "MCP connections"). A connection is a credential
 * of kind `mcp` with no ancestors: its token is its code until the client
 * redeems it, then its refresh token. The refresh token it replaced is kept
 * beside it (`previous_token_hash`), and its code for as long as it lasts
 * (`code_hash`), so that either, presented after, is known for a copy.
 * Each access token is a credential of kind `mcp` under it, an hour long
 * (`callerOf` in caller.ts).
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** An S256 challenge (RFC 7636, section 4.2): a SHA-256, base64url with no padding. */
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
/** A PKCE verifier (RFC 7636, section 4.1). */
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
/** The longest a connection lasts, whatever the app asks: the most a deployment's `cliSessionDays` says, as a CLI's session. */
const CONNECTION_MINUTES = 365 * 24 * 60;
/** A client's name and redirect, as the app keeps them (`clientName`, `registrationRedirects` in @coffre/core/mcp). */
const MOST_NAME = 100;
const MOST_URI = 400;
const MOST_REDIRECTS = 10;

const redirect = (value: unknown): value is string => {
  if (!long(value, MOST_URI)) return false;
  try {
    redirectKind(value);
    return true;
  } catch {
    return false;
  }
};

/** A host as a URL's own: letters, digits, dots and dashes, and a port. */
const HOST = /^[a-z0-9.-]{1,253}(:[0-9]{1,5})?$/;

/**
 * What an entry says of a client: how it is known, the registration's id,
 * which the vault drew, and its host if it reads as one. Never its name, a
 * metadata document's URL nor a redirect: whoever made the client chose
 * them, and the log takes no free text from a caller (docs/design/0.16.md,
 * "A refused change is logged"). The connection's row keeps the rest.
 */
const logged = (client: Pick<McpClient, 'id' | 'host' | 'registration'>) =>
  ({ registration: client.registration, client: client.registration === 'dcr' && UUID.test(client.id) ? client.id : null, host: client.host !== null && HOST.test(client.host) ? client.host : null });

/** A name as the app shows it: no control or format character, which could make one look like another. */
const named = (value: unknown): value is string => long(value, MOST_NAME) && value !== '' && value === value.trim() && !/[\p{Cc}\p{Cf}]/u.test(value);

/** Scopes as the contract takes them: known ones, each once, `read` among them; in the catalogue's order. */
function scopesAsked(value: unknown): McpScope[] | undefined {
  if (!Array.isArray(value) || !value.every((scope) => typeof scope === 'string' && isMcpScope(scope)) || new Set(value).size !== value.length || !value.includes('read')) return undefined;
  return MCP_SCOPES.filter((scope) => value.includes(scope));
}

function clientAsked(value: McpClient | undefined): McpClient | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const { id, name, host, registration, redirectUri } = value;
  if (!text(id) || id === '' || !named(name) || !(host === null || (text(host) && host !== '')) || !redirect(redirectUri)) return undefined;
  // A registration is known by its row, which names no host to vouch for it.
  if (registration === 'dcr' ? !UUID.test(id) || host !== null : registration !== 'cimd') return undefined;
  return { id, name, host, registration, redirectUri };
}

/**
 * The client as a connection's row keeps it, JSON, in the shape 0.14's
 * connections were carried over in (0022_smaller_vault.sql): its id first,
 * by which the upkeep tells a registration no connection names.
 */
const storedClient = (client: Pick<McpClient, 'id' | 'host' | 'registration' | 'redirectUri'>, scopes: readonly McpScope[]) =>
  JSON.stringify({ id: client.id, host: client.host, registration: client.registration, redirectUri: client.redirectUri, scopes: scopeString(scopes) });

/** A credential's row, all its columns, with what an MCP one says. */
function mcpRow(fields: Pick<Fresh<typeof credentials>, 'id' | 'tokenHash' | 'codeHash' | 'generation' | 'principal' | 'label' | 'createdAt' | 'createdBy' | 'expiresAt' | 'ancestors' | 'client' | 'challenge'>): Fresh<typeof credentials> {
  return {
    kind: 'mcp', tokenHint: null, previousTokenHash: null, identityId: null, scope: null, places: null, lastUsedAt: null, lastUsedIp: null, frozenAt: null, revokedAt: null, revokedBy: null,
    jkt: null, notAfter: null, constraints: null, enrollmentId: null, approvedAt: null, approvedBy: null, run: null, ...fields,
  };
}

/** A connection's own row: an MCP credential with no ancestors, whose token is its code or its refresh token. */
const isConnection = (row: Row<typeof credentials>) => row.kind === 'mcp' && row.ancestors === null;

/**
 * A person approves an MCP client (`McpConnect`): one row written, the
 * connection, holding the code's hash and the PKCE challenge, and good for
 * a minute (`CODE_SECONDS`) until its code is redeemed (`mcp.token`). Kept
 * for good, as 0.14.7 logged it.
 *
 * The person's connections are counted from the read: one hidden from it
 * lets them hold one more than they may, which costs nobody else. One
 * written behind the vault counts. A registered client's row written behind
 * the vault refuses it, `tampered`: its redirect is where the code goes.
 */
function mcpConnect(input: Presented & McpChanges & { op: 'mcp.connect' }, vault: Deciding): Operation<Parts, Answers['mcp.connect']> {
  const shown = presented(input);
  const client = clientAsked(input.client);
  const scopes = scopesAsked(input.scopes);
  const { code, challenge } = input;
  if (client === undefined || scopes === undefined || !text(code) || !HASH.test(code) || !text(challenge) || !CHALLENGE.test(challenge)) {
    throw new TypeError("a connection names its client (its id, name, host, how it is known and its redirect), the scopes the person granted, `read` among them, its code's SHA-256 and the client's S256 challenge");
  }
  // Drawn here: a decision draws nothing.
  const id = randomUUID();
  const read = {
    ...callerParts(shown.token, NOWHERE),
    // The caller's connections that are not revoked, by `credentials_live_idx`; the decision tells those that stand.
    theirs: part(credentials, sql`${credentials.principal} = (SELECT c.principal FROM credentials c WHERE c.token_hash = decode(${shown.token.toString('hex')}, 'hex')) AND ${credentials.revokedAt} IS NULL AND ${credentials.client} IS NOT NULL AND ${credentials.ancestors} IS NULL`),
    registered: part(oauthClients, client.registration === 'dcr' ? sql`${oauthClients.id} = ${client.id}::uuid` : sql`false`),
  };
  return {
    read,
    denied: refusedTo('mcp.connect', shown, vault.workloads),
    decide(seen: Seen<typeof read>, at: number, unsealed: Unsealed<typeof read>) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      // A person, as themselves, on a session: a personal token connecting one would make a connection with all its person holds (0.14.7).
      if (!onSession(caller) || !caller.principal.startsWith('user:')) return { refused: 'no_access' };
      let name = client.name;
      if (client.registration === 'dcr') {
        if (unsealed.registered > 0) return { refused: 'tampered' };
        const [row] = seen.registered;
        const uris = row === undefined || row.revokedAt !== null ? undefined : redirectsOf(row.redirectUris);
        if (uris === undefined) return { refused: 'unknown_client' };
        if (!uris.some((registered) => redirectMatches(registered, client.redirectUri))) return { refused: 'wrong_redirect' };
        // Its own claim, as its row keeps it, whatever the page was shown.
        name = row!.name;
      }
      if (seen.theirs.filter((row) => row.expiresAt.getTime() > at).length + unsealed.theirs >= MAX_CONNECTIONS) return { refused: 'too_many_connections' };
      const now = new Date(at);
      const expiresAt = new Date(at + CODE_SECONDS * 1000);
      return {
        writes: [put(credentials, mcpRow({
          id, tokenHash: Buffer.from(code, 'hex'), codeHash: Buffer.from(code, 'hex'), generation: caller.credential.generation, principal: caller.principal, label: name, createdAt: now, createdBy: caller.principal,
          expiresAt, ancestors: null, client: storedClient(client, scopes), challenge,
        }))],
        entry: {
          ...by(caller, shown),
          kept: true,
          action: 'mcp.connect',
          objects: [`principal:${caller.principal}`, `credential:${caller.credential.id}`, `credential:${id}`, ...(client.registration === 'dcr' ? [`oauth_client:${client.id}`] : [])],
          detail: { connection: id, ...logged(client), scopes: scopeString(scopes) },
        },
        answer: { connection: id, expiresAt: expiresAt.toISOString() },
      };
    },
  };
}

/** A registration's redirects, as its row keeps them, JSON; undefined for a row that does not read as such. */
function redirectsOf(stored: string): string[] | undefined {
  try {
    const uris: unknown = JSON.parse(stored);
    return Array.isArray(uris) && uris.every((uri) => typeof uri === 'string') ? uris : undefined;
  } catch {
    return undefined;
  }
}

/**
 * A client redeems a code or a refresh token (`McpToken`): in one
 * statement, the connection's row written with its next refresh token, and
 * an access token's row under it. For a code, the connection lasts from
 * then on, and the person's earlier connections of the client that it
 * supersedes end. Nobody asks it but whoever holds the code, with its
 * verifier, or the refresh token. Its entry ages out, as a session's coming
 * does, unless it ends a connection.
 *
 * Of two redeeming one token at once, the second finds it replaced, and
 * ends the connection: a refresh token is the client's alone, and two
 * holders of it mean one is not the client (OAuth 2.1, section 4.3.1).
 * The access tokens under the connection end with it, by its row alone.
 *
 * Its decision rests on the connection's row and its member's: either
 * written behind the vault refuses it, `tampered`. The person's other
 * connections only end: one hidden from the read stays, one written behind
 * it is not ended.
 */
function mcpToken(input: Asked<'mcp.token'>): Operation<Parts, Answers['mcp.token']> {
  const from = traced(input);
  const { client, tokens, grant } = input;
  const code = input.grant === 'authorization_code' ? input : undefined;
  const refresh = input.grant === 'refresh_token' ? input : undefined;
  const narrowed = refresh?.scopes === null ? null : scopesAsked(refresh?.scopes);
  const held = code?.code ?? refresh?.refresh;
  if (!text(client) || client === '' || !text(tokens?.access) || !HASH.test(tokens.access) || !text(tokens.refresh) || !HASH.test(tokens.refresh) || !text(held) || !HASH.test(held)
    || new Set([tokens.access, tokens.refresh, held]).size !== 3
    || (code !== undefined && !(text(code.verifier) && VERIFIER.test(code.verifier) && redirect(code.redirectUri) && Number.isInteger(code.minutes) && code.minutes >= 1 && code.minutes <= CONNECTION_MINUTES))
    || (refresh !== undefined && narrowed === undefined) || (code === undefined && refresh === undefined)) {
    throw new TypeError("a client redeems a code, with its PKCE verifier, its redirect and the connection's minutes (365 days at most), or a refresh token, with the scopes it narrows to; for an access token and a refresh token, each by its SHA-256, all three different");
  }
  // Told here, from the input alone: the challenge is the verifier's SHA-256 (S256).
  const proof = code === undefined ? undefined : createHash('sha256').update(code.verifier).digest('base64url');
  // Drawn here: a decision draws nothing.
  const access = randomUUID();
  const hash = sql`decode(${held}, 'hex')`;
  // By its unique index or the index beside each: its token now, the refresh token it replaced, or its code.
  const found = sql`SELECT c.id FROM credentials c WHERE c.token_hash = ${hash} UNION ALL SELECT c.id FROM credentials c WHERE c.previous_token_hash = ${hash}
    UNION ALL SELECT c.id FROM credentials c WHERE c.code_hash = ${hash}`;
  const read = {
    connection: part(credentials, sql`${credentials.id} IN (${found})`),
    member: part(principals, sql`${principals.id} IN (SELECT c.principal FROM credentials c WHERE c.id IN (${found}))`),
    // A code's person's other connections of any client, which it may supersede: those not revoked, by `credentials_live_idx`.
    others: part(credentials, code === undefined ? sql`false`
      : sql`${credentials.principal} IN (SELECT c.principal FROM credentials c WHERE c.token_hash = ${hash}) AND ${credentials.revokedAt} IS NULL AND ${credentials.client} IS NOT NULL AND ${credentials.ancestors} IS NULL`),
    instance: instancePart(),
  };
  return {
    read,
    decide(seen: Seen<typeof read>, at: number, unsealed: Unsealed<typeof read>) {
      const before = adopted(seen.instance, unsealed.instance);
      if (before !== undefined) return before;
      if (unsealed.connection + unsealed.member > 0) return { refused: 'tampered' };
      const row = seen.connection.find(isConnection);
      const stored = row && mcpClientOf(row.client);
      if (row === undefined || stored === undefined || row.revokedAt !== null) return { refused: 'unknown_grant' };
      const now = new Date(at);

      // Presented after it was replaced: someone else holds a copy. The connection ends, and every access token under it.
      if (!row.tokenHash.equals(Buffer.from(held, 'hex'))) {
        if (row.expiresAt.getTime() <= at) return { refused: 'unknown_grant' };
        return {
          writes: [amended(credentials, row, { revokedAt: now, revokedBy: VAULT })],
          entry: {
            kept: true,
            action: 'mcp.disconnect', actor: null, credential: null, request: from.request, ip: from.ip,
            objects: [`credential:${row.id}`, `principal:${row.principal}`],
            detail: { connection: row.id, ...logged(stored), principal: row.principal, reason: grant === 'authorization_code' ? 'code_reused' : 'refresh_reused' },
          },
          answer: { ended: true, connection: row.id },
        };
      }

      // A code is redeemed as one, a refresh token as one: neither is the other.
      if ((row.challenge === null) === (code !== undefined)) return { refused: 'unknown_grant' };
      // As its row holds it, before anything a write's time could change: within the minute, or the connection's life, less a write's time.
      if (row.expiresAt.getTime() - WRITE_MS <= at) return { refused: 'expired' };
      if (stored.id !== client) return { refused: 'wrong_client' };
      // Removed since they connected it: let back in, they hold nothing from before.
      const who = seen.member.find((other) => other.id === row.principal);
      if (who === undefined || who.status !== 'active' || who.generation !== row.generation) return { refused: 'deactivated' };

      let scopes = stored.scopes;
      let ends = row.expiresAt;
      const writes: Write[] = [];
      const superseded: Row<typeof credentials>[] = [];
      if (code !== undefined) {
        // The redirect it was sent to, exactly, as 0.14.7 held it, and the verifier only the client that asked holds.
        if (stored.redirectUri !== code.redirectUri) return { refused: 'wrong_redirect' };
        if (proof !== row.challenge) return { refused: 'wrong_verifier' };
        ends = new Date(at + code.minutes * 60_000);
        writes.push(amended(credentials, row, { tokenHash: Buffer.from(tokens.refresh, 'hex'), challenge: null, expiresAt: ends }));
        // A step-up: the client's earlier connections that this one grants all of and more end now, as the consent page said.
        for (const other of seen.others) {
          const theirs = mcpClientOf(other.client);
          if (other.id === row.id || !isConnection(other) || other.challenge !== null || other.expiresAt.getTime() <= at || theirs?.id !== stored.id || !supersedes(scopes, theirs.scopes)) continue;
          superseded.push(other);
          writes.push(amended(credentials, other, { revokedAt: now, revokedBy: row.principal }));
        }
      } else {
        // A refresh may narrow what the access token holds, never widen it.
        if (narrowed !== null && narrowed!.some((scope) => !stored.scopes.includes(scope))) return { refused: 'invalid_scope' };
        scopes = narrowed ?? stored.scopes;
        writes.push(amended(credentials, row, { tokenHash: Buffer.from(tokens.refresh, 'hex'), previousTokenHash: Buffer.from(held, 'hex') }));
      }
      const expiresAt = new Date(Math.min(at + ACCESS_TOKEN_MINUTES * 60_000, ends.getTime()));
      writes.push(put(credentials, mcpRow({
        id: access, tokenHash: Buffer.from(tokens.access, 'hex'), generation: row.generation, principal: row.principal, label: row.label, createdAt: now, createdBy: row.principal,
        codeHash: null, expiresAt, ancestors: JSON.stringify([row.id]), client: JSON.stringify({ ...(JSON.parse(row.client!) as object), scopes: scopeString(scopes) }), challenge: null,
      })));
      return {
        writes,
        // Redeemed while it is good, the write's own time included: a code within its minute, a refresh within its connection's life.
        until: row.expiresAt.getTime() - WRITE_MS,
        entry: {
          // An access token's coming ages out, as a session's (D231); a connection ended is kept.
          kept: superseded.length > 0,
          action: 'mcp.token', actor: row.principal, credential: row.id, request: from.request, ip: from.ip,
          objects: [`principal:${row.principal}`, `credential:${row.id}`, `credential:${access}`, ...superseded.map((other) => `credential:${other.id}`)],
          detail: { connection: row.id, ...logged(stored), grant, credential: access, scopes: scopeString(scopes), ...(superseded.length > 0 ? { superseded: superseded.map((other) => other.id) } : {}) },
        },
        answer: { ended: false, principal: row.principal, connection: row.id, credential: access, expiresAt: expiresAt.toISOString(), scopes },
      };
    },
  };
}

/**
 * A client gives back a token it holds (`McpRevoke`, RFC 7009): its
 * connection's row written ended, one write, and every access token under
 * it ends with it, by that row alone. The token is the connection's refresh
 * token, its own token once its code is redeemed, or one of its access
 * tokens, found with the connection its `ancestors` names. Kept, as every
 * connection's end is.
 *
 * Its decision rests on the row the token finds and its connection's:
 * either written behind the vault refuses it, `tampered`.
 */
function mcpRevoke(input: Asked<'mcp.revoke'>): Operation<Parts, Answers['mcp.revoke']> {
  const from = traced(input);
  const { token, client } = input;
  if (!text(token) || !HASH.test(token) || !(client === null || (text(client) && client !== ''))) {
    throw new TypeError("a client gives back a token by its SHA-256, with its client's id or none");
  }
  const hash = sql`decode(${token}, 'hex')`;
  const read = {
    // By the unique index on its hash; and for an access token, the connection above it, by its id.
    presented: part(credentials, sql`${credentials.tokenHash} = ${hash}`),
    connection: part(credentials, sql`${credentials.id} = (SELECT (c.ancestors::jsonb ->> 0)::uuid FROM credentials c WHERE c.token_hash = ${hash} AND c.kind = 'mcp' AND c.ancestors ~ '^[[]"${ID}"[]]$')`),
    instance: instancePart(),
  };
  return {
    read,
    decide(seen: Seen<typeof read>, at: number, unsealed: Unsealed<typeof read>) {
      const before = adopted(seen.instance, unsealed.instance);
      if (before !== undefined) return before;
      if (unsealed.presented + unsealed.connection > 0) return { refused: 'tampered' };
      const live = (row: Row<typeof credentials>) => row.kind === 'mcp' && row.revokedAt === null && row.expiresAt.getTime() > at;
      const [shown] = seen.presented;
      // Its refresh token, once its code is redeemed; or an access token that stands, of the connection's person.
      const row = shown === undefined || !live(shown) ? undefined
        : shown.ancestors === null ? shown
          : seen.connection.find((above) => isConnection(above) && above.principal === shown.principal);
      const stored = row && mcpClientOf(row.client);
      if (row === undefined || stored === undefined || !live(row) || row.challenge !== null || (client !== null && client !== stored.id)) return { refused: 'unknown_grant' };
      return {
        writes: [amended(credentials, row, { revokedAt: new Date(at), revokedBy: row.principal })],
        entry: {
          kept: true,
          action: 'mcp.disconnect', actor: row.principal, credential: shown!.id, request: from.request, ip: from.ip,
          objects: [`principal:${row.principal}`, `credential:${row.id}`, ...(shown!.id === row.id ? [] : [`credential:${shown!.id}`])],
          detail: { connection: row.id, ...logged(stored), reason: 'revoked' },
        },
        answer: { connection: row.id },
      };
    },
  };
}

/**
 * Anyone registers a client (`OauthRegister`, RFC 7591): one row written.
 * What bounds it: the app's limiter, per source and in total, before it
 * asks; then the table's ceiling, `MAX_CLIENTS` rows, which the read finds
 * by the last row it may hold, in the order of its key. Found, the table is
 * full and the registration refused, `full`. The write reads that row
 * again under the change lock, as every row a decision read, so two
 * registrations racing for the last place do not both have it: the second
 * finds a row where there was none, and starts over. The upkeep deletes
 * a registration no connection names a week after it was made
 * (upkeep.ts), which makes room again. Its entry ages out: a stranger does
 * not grow what the log keeps for good.
 */
function oauthRegister(input: Asked<'oauth.register'>): Operation<Parts, Answers['oauth.register']> {
  const from = traced(input);
  const { name } = input;
  const uris = Array.isArray(input.redirectUris) ? [...input.redirectUris] : undefined;
  if (!named(name) || uris === undefined || uris.length === 0 || uris.length > MOST_REDIRECTS || !uris.every(redirect) || new Set(uris).size !== uris.length) {
    throw new TypeError(`a client registers with a name of ${MOST_NAME} characters at most, and 1 to ${MOST_REDIRECTS} redirects, each HTTPS or HTTP on loopback, each once`);
  }
  // Drawn here: a decision draws nothing.
  const id = randomUUID();
  const read = {
    last: part(oauthClients, sql`${oauthClients.id} = (SELECT o.id FROM oauth_clients o ORDER BY o.id OFFSET ${MAX_CLIENTS - 1} LIMIT 1)`),
    instance: instancePart(),
  };
  return {
    read,
    decide(seen: Seen<typeof read>, at: number, unsealed: Unsealed<typeof read>) {
      const before = adopted(seen.instance, unsealed.instance);
      if (before !== undefined) return before;
      // A row is a row, the vault's or not: the ceiling is on what the table holds.
      if (seen.last.length + unsealed.last > 0) return { refused: 'full' };
      const now = new Date(at);
      return {
        writes: [put(oauthClients, { id, name, redirectUris: JSON.stringify(uris), createdAt: now, createdIp: from.ip, revokedAt: null })],
        entry: {
          kept: false,
          action: 'oauth.register', actor: null, credential: null, request: from.request, ip: from.ip,
          objects: [`oauth_client:${id}`],
          // Its id and how many redirects; its name and its redirects only its row keeps, as they are a stranger's text.
          detail: { client: id, redirects: uris.length },
        },
        answer: { client: id, createdAt: now.toISOString() },
      };
    },
  };
}

/** The changes of MCP connections and OAuth clients (docs/design/0.16.md, "MCP connections"). */
export const mcpOperations: Operations<McpChanges> = {
  'mcp.connect': mcpConnect,
  'mcp.token': mcpToken,
  'mcp.revoke': mcpRevoke,
  'oauth.register': oauthRegister,
};
