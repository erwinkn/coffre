/**
 * What MCP clients may be, and do: the scopes a person grants one, and the
 * rules its identity and redirects must pass (docs/design/mcp.md, sections
 * 4 and 5). Plain functions over strings, for the server and the consent
 * page alike.
 */

/** In the order the consent page lists them; `read` is always granted. */
export const MCP_SCOPES = ['read', 'write', 'reveal', 'manage-access'] as const;

export type McpScope = (typeof MCP_SCOPES)[number];

export const MCP_SCOPE_INFO: Record<McpScope, { label: string; description: string }> = {
  read: {
    label: 'Read',
    description: 'Projects, environments, key names, history, access and the audit log. Never a value.',
  },
  write: {
    label: 'Write',
    description: 'Set, generate, rename, archive and restore secrets; create projects and environments. Each change waits for your approval on coffre.',
  },
  reveal: {
    label: 'Reveal values',
    description: 'Secret values, sent to the app.',
  },
  'manage-access': {
    label: 'Manage access',
    description: 'Grants, members, service tokens and trusted workloads. Each change waits for your approval on coffre.',
  },
};

/** How long a code waits for its client: long enough for a redirect, and no longer. */
export const CODE_SECONDS = 60;
/** An hour: what a leaked access token is good for, at most, unless its connection ends sooner. */
export const ACCESS_TOKEN_MINUTES = 60;
/** Connections a person may hold at once, codes waiting included, before Connected apps has to lose one. */
export const MAX_CONNECTIONS = 20;
/** Registered clients the instance keeps at most: anyone may register one, so the table has a ceiling. */
export const MAX_CLIENTS = 10_000;
/** How long an approval waits for its person: a change an MCP client asks for that nobody decides by then expired. */
export const APPROVAL_SECONDS = 5 * 60;
/** Approvals a connection holds waiting at once: no flood of prompts, and no more than this many entries an expiry. */
export const MAX_PENDING = 5;
/** The longest a call's arguments are, as canonical JSON, that an approval keeps: a few names, a note, a scope of some places. */
export const MAX_ASK_ARGUMENTS = 4096;
/** The tools whose Approve changes nothing but shows the person a value (`mcp.decide`): every other is approved by its change. */
export const MCP_SHOWS: readonly string[] = ['show_secret_value'];

/** What OAuth's `offline_access` asks for, a refresh token, every connection has: accepted and dropped. */
const IGNORED_SCOPES = new Set(['offline_access']);

export function isMcpScope(value: string): value is McpScope {
  return (MCP_SCOPES as readonly string[]).includes(value);
}

/**
 * The scopes a space-separated `scope` asks for, in catalogue order, with
 * `read` always among them; and the ones coffre does not know, which the
 * caller refuses as `invalid_scope`.
 */
export function parseScopes(value: string | null | undefined): { scopes: McpScope[]; unknown: string[] } {
  const asked = new Set((value ?? '').split(' ').filter((scope) => scope !== '' && !IGNORED_SCOPES.has(scope)));
  const unknown = [...asked].filter((scope) => !isMcpScope(scope));
  return { scopes: MCP_SCOPES.filter((scope) => scope === 'read' || asked.has(scope)), unknown };
}

/** Scopes as one string, in catalogue order: how a connection stores them and a token answer says them. */
export function scopeString(scopes: Iterable<McpScope>): string {
  const held = new Set(scopes);
  return MCP_SCOPES.filter((scope) => held.has(scope)).join(' ');
}

/**
 * A person's choice at consent: what they ticked, whatever the client asked
 * for, and never without `read`. What a client asks for only decides what
 * starts ticked: clients ask for what the resource metadata names, `read`,
 * and not every one asks for more later (docs/design/mcp.md, section 5).
 */
export function grantedScopes(chosen: readonly string[]): McpScope[] {
  const picked = new Set(chosen);
  return MCP_SCOPES.filter((scope) => scope === 'read' || picked.has(scope));
}

/**
 * Whether a connection granted `granted` supersedes an earlier one of the
 * same client that holds `held`: it grants all of that and more, as a
 * step-up does. The earlier one then ends, once the new one's code is
 * redeemed; one with the same scopes, a second laptop say, stays.
 */
export function supersedes(granted: readonly McpScope[], held: readonly McpScope[]): boolean {
  return held.every((scope) => granted.includes(scope)) && granted.some((scope) => !held.includes(scope));
}

// --- redirect URIs ----------------------------------------------------------

/** A client's redirect, refused: the message says why, for the consent page and the registration answer. */
export class ClientInvalid extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ClientInvalid';
  }
}

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '[::1]', 'localhost']);

export type RedirectKind = 'https' | 'loopback';

/**
 * Where a redirect may go: HTTPS anywhere, or plain HTTP on loopback, which
 * a native client such as Claude Code listens on (RFC 8252). No custom
 * scheme, no fragment, no user or password.
 */
export function redirectKind(value: string): RedirectKind {
  // The URL parser drops a trailing NUL, but the vault keeps the text as given, and Postgres stores no NUL nor half of a surrogate pair.
  if (/[\0\p{Cs}]/u.test(value)) throw new ClientInvalid('a redirect holds a NUL or half of a surrogate pair');
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ClientInvalid(`${value} is not a URL`);
  }
  if (url.username !== '' || url.password !== '') throw new ClientInvalid(`${value} carries a user or password`);
  if (url.hash !== '' || value.includes('#')) throw new ClientInvalid(`${value} has a fragment`);
  if (url.protocol === 'https:') return 'https';
  if (url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname)) return 'loopback';
  throw new ClientInvalid(`${value} is neither HTTPS nor HTTP on loopback (127.0.0.1, [::1] or localhost)`);
}

/**
 * Whether a requested redirect is one a client registered. Both are parsed
 * first, so `http://127.0.0.1:33418` and `http://127.0.0.1:33418/` are one
 * URL. A loopback one matches on any port, as RFC 8252 lets a native client
 * bind whichever it can; everything else exactly.
 */
export function redirectMatches(registered: string, requested: string): boolean {
  let a: URL;
  let b: URL;
  try {
    redirectKind(requested);
    a = new URL(registered);
    b = new URL(requested);
  } catch {
    return false;
  }
  if (a.protocol === 'http:' && LOOPBACK_HOSTS.has(a.hostname)) {
    return b.protocol === 'http:' && a.hostname === b.hostname && a.pathname === b.pathname && a.search === b.search;
  }
  return a.href === b.href;
}

/** The redirect's host, as the consent page shows it: `localhost` for every loopback one. */
export function redirectHost(value: string): string {
  const url = new URL(value);
  return redirectKind(value) === 'loopback' ? 'localhost' : url.host;
}

// --- clients ------------------------------------------------------------------

/** What coffre knows of a client, from its metadata document or its registration. */
export type ClientMetadata = {
  /** The document's URL, or the ID a registration was given. */
  clientId: string;
  /** Its own claim: shown, never trusted. */
  name: string;
  /** For a document, its URL's host; for a registration, null: it has none to vouch for it. */
  host: string | null;
  redirectUris: string[];
  registration: 'cimd' | 'dcr';
};

const MAX_REDIRECTS = 10;
const MAX_NAME = 100;
/** The longest client id the vault keeps (`text` in its ops). */
export const MAX_CLIENT_ID = 256;

/**
 * Whether a client_id is one the vault and Postgres keep: 256 characters at
 * most, with no NUL and no half of a surrogate pair. Any other is no
 * client's, and is answered as such before it is read or sent anywhere.
 */
export const clientIdKept = (value: string): boolean => value.length <= MAX_CLIENT_ID && !/[\0\p{Cs}]/u.test(value);

/**
 * Whether `value` is a Client ID Metadata Document's URL: HTTPS, with a
 * path, and nothing a document's address has no use for. On a loopback
 * instance, a loopback one too, for development and conformance.
 */
export function isClientIdUrl(value: string, options: { allowLoopback: boolean }): boolean {
  if (!value.startsWith('https://') && !(options.allowLoopback && value.startsWith('http://'))) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.href !== value || url.pathname === '/' || url.search !== '' || url.hash !== '') return false;
  if (url.username !== '' || url.password !== '' || /\/\.\.?(\/|$)/.test(url.pathname)) return false;
  return url.protocol === 'https:' || LOOPBACK_HOSTS.has(url.hostname);
}

/**
 * A fetched Client ID Metadata Document, checked: it names itself, a name
 * and its redirects, and it is a public client. An HTTPS redirect must be on
 * the document's own host, so the consent page names one host: Claude's
 * `https://claude.ai/api/mcp/auth_callback` is on `claude.ai`, where its
 * document is.
 */
export function clientFromDocument(clientId: string, document: unknown): ClientMetadata {
  if (typeof document !== 'object' || document === null || Array.isArray(document)) {
    throw new ClientInvalid('the client metadata document is not a JSON object');
  }
  const fields = document as Record<string, unknown>;
  if (fields.client_id !== clientId) throw new ClientInvalid('the client metadata document names another client_id than its own URL');
  const method = fields.token_endpoint_auth_method;
  if (method !== undefined && method !== 'none') {
    throw new ClientInvalid(`the client authenticates with ${String(method)}; coffre takes public clients only, with PKCE`);
  }
  const host = new URL(clientId).host;
  const uris = redirectList(fields.redirect_uris);
  for (const uri of uris) {
    if (redirectKind(uri) === 'https' && new URL(uri).host !== host) {
      throw new ClientInvalid(`${uri} is not on ${host}, where the client's metadata document is`);
    }
  }
  return { clientId, name: clientName(fields.client_name, host), host, redirectUris: uris, registration: 'cimd' };
}

/**
 * What a registration may keep of what it asked for (RFC 7591): the
 * redirects coffre accepts, the others left out rather than failing it, as
 * the RFC lets a server replace what was asked. Cursor registers a
 * `cursor://` callback beside its loopback and HTTPS ones; refused whole,
 * it could not connect at all.
 */
export function registrationRedirects(value: unknown): { kept: string[]; dropped: string[] } {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_REDIRECTS || value.some((uri) => typeof uri !== 'string' || uri.length > 400)) {
    throw new ClientInvalid(`redirect_uris must list 1 to ${MAX_REDIRECTS} URLs`);
  }
  const kept: string[] = [];
  const dropped: string[] = [];
  for (const uri of value as string[]) {
    try {
      redirectKind(uri);
      if (!kept.includes(uri)) kept.push(uri);
    } catch {
      dropped.push(uri);
    }
  }
  if (kept.length === 0) throw new ClientInvalid(`none of the redirect_uris is HTTPS or HTTP on loopback: ${dropped.join(', ')}`);
  return { kept, dropped };
}

/** A client's name as shown: its own, or its host when it gives none, cut short. */
export function clientName(value: unknown, fallback: string): string {
  // Control and bidirectional characters could make one name look like another.
  // Half of a surrogate pair goes too: it is no text Postgres stores.
  const own = typeof value === 'string' ? value.replace(/[\p{Cc}\p{Cf}\p{Cs}]/gu, '').trim() : '';
  // Cut on a whole character, and trimmed again: what the vault keeps is the name as shown (`named` in its ops/mcp.ts).
  // A host is cut too: a document's may be 200 characters, and the vault keeps 100.
  return (own === '' ? fallback : own).slice(0, MAX_NAME).replace(/[\uD800-\uDBFF]$/, '').trim();
}

function redirectList(value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_REDIRECTS || value.some((uri) => typeof uri !== 'string')) {
    throw new ClientInvalid(`the client metadata document must list 1 to ${MAX_REDIRECTS} redirect_uris`);
  }
  for (const uri of value as string[]) redirectKind(uri);
  return value as string[];
}
