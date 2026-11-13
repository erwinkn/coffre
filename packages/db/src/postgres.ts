import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { checkServerIdentity, type ConnectionOptions } from 'node:tls';

import postgres, { type Options, type Sql } from './postgres-js/index.ts';

/**
 * A client of coffre's postgres.js (`./postgres-js`): statements (`unsafe`),
 * transactions (`begin`), a connection held (`reserve`), and closing it.
 */
export type PostgresClient = Sql;

/** What a client may be opened with beside its URL. */
export type ClientOptions = Pick<Options, 'max' | 'idle_timeout' | 'connect_timeout' | 'max_lifetime' | 'onnotice' | 'debug' | 'onclose'> & {
  /** The stream to speak Postgres on, made for each connection, rather than a TCP socket: a tunnel's. */
  socket?: Options['socket'];
  /** Postgres's `application_name` for the connection. */
  application_name?: string;
  /** Run-time parameters sent when the connection starts, `statement_timeout` and the like. */
  connection?: Record<string, string | number | boolean>;
};

/**
 * A client for `url`, as coffre opens every one: the driver's defaults (10
 * connections, every statement unnamed, as node-postgres sends them), but
 *
 * - notices dropped rather than logged;
 * - no connection closed for its age (`max_lifetime`), as node-postgres
 *   closed none: a backup's session holds its snapshot while pg_dump reads.
 *
 * The driver reads no array type from `pg_type` (postgres.js's
 * `fetch_types`, a round trip more per connection), and would answer one as
 * its text: Postgres's own are taken as known instead (`ARRAYS`). Arrays and
 * dates go as node-postgres sends them (`asPgSends`).
 */
export function postgresClient(url: string, options: ClientOptions = {}): PostgresClient {
  const { application_name, connection, ...rest } = options;
  const target = postgresOptions(url);
  return asPgSends(arrayTypes(postgres({
    onnotice: () => {},
    max_lifetime: null,
    // The URL's own (its TLS, its sslnegotiation) come after, and the caller's last.
    ...target,
    ...rest,
    connection: {
      ...target.connection,
      ...(application_name === undefined ? {} : { application_name }),
      ...connection,
    },
  })));
}

/** A statement asked of a session that lost its connection, and with it its transaction, its locks and its settings. */
export class SessionLost extends Error {
  constructor() {
    super('the database session was lost: its connection closed, and with it its transaction, locks and settings');
    this.name = 'SessionLost';
  }
}

/** What is asked of a session: each fails once it is lost. */
const ASKED = new Set<PropertyKey>(['unsafe', 'begin', 'reserve']);

/**
 * One connection to `url`, kept as a session, as node-postgres's Client
 * kept one: what a statement sets (SET, BEGIN, a session's advisory lock)
 * holds for every statement after. A client of postgres.js would dial a new
 * connection for the next statement once its own closed, which holds none of
 * it: a migration going on without its lock, a probe meant to be rolled back
 * committed, a backup read outside its snapshot. A session does not: once
 * its connection has closed, by the server, the network or `end`, every
 * statement after fails, `SessionLost`.
 */
export function postgresSession(url: string, options: Omit<ClientOptions, 'max'> = {}): PostgresClient {
  let lost = false;
  // `onclose`, if given, hears the session's connection close.
  const client = postgresClient(url, { ...options, max: 1, onclose: (id) => ((lost = true), options.onclose?.(id)) });
  /** A statement refused: rejected, and still a statement, whose `values()` and `execute()` Drizzle and callers ask for. */
  const refused = () => {
    const answer = Promise.reject(new SessionLost());
    answer.catch(() => {});
    return Object.assign(answer, { values: () => answer, execute: () => answer });
  };
  return new Proxy(client, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (typeof value !== 'function' || !ASKED.has(key)) return value;
      return (...args: unknown[]) => (lost ? refused() : (value as (...args: unknown[]) => unknown).apply(target, args));
    },
  });
}

/**
 * `client`, sending a statement's values as node-postgres sends them: an
 * array as Postgres's text for one (`{"a","b"}`, bytes as `\\x…`), a date
 * as its ISO text and a plain object as its JSON, each for the server to
 * type, with the statement, in one round trip; `undefined` as NULL. Its
 * transactions', savepoints' and reserved connections' alike. The driver
 * would type an array by its first element, the element's type rather than
 * the array's, and so bind `[1, 2]` as one integer and mistype a `bytea[]`;
 * and it would ask the server first how to send an array of text.
 */
function asPgSends<T extends object>(client: T): T {
  return new Proxy(client, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key === 'unsafe') {
        return (text: string, values?: unknown[], ...rest: unknown[]) =>
          (value as (...args: unknown[]) => unknown).call(target, text, Array.isArray(values) ? values.map(sent) : values, ...rest);
      }
      if (key === 'group') {
        return (statements: { query: string; parameters?: unknown[]; arrays?: boolean }[]) =>
          (value as (...args: unknown[]) => unknown).call(target, statements.map((statement) => ({ ...statement, parameters: statement.parameters?.map(sent) })));
      }
      if (key === 'begin' || key === 'savepoint' || key === 'reserve') {
        return (...args: unknown[]) => {
          const work = args.at(-1);
          if (typeof work !== 'function') return (value as (...args: unknown[]) => Promise<object>).apply(target, args).then(asPgSends);
          return (value as (...args: unknown[]) => unknown).apply(target, [...args.slice(0, -1), (tx: object) => work(asPgSends(tx))]);
        };
      }
      return value;
    },
  });
}

/**
 * A value as node-postgres sends it: an array, a date or a plain object (as
 * its JSON) as text, bytes of any view as bytes, `undefined` as NULL. What
 * else there is goes as it is.
 */
function sent(value: unknown): unknown {
  if (value === undefined) return null;
  if (Array.isArray(value)) return arrayText(value);
  if (value instanceof Date) return value.toISOString();
  const bytes = bytesOf(value);
  if (bytes !== null) return bytes;
  return plain(value) ? JSON.stringify(value) : value;
}

/** An object made as `{…}` is: no class of its own. */
function plain(value: unknown): value is object {
  if (typeof value !== 'object' || value === null) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** Bytes, from any view of them or their buffer, as a Uint8Array; null for anything else. */
function bytesOf(value: unknown): Uint8Array | null {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  if (value instanceof ArrayBuffer) return Buffer.from(value);
  return null;
}

/** An array as Postgres's text for one, as node-postgres writes it: elements quoted, bytes as hex, nulls as NULL. */
function arrayText(values: unknown[]): string {
  return `{${values.map((value) => {
    if (value === null || value === undefined) return 'NULL';
    if (Array.isArray(value)) return arrayText(value);
    const bytes = bytesOf(value);
    if (bytes !== null) return `\\\\x${Buffer.from(bytes).toString('hex')}`;
    const text = value instanceof Date ? value.toISOString() : typeof value === 'object' ? JSON.stringify(value) : String(value);
    return `"${text.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
  }).join(',')}}`;
}

/**
 * Postgres's built-in types and their arrays, element and array oid, as
 * `fetch_types` would read them from `pg_type` at each connection: those a
 * hand-written statement may send or answer, as node-postgres knew them. An
 * array of any other type (ranges, geometry, `macaddr8`, a type of one's
 * own) is answered as Postgres's text for it: add it here to read it.
 */
const ARRAYS = [
  [16, 1000], [17, 1001], [18, 1002], [19, 1003], [20, 1016], [21, 1005], [23, 1007], [25, 1009], [26, 1028],
  [114, 199], [650, 651], [700, 1021], [701, 1022], [829, 1040], [869, 1041], [1042, 1014], [1043, 1015],
  [1082, 1182], [1083, 1183], [1114, 1115], [1184, 1185], [1186, 1187], [1266, 1270], [1700, 1231], [2950, 2951],
  [3802, 3807],
] as const;

/** `client`, which reads Postgres's arrays as node-postgres reads them, each element by its type's parser. */
function arrayTypes(client: PostgresClient): PostgresClient {
  const parsers = client.options.parsers;
  for (const [element, array] of ARRAYS) {
    const parse = parsers[element];
    parsers[array] = (text: string) => arrayOf(text, parse);
  }
  return client;
}

/**
 * Postgres's text for an array, `{a,"b,c",NULL,{1,2}}`, as its values: a
 * quoted element is text (`"NULL"` included), an unquoted NULL is null, and
 * explicit bounds (`[0:1]={…}`) are read past.
 */
export function arrayOf(text: string, parse?: (text: string) => unknown): unknown[] {
  let at = text.startsWith('[') ? text.indexOf('=') + 1 : 0;
  const list = (): unknown[] => {
    const values: unknown[] = [];
    at += 1;
    if (text[at] === '}') {
      at += 1;
      return values;
    }
    for (;;) {
      if (text[at] === '{') {
        values.push(list());
      } else if (text[at] === '"') {
        let element = '';
        for (at += 1; text[at] !== '"'; at += 1) element += text[text[at] === '\\' ? ++at : at];
        at += 1;
        values.push(parse ? parse(element) : element);
      } else {
        const start = at;
        while (text[at] !== ',' && text[at] !== '}') at += 1;
        const element = text.slice(start, at);
        values.push(element === 'NULL' ? null : parse ? parse(element) : element);
      }
      if (text[at++] === '}') return values;
    }
  };
  return list();
}

/**
 * The Postgres types Drizzle maps from their text itself: dates and times,
 * and arrays of them and of numerics, as Drizzle's own drivers set them up,
 * postgres.js's (`construct`) and node-postgres's alike.
 */
const TEXT_TYPES = [1184, 1082, 1083, 1114, 1182, 1185, 1115, 1231];

/**
 * `client`, set up as Drizzle's own postgres.js driver sets one up: dates
 * and times come as Postgres's text, which each column maps, and JSON goes
 * as Drizzle writes it. For every statement of the client, `unsafe`'s
 * included: a client made a database (`createDatabase`) answers a raw
 * `now()` as text, not a Date.
 */
export function textTypes(client: PostgresClient): PostgresClient {
  const identity = (value: unknown) => value;
  for (const type of TEXT_TYPES) {
    client.options.parsers[type] = identity;
    client.options.serializers[type] = identity;
  }
  client.options.serializers[114] = identity;
  client.options.serializers[3802] = identity;
  return client;
}

/**
 * The connection `url` names, as node-postgres and its pg-connection-string
 * read one. The driver reads no URL: it is given the parts. (Upstream
 * postgres.js read URLs otherwise: it sent every query parameter it did not
 * know to the server as a setting, which refused the connection over one it
 * did not know either, `sslrootcert` or `uselibpqcompat`; its
 * `sslmode=require` skipped the certificate check, where coffre's URLs, as
 * pg reads them, verify; and it checked an IP address against `localhost`.)
 *
 * TLS is:
 *
 *   no sslmode, sslmode=disable               none
 *   sslmode=prefer, require, verify-ca,       the certificate chain and the host verified
 *     verify-full; ssl=true or 1
 *   sslmode=no-verify                         TLS, nothing verified
 *   uselibpqcompat=true                       libpq's modes: prefer and require verify nothing
 *                                             (require with a sslrootcert, the chain), verify-ca
 *                                             the chain, verify-full the chain and the host
 *   sslrootcert=system                        Node's trusted CAs; only with verify-full or no sslmode
 *   sslrootcert, sslcert, sslkey (files)      read from disk, as pg does
 *
 * The host is verified against the URL's own, an IP address included.
 */
export function postgresOptions(url: string): Partial<Options> & { connection: Record<string, string> } {
  // A URL may name no host, its socket's directory in the query (`postgresql://u@/db?host=/var/run/postgresql`), which a
  // URL parser refuses: as pg-connection-string does, it is read with a host in its place, and the host is the query's.
  const hostless = /^[a-z]+:\/\/([^/?#@]*@)?\//i.test(url);
  // Several hosts, which libpq tries in turn: node-postgres read them as one name, and so does this, but says so.
  if (/^[a-z]+:\/\/([^/?#@]*@)?[^/?#]*,/i.test(url)) throw new Error('a Postgres URL names one host: several, as libpq takes them, are not supported');
  let read: { query: Map<string, string>; host: string; port: number; user: string; pass: string; database: string | undefined };
  try {
    const parsed = new URL(hostless ? url.replace(/^([a-z]+:\/\/([^/?#@]*@)?)/i, '$1localhost') : url);
    // A parameter given empty is no parameter, as pg-connection-string reads one.
    const query = new Map([...parsed.searchParams].filter(([, value]) => value !== ''));
    const port = query.get('port') ?? (parsed.port || '5432');
    if (!/^\d{1,5}$/.test(port) || Number(port) === 0 || Number(port) > 65535) throw new Error('no port');
    read = {
      query,
      host: query.get('host') ?? decodeURIComponent(parsed.hostname.replace(/^\[(.*)\]$/, '$1')),
      port: Number(port),
      // As pg-connection-string reads them, a `user` or `password` parameter in the query wins.
      user: query.get('user') ?? decodeURIComponent(parsed.username),
      pass: query.get('password') ?? decodeURIComponent(parsed.password),
      database: decodeURIComponent(parsed.pathname.slice(1)) || undefined,
    };
  } catch {
    // A parse error, a malformed escape or port included, must not print the URL's password.
    throw new Error('invalid Postgres URL');
  }
  const { query, host, port, user, pass, database } = read;
  // libpq would take the operating system's user; coffre reads nothing of where it runs, so the URL names one.
  if (user === '') throw new Error('a Postgres URL names its user: postgresql://<user>@<host>/<database>');
  if (host.includes(',')) throw new Error('a Postgres URL names one host: several, as libpq takes them, are not supported');
  // node-postgres cancelled a statement past it, from the client: refused rather than ignored, the server's bound named.
  if (query.has('query_timeout')) throw new Error("a Postgres URL's query_timeout is not supported: statement_timeout bounds a statement in the server");
  // libpq's bound on opening a connection, in seconds, as the driver takes it: 0 for none.
  const connectTimeout = query.get('connect_timeout');
  if (connectTimeout !== undefined && !/^\d+$/.test(connectTimeout)) throw new Error('invalid Postgres URL');
  // What libpq refuses, or the driver cannot do, is refused rather than read as something else.
  const mode = query.get('sslmode');
  if (mode !== undefined && !['disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full', 'no-verify'].includes(mode)) {
    throw new Error(`a Postgres URL's sslmode is one of libpq's, not ${mode}`);
  }
  if (!['postgres', 'direct', undefined].includes(query.get('sslnegotiation'))) throw new Error("a Postgres URL's sslnegotiation is postgres or direct");
  if (query.get('channel_binding') === 'require') throw new Error("a Postgres URL's channel_binding=require is not supported: SCRAM goes without channel binding");
  // What node-postgres sent the server from the query, as it starts the connection: the rest it read itself, or not.
  const connection: Record<string, string> = {};
  for (const name of ['application_name', 'fallback_application_name', 'options', 'statement_timeout', 'lock_timeout', 'idle_in_transaction_session_timeout'] as const) {
    const value = query.get(name);
    if (value !== undefined) connection[name] = value;
  }
  const sslnegotiation = query.get('sslnegotiation') === 'direct' ? 'direct' : undefined;
  return {
    ...(host.startsWith('/') ? { path: `${host}/.s.PGSQL.${port}` } : { host }),
    port,
    user,
    pass,
    database,
    ssl: tlsFor(query, host, sslnegotiation !== undefined),
    ...(sslnegotiation === undefined ? {} : { sslnegotiation }),
    ...(connectTimeout === undefined ? {} : { connect_timeout: Number(connectTimeout) }),
    connection,
  } as Partial<Options> & { connection: Record<string, string> };
}

function tlsFor(query: Map<string, string>, host: string, direct: boolean): false | ConnectionOptions {
  const mode = query.get('sslmode');
  let rootcert = query.get('sslrootcert');
  if (rootcert === 'system') {
    if (mode !== undefined && mode !== 'verify-full') throw new Error('sslrootcert=system requires sslmode=verify-full');
    if (!host || host.startsWith('/')) throw new Error('sslrootcert=system requires a Postgres hostname');
    // Node's default trusted roots: no CA of our own.
    rootcert = undefined;
  }
  const files = { cert: query.get('sslcert'), key: query.get('sslkey'), ca: rootcert };
  const flag = query.get('ssl');
  const wanted = mode !== undefined || Object.values(files).some((file) => file !== undefined) || query.get('sslrootcert') === 'system'
    || flag === 'true' || flag === '1' || direct;
  if (!wanted || mode === 'disable') return false;

  const tls: ConnectionOptions = {};
  for (const [name, file] of Object.entries(files)) {
    if (file !== undefined) tls[name as keyof typeof files] = readFileSync(file).toString();
  }
  // What opens an encrypted sslkey.
  const passphrase = query.get('sslpassword');
  if (passphrase !== undefined) tls.passphrase = passphrase;
  const libpq = query.get('uselibpqcompat') === 'true';
  const verify = !libpq
    ? mode === 'no-verify' ? 'none' : 'full'
    : mode === 'prefer' || (mode === 'require' && tls.ca === undefined) ? 'none' : mode === 'require' || mode === 'verify-ca' ? 'chain' : 'full';
  if (libpq && mode === 'verify-ca' && tls.ca === undefined) {
    throw new Error('sslmode=verify-ca requires a CA in sslrootcert: with a public CA, it lets anyone with a certificate from it pass as the database. Use sslmode=verify-full');
  }
  if (verify === 'none') return { ...tls, rejectUnauthorized: false };
  return {
    ...tls,
    rejectUnauthorized: true,
    // The driver names an IP address to TLS as nothing, which Node checks as localhost: the URL's host is checked instead.
    checkServerIdentity: verify === 'chain' ? () => undefined : (_hostname, certificate) => checkServerIdentity(host, certificate),
    ...(isIP(host) === 0 ? { servername: host } : {}),
  };
}

/** `name` as a Postgres identifier, quoted, as node-postgres's `escapeIdentifier` writes one. */
export function quoteIdentifier(name: string): string {
  return `"${name.replaceAll('"', '""')}"`;
}

/** `text` as a Postgres string literal, as node-postgres's `escapeLiteral` writes one: `E'…'` when it holds a backslash. */
export function quoteLiteral(text: string): string {
  const quoted = `'${text.replaceAll("'", "''").replaceAll('\\', '\\\\')}'`;
  return text.includes('\\') ? ` E${quoted}` : quoted;
}
