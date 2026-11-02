import { CREDENTIAL_NAME } from './identity/workloads.ts';
import { alike, FIELD_NAME, PARAMETER_NAME, readPattern } from './proxy-match.ts';

/**
 * Proxy definitions written in the UI, per environment (0.16, T186;
 * docs/design/proxy-ui.md). The shapes are the Proxy tab's (#421): a route
 * (`/use/<name>`), a signer, a verifier or a database tunnel, each a plain
 * JSON object the vault seals in the environment's `proxy` object. What
 * code defines (`credentialProxy({ … })`) is not here: a UI item whose name
 * code also defines is ignored (R66).
 *
 * The vault checks every definition at save (`proxyDefinitionProblem`) and keeps
 * it in its canonical form (`canonicalDefinition`), with the keys its
 * templates name (`definitionKeys`), so that live uses and the log's replay
 * read one key list (R53). The app checks what needs code: an egress or a
 * network it declares.
 */

/** How a route's values reach its upstream: each field a template, `{KEY}` the environment's value. */
export type ProxyInject =
  | { kind: 'header' | 'query' | 'form' | 'json'; name: string; template: string }
  | { kind: 'basic'; user: string; password: string }
  | { kind: 'sigv4'; accessKeyId: string; secretAccessKey: string; sessionToken: string | null; region: string; service: string };

/** Which requests a route takes: these methods (none: any), on this path. A plain path is a prefix by segments; `*` stands for one segment, `**`, last, for the rest. */
export type ProxyAllow = { methods: ProxyMethod[]; path: string };

/** How often a workload may use an item, a minute and a day: a whole number of at least 1, or no limit there. */
export type ProxyLimit = { perMinute: number | null; perDay: number | null };

/** What the app holds in place of the key: the handle as it is (null), one with the key's prefix, or a JWT carrying some of its claims. */
export type ProxyPlaceholder = null | { kind: 'prefix'; prefix: string } | { kind: 'jwt'; claims: string[] };

export type ProxyEncoding = 'hex' | 'base64' | 'base64url';

export type ProxyHmac = { key: string; encoding: ProxyEncoding; prefix: string; maxBytes: number | null };

export type ProxyRoute = {
  kind: 'route';
  name: string;
  upstream: string;
  inject: ProxyInject[];
  /** Null: any method on any path, as with no allow list in code; `[]`: no request at all (403). */
  allow: ProxyAllow[] | null;
  limit: ProxyLimit;
  placeholder: ProxyPlaceholder;
  /** The egress, by the name code declares it under, its requests leave through; null: direct. */
  egress: string | null;
};

export type ProxySigner = { kind: 'signer'; name: string; signer: { kind: 'private-key'; key: string } | ({ kind: 'hmac' } & ProxyHmac); limit: ProxyLimit };
export type ProxyVerifier = { kind: 'verifier'; name: string; hmac: ProxyHmac; limit: ProxyLimit };
export type ProxyTunnel = { kind: 'tunnel'; name: string; key: string; hosts: string[]; network: string | null };

export type ProxyDefinition = ProxyRoute | ProxySigner | ProxyVerifier | ProxyTunnel;
export type ProxyKind = ProxyDefinition['kind'];

/** The methods an allow entry names, a fixed list. */
export const PROXY_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const;
export type ProxyMethod = (typeof PROXY_METHODS)[number];

/** The most items one environment's object holds: its index stays under 17 KB, which every use of it carries. */
export const MAX_PROXY_ITEMS = 256;

/** The most bytes one definition takes, as JSON. */
export const MAX_DEFINITION_BYTES = 8192;

/**
 * A key a template names: `{OPENAI_API_KEY}`. The proxy's own reading of
 * templates (`TEMPLATE_KEY` in credential-proxy.ts), here shared with the
 * vault's save, which stores what it reads (section 3).
 */
export const TEMPLATE_KEY = /\{([A-Za-z_][A-Za-z0-9_]{0,127})\}/g;

/** A key's name, as a signer, a verifier or a tunnel names it. */
export const KEY_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

/**
 * The keys a definition sends, each once, sorted: the keys its templates
 * name, or the one key a signer, a verifier or a tunnel names. What the
 * vault stores beside each item, and clears at save.
 */
export function definitionKeys(definition: ProxyDefinition): string[] {
  const names = (() => {
    switch (definition.kind) {
      case 'route': return definition.inject.flatMap(templatesOf).flatMap(keysIn);
      case 'signer': return [definition.signer.key];
      case 'verifier': return [definition.hmac.key];
      case 'tunnel': return [definition.key];
    }
  })();
  return [...new Set(names)].sort();
}

function keysIn(template: string): string[] {
  return [...template.matchAll(TEMPLATE_KEY)].map((match) => match[1]!);
}

function templatesOf(rule: ProxyInject): string[] {
  switch (rule.kind) {
    case 'basic': return [rule.user, rule.password];
    case 'sigv4': return [rule.accessKeyId, rule.secretAccessKey, ...(rule.sessionToken === null ? [] : [rule.sessionToken])];
    default: return [rule.template];
  }
}

/** Why `value` is no definition the vault keeps, or null. */
export function proxyDefinitionProblem(value: unknown, options: { insecureUpstreams?: boolean } = {}): string | null {
  try {
    canonicalDefinition(value, options);
    return null;
  } catch (error) {
    if (error instanceof DefinitionProblem) return error.message;
    throw error;
  }
}

class DefinitionProblem extends Error {}

function problem(message: string): never {
  throw new DefinitionProblem(message);
}

/**
 * `value` as the vault keeps it: every field there, in one shape (a header's
 * name in lowercase, an absent limit null), nothing else. Throws on the
 * first problem, by its words; `proxyDefinitionProblem` says them.
 *
 *   { kind: 'route', name: 'openai', upstream: 'https://api.openai.com/v1',
 *     inject: [{ kind: 'header', name: 'Authorization', template: 'Bearer {OPENAI_API_KEY}' }],
 *     allow: [{ methods: ['POST'], path: '/chat/completions' }],
 *     limit: { perMinute: null, perDay: null }, placeholder: null, egress: null }
 */
export function canonicalDefinition(value: unknown, options: { insecureUpstreams?: boolean } = {}): ProxyDefinition {
  const item = record(value, 'a definition');
  const name = item.name;
  if (typeof name !== 'string' || !CREDENTIAL_NAME.test(name)) problem('a name is a lowercase letter, then up to 31 lowercase letters, digits or dashes');
  const at = (what: string) => `${name}: ${what}`;
  let definition: ProxyDefinition;
  switch (item.kind) {
    case 'route': {
      only(item, ['kind', 'name', 'upstream', 'inject', 'allow', 'limit', 'placeholder', 'egress'], name);
      const inject = list(item.inject, at('inject'), 1, 8).map((rule, i) => injectRule(rule, at(`inject[${i}]`)));
      injectOrder(inject, name);
      const placeholder = placeholderOf(item.placeholder, name);
      if (placeholder !== null && !inject.some((rule) => rule.kind !== 'basic' && rule.kind !== 'sigv4' && keysIn(rule.template).length === 1)) {
        problem(at('a placeholder shapes a header, query, form or JSON rule that sends one key, and this route has none'));
      }
      definition = {
        kind: 'route',
        name,
        upstream: upstreamOf(item.upstream, name, options.insecureUpstreams === true),
        inject,
        allow: allowOf(item.allow, name),
        limit: limitOf(item.limit, name),
        placeholder,
        egress: transportName(item.egress, at('egress')),
      };
      break;
    }
    case 'signer': {
      only(item, ['kind', 'name', 'signer', 'limit'], name);
      const signer = record(item.signer, at('signer'));
      if (signer.kind === 'private-key') {
        only(signer, ['kind', 'key'], at('signer'));
        definition = { kind: 'signer', name, signer: { kind: 'private-key', key: keyName(signer.key, at('signer.key')) }, limit: limitOf(item.limit, name) };
      } else if (signer.kind === 'hmac') {
        definition = { kind: 'signer', name, signer: { kind: 'hmac', ...hmacOf(signer, at('signer'), ['kind']) }, limit: limitOf(item.limit, name) };
      } else {
        problem(at("a signer signs with a private key ('private-key') or an HMAC ('hmac')"));
      }
      break;
    }
    case 'verifier':
      only(item, ['kind', 'name', 'hmac', 'limit'], name);
      definition = { kind: 'verifier', name, hmac: hmacOf(record(item.hmac, at('hmac')), at('hmac')), limit: limitOf(item.limit, name) };
      break;
    case 'tunnel': {
      only(item, ['kind', 'name', 'key', 'hosts', 'network'], name);
      const network = transportName(item.network, at('network'));
      const hosts = list(item.hosts, at('hosts'), 1, 16).map((host, i) => hostOf(host, at(`hosts[${i}]`), network !== null || options.insecureUpstreams === true));
      if (new Set(hosts).size !== hosts.length) problem(at('each host once'));
      definition = { kind: 'tunnel', name, key: keyName(item.key, at('key')), hosts, network };
      break;
    }
    default:
      problem(at("a definition is a 'route', a 'signer', a 'verifier' or a 'tunnel'"));
  }
  if (new TextEncoder().encode(JSON.stringify(definition)).length > MAX_DEFINITION_BYTES) problem(at(`a definition takes at most ${MAX_DEFINITION_BYTES} bytes`));
  return definition;
}

function record(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) problem(`${what} is an object`);
  return value as Record<string, unknown>;
}

function only(value: Record<string, unknown>, fields: readonly string[], what: string): void {
  const extra = Object.keys(value).find((field) => !fields.includes(field));
  if (extra !== undefined) problem(`${what}: no field ${JSON.stringify(extra)}`);
}

function list(value: unknown, what: string, least: number, most: number): unknown[] {
  if (!Array.isArray(value) || value.length < least || value.length > most) problem(`${what} is a list of ${least === most ? least : `${least} to ${most}`}`);
  return value;
}

function text(value: unknown, what: string, most: number, least = 1): string {
  // No control characters: a header's or a field's value cut at one is another.
  if (typeof value !== 'string' || value.length < least || value.length > most || /[\u0000-\u001f\u007f]/.test(value)) problem(`${what} is text of ${least} to ${most} characters, with no control characters`);
  return value;
}

function keyName(value: unknown, what: string): string {
  if (typeof value !== 'string' || !KEY_NAME.test(value)) problem(`${what} names a key: letters, digits and underscores, not starting with a digit`);
  return value;
}

/** A template that names at least one key, as code's startup check requires: no rule sends nothing. */
function template(value: unknown, what: string): string {
  const written = text(value, what, 1024);
  if (keysIn(written).length === 0) problem(`${what} names no key: write it as {KEY}`);
  return written;
}

const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/;

function injectRule(value: unknown, what: string): ProxyInject {
  const rule = record(value, what);
  switch (rule.kind) {
    case 'header': {
      only(rule, ['kind', 'name', 'template'], what);
      if (typeof rule.name !== 'string' || !HEADER_NAME.test(rule.name)) problem(`${what}: a header's name is a token of 1 to 64 characters`);
      return { kind: 'header', name: rule.name.toLowerCase(), template: template(rule.template, `${what}.template`) };
    }
    case 'query':
      only(rule, ['kind', 'name', 'template'], what);
      if (!PARAMETER_NAME.test(text(rule.name, `${what}.name`, 128))) problem(`${what}: a parameter's name is a token of 1 to 128 characters`);
      return { kind: 'query', name: rule.name as string, template: template(rule.template, `${what}.template`) };
    case 'form': case 'json':
      only(rule, ['kind', 'name', 'template'], what);
      // As the proxy's own check (`checkRule`): a field at the top of the body, named as every parser reads it.
      if (typeof rule.name !== 'string' || !FIELD_NAME.test(rule.name)) problem(`${what}: a field's name is letters, digits and _.-, a letter or digit among them, 1 to 128`);
      return { kind: rule.kind, name: rule.name, template: template(rule.template, `${what}.template`) };
    case 'basic': {
      only(rule, ['kind', 'user', 'password'], what);
      const user = text(rule.user, `${what}.user`, 1024, 0);
      const password = text(rule.password, `${what}.password`, 1024, 0);
      if (keysIn(user).length + keysIn(password).length === 0) problem(`${what} names no key: write {KEY} in its user or password`);
      return { kind: 'basic', user, password };
    }
    case 'sigv4': {
      only(rule, ['kind', 'accessKeyId', 'secretAccessKey', 'sessionToken', 'region', 'service'], what);
      const word = (field: string) => {
        const written = rule[field];
        if (typeof written !== 'string' || !/^[a-z0-9-]{1,32}$/.test(written)) problem(`${what}.${field} is lowercase letters, digits and dashes, 1 to 32`);
        return written;
      };
      return {
        kind: 'sigv4',
        accessKeyId: template(rule.accessKeyId, `${what}.accessKeyId`),
        secretAccessKey: template(rule.secretAccessKey, `${what}.secretAccessKey`),
        sessionToken: rule.sessionToken === null || rule.sessionToken === undefined || rule.sessionToken === '' ? null : template(rule.sessionToken, `${what}.sessionToken`),
        region: word('region'),
        service: word('service'),
      };
    }
    default:
      problem(`${what}: a rule is a 'header', 'query', 'form', 'json', 'basic' or 'sigv4'`);
  }
}

/**
 * The rules among themselves (section 7): one per header (any case),
 * parameter or field; a form and a JSON body never both; one `basic` at
 * most, never beside a rule setting `authorization`; one `sigv4` at most,
 * last, beside no rule setting `authorization`, an `x-amz-` header or
 * parameter, or a body field, which would change what it signs.
 */
function injectOrder(rules: readonly ProxyInject[], name: string): void {
  const slots = new Set<string>();
  for (const rule of rules) {
    if (rule.kind === 'basic' || rule.kind === 'sigv4') continue;
    // As the proxy reads them (`checkRules`): a header in any case, a parameter or a field as any parser may (`alike`: `secret` and `SECRET` are one).
    const slot = rule.kind === 'header' ? `header:${rule.name.toLowerCase()}` : `${rule.kind === 'json' ? 'form' : rule.kind}:${alike(rule.name)}`;
    if (slots.has(slot)) problem(`${name}: one rule per header, parameter or field: ${rule.name} is set twice`);
    slots.add(slot);
  }
  const kinds = rules.map((rule) => rule.kind);
  if (kinds.includes('form') && kinds.includes('json')) problem(`${name}: a body is a form or JSON, never both`);
  if (kinds.filter((kind) => kind === 'basic').length > 1) problem(`${name}: one basic rule at most`);
  const authorization = rules.some((rule) => rule.kind === 'header' && rule.name === 'authorization');
  const queryAuthorization = rules.some((rule) => rule.kind === 'query' && rule.name.toLowerCase() === 'authorization');
  if (kinds.includes('basic') && authorization) problem(`${name}: basic sets authorization, which another rule sets too`);
  const sigv4 = kinds.filter((kind) => kind === 'sigv4').length;
  if (sigv4 > 1) problem(`${name}: one sigv4 rule at most`);
  if (sigv4 === 1) {
    if (kinds.at(-1) !== 'sigv4') problem(`${name}: sigv4 signs the request as the rules before it leave it, so it goes last`);
    if (authorization || queryAuthorization || kinds.includes('basic')) problem(`${name}: sigv4 sets authorization itself`);
    if (rules.some((rule) => (rule.kind === 'header' || rule.kind === 'query') && rule.name.toLowerCase().startsWith('x-amz-'))) problem(`${name}: sigv4 sets the x-amz- headers and parameters itself`);
    if (kinds.includes('form') || kinds.includes('json')) problem(`${name}: sigv4 signs the body, which a field would change`);
  }
}

function placeholderOf(value: unknown, name: string): ProxyPlaceholder {
  if (value === null || value === undefined) return null;
  const placeholder = record(value, `${name}: placeholder`);
  if (placeholder.kind === 'prefix') {
    only(placeholder, ['kind', 'prefix'], `${name}: placeholder`);
    return { kind: 'prefix', prefix: text(placeholder.prefix, `${name}: placeholder.prefix`, 64) };
  }
  if (placeholder.kind === 'jwt') {
    only(placeholder, ['kind', 'claims'], `${name}: placeholder`);
    const claims = list(placeholder.claims ?? [], `${name}: placeholder.claims`, 0, 16).map((claim, i) => text(claim, `${name}: placeholder.claims[${i}]`, 128));
    return { kind: 'jwt', claims };
  }
  problem(`${name}: a placeholder is a 'prefix' or a 'jwt'`);
}

function limitOf(value: unknown, name: string): ProxyLimit {
  if (value === null || value === undefined) return { perMinute: null, perDay: null };
  const limit = record(value, `${name}: limit`);
  only(limit, ['perMinute', 'perDay'], `${name}: limit`);
  const count = (field: 'perMinute' | 'perDay') => {
    const n = limit[field];
    if (n === null || n === undefined) return null;
    if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < 1) problem(`${name}: limit.${field} is a whole number of at least 1, or none`);
    return n;
  };
  return { perMinute: count('perMinute'), perDay: count('perDay') };
}

function hmacOf(hmac: Record<string, unknown>, what: string, also: readonly string[] = []): ProxyHmac {
  only(hmac, [...also, 'key', 'encoding', 'prefix', 'maxBytes'], what);
  if (hmac.encoding !== 'hex' && hmac.encoding !== 'base64' && hmac.encoding !== 'base64url') problem(`${what}.encoding is hex, base64 or base64url`);
  const maxBytes = hmac.maxBytes ?? null;
  if (maxBytes !== null && (typeof maxBytes !== 'number' || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 16 * 1024 * 1024)) problem(`${what}.maxBytes is a whole number of bytes, 1 to 16 MiB, or none`);
  return { key: keyName(hmac.key, `${what}.key`), encoding: hmac.encoding, prefix: text(hmac.prefix ?? '', `${what}.prefix`, 64, 0), maxBytes: maxBytes as number | null };
}

function transportName(value: unknown, what: string): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string' || !CREDENTIAL_NAME.test(value)) problem(`${what} names one code declares: lowercase letters, digits and dashes`);
  return value;
}

/**
 * An upstream an Owner may write (section 5): `https://` to a public DNS
 * name or address, no user, query or fragment. Loopback, private,
 * link-local and metadata addresses, `localhost` and single-label names are
 * refused; `insecureUpstreams`, the app's config for a local fake, lifts it.
 */
function upstreamOf(value: unknown, name: string, insecure: boolean): string {
  const written = text(value, `${name}: upstream`, 2048);
  let url: URL;
  try {
    url = new URL(written);
  } catch {
    problem(`${name}: upstream is a URL, https://api.example.com/v1`);
  }
  if (url.protocol !== 'https:' && !(insecure && url.protocol === 'http:')) problem(`${name}: upstream is https://`);
  if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') problem(`${name}: upstream has no user, query or fragment`);
  hostOf(url.hostname, `${name}: upstream`, insecure);
  return written;
}

/** A host an Owner may name: public, as `upstreamOf` says, unless `trusted` (a network code declares, or `insecureUpstreams`). */
function hostOf(value: unknown, what: string, trusted: boolean): string {
  const written = text(value, what, 253);
  let host: string;
  try {
    host = canonicalHost(new URL(`http://${written.includes(':') && !written.startsWith('[') ? `[${written}]` : written}`).hostname);
  } catch {
    problem(`${what} is a host name or address`);
  }
  if (trusted) return host;
  if (privateHost(host)) problem(`${what} is a private, loopback or link-local address, or localhost, which no UI definition reaches`);
  if (!host.includes(':') && !/^\d+\.\d+\.\d+\.\d+$/.test(host) && !host.includes('.')) problem(`${what} is a single-label name, which a resolver may point anywhere: name the host in full`);
  return host;
}

/** A host as a URL's `hostname` writes it, without brackets or trailing dots, in lowercase. */
export function canonicalHost(host: string): string {
  return host.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.+$/, '');
}

/** Whether a host is a private, loopback or link-local address (169.254.169.254, the metadata service's, included), or localhost, however it is written. */
export function privateHost(host: string): boolean {
  const name = canonicalHost(host);
  if (name === 'localhost' || name.endsWith('.localhost')) return true;
  const v4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(name);
  if (v4 !== null) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 198 && (b === 18 || b === 19));
  }
  if (!name.includes(':')) return false;
  // 6to4 carries an IPv4 address in its next 32 bits: 2002:a00:1:: is 10.0.0.1's.
  const [first, high, low] = hextets(name);
  if (first === 0x2002) return privateHost(`${high! >> 8}.${high! & 255}.${low! >> 8}.${low! & 255}`);
  // ::/16 holds loopback, the unspecified address and IPv4 written as IPv6 (::ffff:a00:1, ::7f00:1); 64:ff9b:: is NAT64's; fe80::/10 is link-local, fec0::/10 site-local.
  return /^(?:::|0:)/.test(name) || /^f[cd]/.test(name) || /^fe[89a-f]/.test(name) || name.startsWith('64:ff9b:');
}

/** An IPv6 address as a URL writes it (hex groups, `::` once at most), as its eight groups. */
function hextets(address: string): number[] {
  const [head, tail] = address.split('::').map((part) => (part === '' ? [] : part.split(':')));
  const groups = tail === undefined ? head! : [...head!, ...Array<string>(8 - head!.length - tail.length).fill('0'), ...tail];
  return groups.map((group) => parseInt(group, 16));
}

/**
 * A route's allow list (section 7): each entry its methods, from the fixed
 * list, each once (none: any), and a path the proxy's matcher takes as a
 * Proxy tab's (`readPattern`): no segment a server behind may read as
 * another (`.`, `..`, empty, `%2561`, `a;v1`, `a.`), `*` and `**` alone in
 * a segment, `**` only last, no trailing slash (`/companies/**` says it);
 * no entry twice. `/` alone allows every path.
 */
function allowOf(value: unknown, name: string): ProxyAllow[] | null {
  // None is any request, as in code; an empty list is none (section 7). Kept apart, so the proxy reads the one the Owner meant.
  if (value === null || value === undefined) return null;
  const entries = list(value, `${name}: allow`, 0, 64).map((entry, i) => {
    const what = `${name}: allow[${i}]`;
    const allow = record(entry, what);
    only(allow, ['methods', 'path'], what);
    const methods = list(allow.methods ?? [], `${what}.methods`, 0, PROXY_METHODS.length);
    if (methods.some((method) => !(PROXY_METHODS as readonly unknown[]).includes(method)) || new Set(methods).size !== methods.length) {
      problem(`${what}.methods are from ${PROXY_METHODS.join(', ')}, each once`);
    }
    const path = allowedPath(allow.path, `${what}.path`);
    return { methods: PROXY_METHODS.filter((method) => methods.includes(method)), path: path.written, read: path.read };
  });
  // Once each, as the proxy reads them: `/a` and `/%61` are one path.
  const seen = new Set(entries.map((entry) => `${entry.methods.join(',')} ${entry.read}`));
  if (seen.size !== entries.length) problem(`${name}: each allow entry once`);
  return entries.map(({ methods, path }) => ({ methods, path }));
}

/**
 * An allow entry's path as the proxy reads a Proxy tab's (`readPattern`,
 * `ui`): its parse is the matcher's own, so a saved path is one it takes.
 */
function allowedPath(value: unknown, what: string): { written: string; read: string } {
  const written = text(value, what, 1024);
  const read = readPattern(written, 'ui');
  if ('problem' in read) problem(`${what}: ${read.problem}`);
  return { written, read: JSON.stringify(read.pattern) };
}
