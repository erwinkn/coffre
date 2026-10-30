// The Proxy tab, a prototype (W260, DO NOT MERGE): what an environment's
// credential proxy holds beside what the deployment's code defines. Routes
// (`/use/<name>`), signers, verifiers and database tunnels, in one list.
// Nothing here reaches the vault or `/use`: the deployment hands the page a
// store (dev/deployment/app/src/proxy-prototype.ts keeps one in memory),
// and the rules below are the proposal's, mocked:
//
// - Each environment owns its items. The code's apply to every environment,
//   or to those its `environments` names, and win a name both use: the
//   environment's own item under that name is not shown, nor served (R65).
// - Changing them takes `proxy.edit`, which project and instance Owners
//   hold. Where an item sends its keys (a route's upstream, injection and
//   egress; a signer's or verifier's key; a tunnel's key, hosts and network)
//   also takes reading every key it names: sending a key somewhere is
//   reading it. Sensitive keys no person reads: an Owner covering the place
//   may route them anyway, each such change audited.
// - Several inject rules and allow entries per route, and glob paths, are
//   not in today's proxy: each needs a backend change (0.16).
import { queryOptions } from '@tanstack/react-query';

import type { SecretKey } from '../shared/models';

export type ProxyPlace = { project: string; environment: string };

export type ItemKind = 'route' | 'signer' | 'verifier' | 'tunnel';

export const KIND_LABELS: Record<ItemKind, string> = { route: 'Route', signer: 'Signer', verifier: 'Verifier', tunnel: 'Database' };

/** How a route's values reach its upstream, as `credentialProxy` has it: each field a template, `{KEY}` the environment's value. */
export type ProxyInject =
  | { kind: 'header' | 'query' | 'form' | 'json'; name: string; template: string }
  | { kind: 'basic'; user: string; password: string }
  | { kind: 'sigv4'; accessKeyId: string; secretAccessKey: string; sessionToken: string; region: string; service: string };

export type InjectKind = ProxyInject['kind'];

/** Which requests a route takes: these methods (none: any), on this path. A plain path is a prefix; `*` stands for one segment, `**` for the rest. */
export type AllowEntry = { methods: string[]; path: string };

export type Limit = { perMinute: number | null; perDay: number | null };

/** What the app holds in place of the key: the handle as it is (null), one with the key's prefix, or a JWT carrying some of its claims. */
export type ProxyPlaceholder = null | { kind: 'prefix'; prefix: string } | { kind: 'jwt'; claims: string[] };

export type Encoding = 'hex' | 'base64' | 'base64url';

export type Hmac = { key: string; encoding: Encoding; prefix: string; maxBytes: number | null };

export type RouteDefinition = {
  kind: 'route';
  name: string;
  upstream: string;
  inject: ProxyInject[];
  /** None: any method on any path. */
  allow: AllowEntry[];
  limit: Limit;
  placeholder: ProxyPlaceholder;
  /** The named egress its requests leave through; null: direct. */
  egress: string | null;
};

export type SignerDefinition = { kind: 'signer'; name: string; signer: { kind: 'private-key'; key: string } | ({ kind: 'hmac' } & Hmac); limit: Limit };
export type VerifierDefinition = { kind: 'verifier'; name: string; hmac: Hmac; limit: Limit };
export type TunnelDefinition = { kind: 'tunnel'; name: string; key: string; hosts: string[]; network: string | null };

export type ProxyDefinition = RouteDefinition | SignerDefinition | VerifierDefinition | TunnelDefinition;

export type ProxyCredential = ProxyDefinition & {
  /** `code`: `credentialProxy({ … })`, read only here. */
  source: 'code' | 'environment';
  /** The environments a code item serves, by path (`market/prod`), as its `environments` names them; null: every one. */
  environments: string[] | null;
  /** A limit the code computes per service, which no form shows. */
  limitPerService: boolean;
  changedAt: string | null;
  changedBy: string | null;
};

/** A transport the code declares, by name: an egress for routes (a VPC Service), a network for tunnels (a VPC Network). Hosts it alone reaches, if it says. */
export type ProxyTransport = { name: string; description: string | null; hosts: string[] | null };

export type ProxyConfig = {
  credentials: ProxyCredential[];
  egresses: ProxyTransport[];
  networks: ProxyTransport[];
  /** `<publicUrl>/use`, under which each route answers. */
  useUrl: string;
};

/** One change to an environment's items: `was` the name it replaces (null adds one), `definition` null deletes it. */
export type ProxyChange = { was: string | null; definition: ProxyDefinition | null };

export type ProxyStore = {
  read(place: ProxyPlace): Promise<ProxyConfig>;
  /** Applies every change or none, and answers the environment's items after. */
  write(place: ProxyPlace, changes: ProxyChange[]): Promise<ProxyConfig>;
};

export const proxyKey = (place: ProxyPlace) => ['proxy-prototype', place.project, place.environment] as const;

export const proxyQuery = (store: ProxyStore, place: ProxyPlace) => queryOptions({ queryKey: proxyKey(place), queryFn: () => store.read(place) });

export const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
export const ENCODINGS: Encoding[] = ['hex', 'base64', 'base64url'];

// --- making them -------------------------------------------------------------------------

const NO_LIMIT: Limit = { perMinute: null, perDay: null };

export function blankInject(kind: InjectKind): ProxyInject {
  switch (kind) {
    case 'basic':
      return { kind, user: '', password: '' };
    case 'sigv4':
      return { kind, accessKeyId: '', secretAccessKey: '', sessionToken: '', region: '', service: 's3' };
    case 'header':
      return { kind, name: 'authorization', template: 'Bearer ' };
    default:
      return { kind, name: '', template: '' };
  }
}

export function blankDefinition(kind: ItemKind): ProxyDefinition {
  switch (kind) {
    case 'route':
      return { kind, name: '', upstream: 'https://', inject: [blankInject('header')], allow: [], limit: NO_LIMIT, placeholder: null, egress: null };
    case 'signer':
      return { kind, name: '', signer: { kind: 'private-key', key: '' }, limit: NO_LIMIT };
    case 'verifier':
      return { kind, name: '', hmac: { key: '', encoding: 'hex', prefix: '', maxBytes: null }, limit: NO_LIMIT };
    case 'tunnel':
      return { kind, name: '', key: '', hosts: [], network: null };
  }
}

/** An item's own fields, without what the store keeps beside it. */
export function definitionOf(credential: ProxyCredential): ProxyDefinition {
  const { source: _source, environments: _environments, limitPerService: _limit, changedAt: _at, changedBy: _by, ...definition } = credential;
  return definition as ProxyDefinition;
}

/** An item as it will be saved: names and addresses trimmed, empty entries dropped. */
export function normalized(definition: ProxyDefinition): ProxyDefinition {
  const name = definition.name.trim();
  switch (definition.kind) {
    case 'route':
      return {
        ...definition,
        name,
        upstream: definition.upstream.trim().replace(/\/+$/, ''),
        allow: definition.allow.map((entry) => ({ methods: METHODS.filter((method) => entry.methods.includes(method)), path: entry.path.trim() })),
        placeholder:
          definition.placeholder?.kind === 'jwt'
            ? { kind: 'jwt', claims: definition.placeholder.claims.map((claim) => claim.trim()).filter((claim) => claim !== '') }
            : definition.placeholder?.kind === 'prefix'
              ? { kind: 'prefix', prefix: definition.placeholder.prefix.trim() }
              : null,
      };
    case 'tunnel':
      return { ...definition, name, hosts: definition.hosts.map((host) => host.trim()).filter((host) => host !== '') };
    default:
      return { ...definition, name };
  }
}

export const sameDefinition = (a: ProxyDefinition, b: ProxyDefinition) => JSON.stringify(normalized(a)) === JSON.stringify(normalized(b));

// --- templates -------------------------------------------------------------------------------

const TOKEN = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

/** A template in pieces: its text, and each `{KEY}` it names. */
export function templateParts(template: string): ({ text: string } | { key: string })[] {
  const parts: ({ text: string } | { key: string })[] = [];
  let at = 0;
  for (const match of template.matchAll(TOKEN)) {
    if (match.index > at) parts.push({ text: template.slice(at, match.index) });
    parts.push({ key: match[1]! });
    at = match.index + match[0].length;
  }
  if (at < template.length) parts.push({ text: template.slice(at) });
  return parts;
}

export function templatesOf(inject: ProxyInject): string[] {
  switch (inject.kind) {
    case 'basic':
      return [inject.user, inject.password];
    case 'sigv4':
      return [inject.accessKeyId, inject.secretAccessKey, inject.sessionToken];
    default:
      return [inject.template];
  }
}

const keysIn = (template: string) => [...template.matchAll(TOKEN)].map((match) => match[1]!);

/** A key as a SigV4 field holds it: `{AWS_ACCESS_KEY_ID}`, or none. */
export const soleKey = (template: string) => /^\{([A-Za-z_][A-Za-z0-9_]*)\}$/.exec(template)?.[1] ?? '';

/** Every key an item sends or uses, once, in order. */
export function keysOf(definition: ProxyDefinition): string[] {
  switch (definition.kind) {
    case 'route':
      return [...new Set(definition.inject.flatMap(templatesOf).flatMap(keysIn))];
    case 'signer':
      return definition.signer.key === '' ? [] : [definition.signer.key];
    case 'verifier':
      return definition.hmac.key === '' ? [] : [definition.hmac.key];
    case 'tunnel':
      return definition.key === '' ? [] : [definition.key];
  }
}

// --- the rules, mocked -----------------------------------------------------------------------

/** Whether a change sends keys somewhere they did not go: a new item, or a new destination for the old one. */
export function redirects(before: ProxyDefinition | null, after: ProxyDefinition): boolean {
  if (before === null || before.kind !== after.kind) return true;
  const a = normalized(before);
  const b = normalized(after);
  const same = (x: unknown, y: unknown) => JSON.stringify(x) === JSON.stringify(y);
  switch (b.kind) {
    case 'route': {
      const was = a as RouteDefinition;
      return was.upstream !== b.upstream || was.egress !== b.egress || !same(was.inject, b.inject);
    }
    case 'signer':
      return (a as SignerDefinition).signer.key !== b.signer.key;
    case 'verifier':
      return (a as VerifierDefinition).hmac.key !== b.hmac.key;
    case 'tunnel': {
      const was = a as TunnelDefinition;
      return was.key !== b.key || was.network !== b.network || !same(was.hosts, b.hosts);
    }
  }
}

/** The keys of `names` the editor cannot read: sensitive ones, which no person reads, apart. */
export function unreadable(names: readonly string[], keys: readonly SecretKey[]): { key: string; sensitive: boolean }[] {
  return names.flatMap((name) => {
    const entry = keys.find((one) => one.key === name && !one.archived);
    if (entry === undefined || entry.readable) return [];
    return [{ key: name, sensitive: entry.sensitivity === 'sensitive' }];
  });
}

const them = (count: number) => (count === 1 ? 'it' : 'them');

/** The refusal, in words, for keys the editor may not send somewhere new. */
export function lockedInWords(locked: readonly { key: string }[]): string {
  return `You can't read ${locked.map((one) => one.key).join(', ')}, so you can't send ${them(locked.length)} somewhere new.`;
}

/** What routing sensitive keys means for an Owner, said where it happens. */
export function routedInWords(keys: readonly string[]): string {
  return `${keys.join(', ')} ${keys.length === 1 ? 'is' : 'are'} sensitive: as an Owner you may send ${them(keys.length)} here, and the change is audited.`;
}

export type Problems = Record<string, string>;

export type Checked = {
  place: ProxyPlace;
  /** The environment's keys, as its secrets list has them for the editor. */
  keys: readonly SecretKey[];
  /** Whether the editor is an Owner covering the place, who may route sensitive keys (audited). */
  owner: boolean;
  /** The names held already: the code's, and this environment's other items. */
  code: readonly string[];
  others: readonly string[];
  egresses: readonly ProxyTransport[];
  networks: readonly ProxyTransport[];
  /** The item as it was, or null for a new one. */
  before: ProxyDefinition | null;
};

/** What is wrong with an item, field by field, and the sensitive keys it routes, which an Owner may, audited. */
export function definitionProblems(definition: ProxyDefinition, checked: Checked): { problems: Problems; routed: string[] } {
  const problems: Problems = {};
  const item = normalized(definition);
  const where = `${checked.place.project}/${checked.place.environment}`;
  const has = (key: string) => checked.keys.some((entry) => entry.key === key && !entry.archived);

  if (!/^[a-z][a-z0-9-]{0,31}$/.test(item.name)) problems.name = 'Lowercase letters, digits and dashes, starting with a letter.';
  else if (checked.code.includes(item.name)) problems.name = `The code takes ${item.name}: pick another name.`;
  else if (checked.others.includes(item.name)) problems.name = `${where} has ${item.name} already.`;

  const key = (field: string, name: string, what = 'Pick a key.') => {
    if (name === '') problems[field] = what;
    else if (!has(name)) problems[field] = `No ${name} in ${where}.`;
  };
  const limit = (value: Limit) => {
    if (value.perMinute !== null && value.perDay !== null && value.perDay < value.perMinute) problems.perDay = 'At least the minute’s limit.';
  };
  const hmac = (value: Hmac) => {
    key('key', value.key);
    if (!/^[\x21-\x7e]*$/.test(value.prefix)) problems.prefix = 'Printable characters, no spaces.';
    if (value.maxBytes !== null && (value.maxBytes < 1 || value.maxBytes > 1_048_576)) problems.maxBytes = 'Up to 1,048,576 bytes (1 MiB).';
  };

  switch (item.kind) {
    case 'route': {
      routeProblems(item, checked, problems, has, where);
      limit(item.limit);
      break;
    }
    case 'signer':
      if (item.signer.kind === 'hmac') hmac(item.signer);
      else key('key', item.signer.key);
      limit(item.limit);
      break;
    case 'verifier':
      hmac(item.hmac);
      limit(item.limit);
      break;
    case 'tunnel': {
      key('key', item.key);
      const network = checked.networks.find((one) => one.name === item.network);
      if (item.network !== null && network === undefined) problems.network = `The code declares no network ${item.network}.`;
      if (item.network !== null && item.hosts.length === 0) problems.hosts = 'A network needs the hosts the URL may name.';
      const bad = item.hosts.find((host) => !/^[A-Za-z0-9.-]+(:\d{1,5})?$|^\[[0-9a-fA-F:]+\](:\d{1,5})?$/.test(host));
      if (bad !== undefined) problems.hosts = `${bad}: a host name or address.`;
      break;
    }
  }

  // Sending a key somewhere is reading it: only a key the editor reads, or a sensitive one an Owner routes, audited.
  const routed: string[] = [];
  if (redirects(checked.before, item)) {
    const locked = unreadable(keysOf(item), checked.keys);
    const refused = locked.filter((one) => !(one.sensitive && checked.owner));
    routed.push(...locked.filter((one) => one.sensitive && checked.owner).map((one) => one.key));
    if (refused.length > 0) problems.keys = lockedInWords(refused);
  }
  return { problems, routed };
}

const HEADER = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const FORBIDDEN_HEADERS = new Set(['host', 'content-length', 'cookie', 'connection', 'transfer-encoding']);

function routeProblems(route: RouteDefinition, checked: Checked, problems: Problems, has: (key: string) => boolean, where: string) {
  try {
    const url = new URL(route.upstream);
    if (url.protocol === 'http:') problems.upstream = 'Plain HTTP is for the code alone (insecureUpstreams).';
    else if (url.protocol !== 'https:' || url.hostname === '') problems.upstream = 'An https:// address.';
    else if (url.search !== '' || url.hash !== '' || url.username !== '' || url.password !== '') problems.upstream = 'No query, fragment or credentials: paths go under it.';
  } catch {
    problems.upstream = 'An https:// address, such as https://api.openai.com/v1.';
  }

  if (route.egress !== null) {
    const egress = checked.egresses.find((one) => one.name === route.egress);
    const refusal = egress === undefined ? `The code declares no egress ${route.egress}.` : transportRefusal(egress, route.upstream);
    if (refusal !== null) problems.egress = refusal;
  }

  if (route.inject.length === 0) problems.inject = 'Add a rule: a route sends a key.';
  const seen = new Set<string>();
  route.inject.forEach((rule, index) => {
    const field = `inject.${index}`;
    const absent = templatesOf(rule).flatMap(keysIn).filter((name) => !has(name));
    if (rule.kind === 'sigv4') {
      if (soleKey(rule.accessKeyId) === '' || soleKey(rule.secretAccessKey) === '') problems[field] = 'Pick the keys holding the key pair.';
      else if (!/^[a-z]{2}(-[a-z]+)+-\d$/.test(rule.region)) problems[field] = 'A region, such as eu-west-3.';
      else if (!/^[a-z0-9-]+$/.test(rule.service)) problems[field] = 'A service, such as s3.';
    } else if (rule.kind === 'header' && (!HEADER.test(rule.name) || FORBIDDEN_HEADERS.has(rule.name.toLowerCase()))) {
      problems[field] = FORBIDDEN_HEADERS.has(rule.name.toLowerCase()) ? `coffre sets ${rule.name.toLowerCase()} itself.` : 'A header name, such as authorization.';
    } else if ((rule.kind === 'query' || rule.kind === 'form' || rule.kind === 'json') && !/^[A-Za-z0-9_.\-[\]]+$/.test(rule.name)) {
      problems[field] = 'A field name, such as key.';
    }
    if (problems[field] === undefined && absent.length > 0) problems[field] = `No ${absent.join(', ')} in ${where}.`;
    if (problems[field] === undefined && templatesOf(rule).flatMap(keysIn).length === 0) problems[field] = 'Name a key: type {.';
    // One Authorization of each kind, and one rule per header or field.
    const slot = rule.kind === 'basic' || rule.kind === 'sigv4' ? rule.kind : `${rule.kind}:${rule.name.toLowerCase()}`;
    if (problems[field] === undefined && seen.has(slot))
      problems[field] = rule.kind === 'basic' ? 'Basic auth at most once.' : rule.kind === 'sigv4' ? 'SigV4 at most once.' : `${rule.name} is set by another rule.`;
    seen.add(slot);
    if (problems[field] === undefined && rule.kind === 'basic' && route.inject.some((other) => other.kind === 'header' && other.name.toLowerCase() === 'authorization'))
      problems[field] = 'Basic auth sets authorization, which a header rule sets too.';
  });
  const last = route.inject.findIndex((rule) => rule.kind === 'sigv4');
  if (last !== -1 && last !== route.inject.length - 1 && problems[`inject.${last}`] === undefined)
    problems[`inject.${last}`] = 'SigV4 signs last, after every other rule: move it to the end.';

  const pairs = new Set<string>();
  route.allow.forEach((entry, index) => {
    const problem = pathProblem(entry.path);
    const pair = `${entry.methods.join(',')} ${entry.path}`;
    if (problem !== null) problems[`allow.${index}`] = problem;
    else if (pairs.has(pair)) problems[`allow.${index}`] = 'The same entry twice.';
    pairs.add(pair);
  });

  const placeholder = route.placeholder;
  if (placeholder !== null) {
    const shaped = route.inject.filter((rule) => rule.kind !== 'basic' && rule.kind !== 'sigv4').flatMap(templatesOf).flatMap(keysIn);
    if (new Set(shaped).size !== 1) problems.placeholder = 'A placeholder shapes the one key a header, query or field rule carries.';
    else if (placeholder.kind === 'prefix' && !/^[A-Za-z0-9_-]+$/.test(placeholder.prefix)) problems.placeholder = 'Letters, digits, dashes and underscores, such as sk_test_.';
    else if (placeholder.kind === 'jwt' && placeholder.claims.length === 0) problems.placeholder = 'Name a claim.';
  }
}

/** Why an address may not go through a transport, or null when it may: one that names no hosts takes any. */
export function transportRefusal(transport: ProxyTransport, upstream: string): string | null {
  if (transport.hosts === null) return null;
  let host: string;
  try {
    host = new URL(upstream).hostname;
  } catch {
    return null;
  }
  return transport.hosts.includes(host) ? null : `${transport.name} reaches ${transport.hosts.join(', ')} alone, not ${host}.`;
}

// --- paths ------------------------------------------------------------------------------------------

const SEGMENT = /^[A-Za-z0-9._~!$&'()+,;=:@%-]+$/;

/** What is wrong with an allow path, or null: `/a/b` a prefix, `*` one segment, `**` the rest, nothing else. No regexes. */
export function pathProblem(path: string): string | null {
  if (!path.startsWith('/')) return 'A path, starting with /.';
  const segments = path.slice(1).split('/');
  for (const [index, segment] of segments.entries()) {
    if (segment === '' && index === segments.length - 1) continue;
    if (segment === '**' && index !== segments.length - 1) return '** stands for the rest: only last.';
    if (segment === '..' || segment === '.') return 'No . or .. segments.';
    if (segment !== '*' && segment !== '**' && !SEGMENT.test(segment)) return segment.includes('*') ? '* and ** stand for whole segments.' : `${segment}: not a path segment.`;
  }
  return null;
}

export const isGlob = (path: string) => path.split('/').some((segment) => segment === '*' || segment === '**');

/** Whether today's proxy could take the route's allow list as it is: one set of methods over plain prefixes. */
export function allowsToday(allow: readonly AllowEntry[]): boolean {
  return allow.every((entry) => !isGlob(entry.path) && entry.methods.join() === allow[0]!.methods.join());
}

/** Whether `path` is one an entry's pattern takes: by prefix, or segment by segment for a glob. */
export function pathMatches(pattern: string, path: string): boolean {
  if (!isGlob(pattern)) {
    const prefix = pattern.replace(/\/+$/, '');
    return prefix === '' || path === prefix || path.startsWith(`${prefix}/`);
  }
  const want = pattern.slice(1).split('/');
  const have = path.slice(1).split('/');
  for (const [index, segment] of want.entries()) {
    if (segment === '**') return true;
    if (index >= have.length || have[index] === '') return false;
    if (segment !== '*' && segment !== have[index]) return false;
  }
  return have.length === want.length;
}

/** Where a sample call goes, and why it would not. */
export function sampleCall(route: RouteDefinition, method: string, path: string): { url: string; refusal: string | null } {
  const tail = path.startsWith('/') ? path : `/${path}`;
  const allowed = route.allow.length === 0 || route.allow.some((entry) => (entry.methods.length === 0 || entry.methods.includes(method)) && pathMatches(entry.path, tail));
  return { url: `${route.upstream}${tail}`, refusal: allowed ? null : `403: no allow entry takes ${method} ${tail}` };
}

// --- words, and code ---------------------------------------------------------------------------------

export const INJECT_LABELS: Record<InjectKind, string> = { header: 'Header', query: 'Query', form: 'Form', json: 'JSON', basic: 'Basic', sigv4: 'SigV4' };

export function injectInWords(inject: ProxyInject): string {
  switch (inject.kind) {
    case 'header':
      return `${inject.name}: ${inject.template}`;
    case 'query':
      return `?${inject.name}=${inject.template}`;
    case 'form':
      return `${inject.name}=${inject.template}`;
    case 'json':
      return `"${inject.name}": "${inject.template}"`;
    case 'basic':
      return `${inject.user}:${inject.password}`;
    case 'sigv4':
      return `${inject.service} in ${inject.region}, ${[inject.accessKeyId, inject.secretAccessKey, inject.sessionToken].filter((one) => one !== '').join(', ')}`;
  }
}

const format = new Intl.NumberFormat('en');

export function limitInWords(limit: Limit, perService = false): string {
  if (perService) return 'Per service, in code';
  const parts = [limit.perMinute !== null && `${format.format(limit.perMinute)} a minute`, limit.perDay !== null && `${format.format(limit.perDay)} a day`].filter((part) => part !== false);
  return parts.length === 0 ? 'None' : parts.join(', ');
}

/** What the list says an item reaches: a route's host, a key, a database's hosts. */
export function targetOf(definition: ProxyDefinition): string {
  switch (definition.kind) {
    case 'route':
      try {
        return new URL(definition.upstream).host;
      } catch {
        return definition.upstream;
      }
    case 'signer':
      return definition.signer.key;
    case 'verifier':
      return definition.hmac.key;
    case 'tunnel':
      return definition.hosts.length > 0 ? `${definition.key} @ ${definition.hosts.join(', ')}` : definition.key;
  }
}

const q = (text: string) => `'${text.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
const prop = (name: string) => (/^[a-z][a-z0-9]*$/i.test(name) ? name : q(name));
const limitCode = (limit: Limit) => {
  const parts = [limit.perMinute !== null && `perMinute: ${limit.perMinute}`, limit.perDay !== null && `perDay: ${limit.perDay}`].filter((part) => part !== false);
  return parts.length === 0 ? null : `{ ${parts.join(', ')} }`;
};
const injectCode = (inject: ProxyInject) => {
  switch (inject.kind) {
    case 'basic':
      return `basic(${q(inject.user)}, ${q(inject.password)})`;
    case 'sigv4':
      return `sigv4({ accessKeyId: ${q(inject.accessKeyId)}, secretAccessKey: ${q(inject.secretAccessKey)}${inject.sessionToken === '' ? '' : `, sessionToken: ${q(inject.sessionToken)}`}, region: ${q(inject.region)}, service: ${q(inject.service)} })`;
    default:
      return `${inject.kind}(${q(inject.name)}, ${q(inject.template)})`;
  }
};
const hmacCode = (value: Hmac, limit: Limit) => {
  const options = [`encoding: ${q(value.encoding)}`, value.prefix !== '' && `prefix: ${q(value.prefix)}`, value.maxBytes !== null && `maxBytes: ${value.maxBytes}`, limitCode(limit) !== null && `limit: ${limitCode(limit)}`].filter(
    (part) => part !== false,
  );
  return `hmac(${q(value.key)}, { ${options.join(', ')} })`;
};

/**
 * An item as `credentialProxy({ … })` would hold it, to move into code
 * (code wins a name both take). What today's proxy has no shape for, several
 * rules or allow entries, is written as 0.16 would take it, and says so.
 */
export function codeOf(definition: ProxyDefinition): string {
  const item = normalized(definition);
  const name = prop(item.name || 'name');
  switch (item.kind) {
    case 'route': {
      const lines = [`upstream: ${q(item.upstream)},`];
      if (item.egress !== null) lines.push(`egress: egresses[${q(item.egress)}],`);
      lines.push(item.inject.length === 1 ? `inject: ${injectCode(item.inject[0]!)},` : `inject: [${item.inject.map(injectCode).join(', ')}], // 0.16`);
      if (item.placeholder !== null) lines.push(`placeholder: ${item.placeholder.kind === 'prefix' ? `prefix(${q(item.placeholder.prefix)})` : `jwt({ claims: [${item.placeholder.claims.map(q).join(', ')}] })`},`);
      if (item.allow.length > 0 && allowsToday(item.allow)) {
        if (item.allow[0]!.methods.length > 0) lines.push(`methods: [${item.allow[0]!.methods.map(q).join(', ')}],`);
        lines.push(`paths: [${item.allow.map((entry) => q(entry.path)).join(', ')}],`);
      } else if (item.allow.length > 0) {
        lines.push(`allow: [ // 0.16`, ...item.allow.map((entry) => `  { methods: [${entry.methods.map(q).join(', ')}], path: ${q(entry.path)} },`), `],`);
      }
      if (limitCode(item.limit) !== null) lines.push(`limit: ${limitCode(item.limit)},`);
      return `credentials: {\n  ${name}: {\n${lines.map((line) => `    ${line}`).join('\n')}\n  },\n},`;
    }
    case 'signer': {
      const body = item.signer.kind === 'hmac' ? hmacCode(item.signer, item.limit) : `privateKey(${q(item.signer.key)}${limitCode(item.limit) === null ? '' : `, { limit: ${limitCode(item.limit)} }`})`;
      return `signers: {\n  ${name}: ${body},\n},`;
    }
    case 'verifier':
      return `verifiers: {\n  ${name}: ${hmacCode(item.hmac, item.limit)},\n},`;
    case 'tunnel': {
      const options = [item.hosts.length > 0 && `hosts: [${item.hosts.map(q).join(', ')}]`, item.network !== null && `connect: networks[${q(item.network)}]`].filter((part) => part !== false);
      return `tunnels: {\n  ${name}: postgres(${q(item.key)}${options.length === 0 ? '' : `, { ${options.join(', ')} }`}),\n},`;
    }
  }
}

/** A change, field by field, in words: what the review shows. A field the change leaves is left out. */
export function diffOf(before: ProxyDefinition | null, after: ProxyDefinition): { label: string; before: string | null; after: string }[] {
  const fields = fieldsOf(normalized(after));
  const was = before === null ? null : new Map(fieldsOf(normalized(before)));
  return fields.flatMap(([label, value]) => {
    const old = was?.get(label) ?? null;
    return old === value ? [] : [{ label, before: was === null ? null : (old ?? '–'), after: value }];
  });
}

function fieldsOf(item: ProxyDefinition): [string, string][] {
  const limit = (value: Limit): [string, string] => ['Limit', limitInWords(value)];
  switch (item.kind) {
    case 'route':
      return [
        ['Name', item.name],
        ['Upstream', item.upstream],
        ['Egress', item.egress ?? 'Direct'],
        ...item.inject.map((rule, index): [string, string] => [`Sends ${index + 1}`, `${INJECT_LABELS[rule.kind]} ${injectInWords(rule)}`]),
        ['Placeholder', item.placeholder === null ? 'The handle' : item.placeholder.kind === 'prefix' ? `Prefix ${item.placeholder.prefix}` : `JWT ${item.placeholder.claims.join(', ')}`],
        ...(item.allow.length === 0
          ? [['Allows', 'Any method, any path'] as [string, string]]
          : item.allow.map((entry, index): [string, string] => [`Allows ${index + 1}`, `${entry.methods.length === 0 ? 'Any' : entry.methods.join(' ')} ${entry.path}`])),
        limit(item.limit),
      ];
    case 'signer':
      return [
        ['Name', item.name],
        ['Signs with', item.signer.kind === 'hmac' ? 'HMAC-SHA256' : 'Private key'],
        ['Key', item.signer.key],
        ...(item.signer.kind === 'hmac' ? hmacFields(item.signer) : []),
        limit(item.limit),
      ];
    case 'verifier':
      return [['Name', item.name], ['Key', item.hmac.key], ...hmacFields(item.hmac), limit(item.limit)];
    case 'tunnel':
      return [
        ['Name', item.name],
        ['Key', item.key],
        ['Hosts', item.hosts.length === 0 ? 'By address only' : item.hosts.join(', ')],
        ['Network', item.network ?? 'Direct'],
      ];
  }
}

const hmacFields = (value: Hmac): [string, string][] => [
  ['Encoding', value.encoding],
  ['Prefix', value.prefix === '' ? 'None' : value.prefix],
  ['Max bytes', value.maxBytes === null ? '64 KiB' : format.format(value.maxBytes)],
];
