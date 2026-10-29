// The Proxy tab, a prototype (W260, DO NOT MERGE): the credential-proxy
// definitions an environment holds, beside those the deployment's code
// defines. Nothing here reaches the vault or `/use`: the deployment hands
// the page a store (dev/deployment/app/src/proxy-prototype.ts keeps one in
// memory), and the rules below are the proposal's, mocked:
//
// - Each environment owns its definitions. The code's apply to every one,
//   and win a name both define.
// - Changing them takes `proxy.edit`, which project and instance Owners
//   hold. Where a definition sends its keys (its upstream, injection and
//   egress) also takes reading every key it names: sending a key to a host
//   is reading it.
// - A definition leaves directly, or through an egress the code declares by
//   name (a VPC Service binding, say). One that lists its hosts takes only
//   upstreams on them; one that lists none takes any, and a wrong host fails
//   its TLS check, a 502, before any key is sent.
import { queryOptions } from '@tanstack/react-query';

import type { SecretKey } from '../shared/models';

export type ProxyPlace = { project: string; environment: string };

/** How a credential's keys reach its upstream, as `credentialProxy` has it: each field a template, `{KEY}` the environment's value. */
export type ProxyInject =
  | { kind: 'header' | 'query' | 'form' | 'json'; name: string; template: string }
  | { kind: 'basic'; user: string; password: string }
  | { kind: 'sigv4'; accessKeyId: string; secretAccessKey: string; sessionToken: string; region: string; service: string };

export type InjectKind = ProxyInject['kind'];

/** What the app holds in place of the key: the handle as it is (null), one with the key's prefix, or a JWT carrying some of its claims. */
export type ProxyPlaceholder = null | { kind: 'prefix'; prefix: string } | { kind: 'jwt'; claims: string[] };

/** One definition, as the tab edits it. Empty `methods` or `paths`: any. */
export type ProxyDefinition = {
  name: string;
  upstream: string;
  inject: ProxyInject;
  methods: string[];
  paths: string[];
  limit: { perMinute: number | null; perDay: number | null };
  placeholder: ProxyPlaceholder;
  /** The named egress its requests leave through; null: direct. */
  egress: string | null;
};

export type ProxyCredential = ProxyDefinition & {
  /** `code`: `credentialProxy({ credentials })`, for every environment, read only here. */
  source: 'code' | 'environment';
  /** A limit the code computes per service, which no form shows. */
  limitPerService: boolean;
  changedAt: string | null;
  changedBy: string | null;
  /** Code defines this name too, since then: code's is served, and this one is not. */
  shadowedSince: string | null;
};

/** A transport the code declares, by name: what it is, and the hosts it alone reaches, if it says (null: any upstream may pick it). */
export type ProxyEgress = { name: string; description: string | null; hosts: string[] | null };

/** Why an upstream may not leave through an egress, or null when it may. */
export function egressRefusal(egress: ProxyEgress, upstream: string): string | null {
  if (egress.hosts === null) return null;
  let host: string;
  try {
    host = new URL(upstream).hostname;
  } catch {
    return null;
  }
  return egress.hosts.includes(host) ? null : `${egress.name} reaches ${egress.hosts.join(', ')} alone, not ${host}.`;
}

export type ProxyConfig = {
  credentials: ProxyCredential[];
  egresses: ProxyEgress[];
  /** `<publicUrl>/use`, under which each credential answers. */
  useUrl: string;
};

/** One change to an environment's definitions: `was` the name it replaces (null adds one), `definition` null deletes it. */
export type ProxyChange = { was: string | null; definition: ProxyDefinition | null };

export type ProxyStore = {
  read(place: ProxyPlace): Promise<ProxyConfig>;
  /** Applies every change or none, and answers the environment's definitions after. */
  write(place: ProxyPlace, changes: ProxyChange[]): Promise<ProxyConfig>;
};

export const proxyKey = (place: ProxyPlace) => ['proxy-prototype', place.project, place.environment] as const;

export const proxyQuery = (store: ProxyStore, place: ProxyPlace) =>
  queryOptions({ queryKey: proxyKey(place), queryFn: () => store.read(place) });

export const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;

export const INJECT_KINDS: { kind: InjectKind; label: string }[] = [
  { kind: 'header', label: 'Header' },
  { kind: 'query', label: 'Query parameter' },
  { kind: 'form', label: 'Form field' },
  { kind: 'json', label: 'JSON field' },
  { kind: 'basic', label: 'Basic auth' },
  { kind: 'sigv4', label: 'AWS SigV4' },
];

// --- templates ---------------------------------------------------------------------

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

/** Every key a definition sends, once, in order. */
export function keysOf(inject: ProxyInject): string[] {
  return [...new Set(templatesOf(inject).flatMap((template) => [...template.matchAll(TOKEN)].map((match) => match[1]!)))];
}

/** A key as a SigV4 field holds it: `{AWS_ACCESS_KEY_ID}`, or none. */
export const soleKey = (template: string) => /^\{([A-Za-z_][A-Za-z0-9_]*)\}$/.exec(template)?.[1] ?? '';

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

export function blankDefinition(): ProxyDefinition {
  return {
    name: '',
    upstream: 'https://',
    inject: blankInject('header'),
    methods: [],
    paths: [],
    limit: { perMinute: null, perDay: null },
    placeholder: null,
    egress: null,
  };
}

/** A definition's own fields, without what the store keeps beside it. */
export function definitionOf(credential: ProxyCredential): ProxyDefinition {
  const { name, upstream, inject, methods, paths, limit, placeholder, egress } = credential;
  return { name, upstream, inject, methods, paths, limit, placeholder, egress };
}

// --- the rules, mocked -------------------------------------------------------------

/** Whether a change sends keys somewhere they did not go: a new definition, or a new upstream, injection or egress. */
export function redirects(before: ProxyDefinition | null, after: ProxyDefinition): boolean {
  return (
    before === null ||
    before.upstream !== after.upstream ||
    before.egress !== after.egress ||
    JSON.stringify(before.inject) !== JSON.stringify(after.inject)
  );
}

/** The keys of `names` the editor cannot read, each with why: sending them somewhere new is reading them. */
export function unreadable(names: readonly string[], keys: readonly SecretKey[]): { key: string; sensitive: boolean }[] {
  return names.flatMap((name) => {
    const entry = keys.find((one) => one.key === name && !one.archived);
    if (entry === undefined || entry.readable) return [];
    return [{ key: name, sensitive: entry.sensitivity === 'sensitive' }];
  });
}

/** The refusal, in words, for keys the editor cannot read. */
export function unreadableInWords(locked: readonly { key: string; sensitive: boolean }[]): string {
  const names = locked.map((one) => one.key).join(', ');
  const sensitive = locked.every((one) => one.sensitive);
  return sensitive
    ? `${names} ${locked.length === 1 ? 'is' : 'are'} sensitive: no one reads ${locked.length === 1 ? 'it' : 'them'}, so no one sends ${locked.length === 1 ? 'it' : 'them'} somewhere new.`
    : `You can't read ${names}, so you can't send ${locked.length === 1 ? 'it' : 'them'} somewhere new.`;
}

export type Field =
  | 'name'
  | 'upstream'
  | 'egress'
  | 'injectName'
  | 'template'
  | 'user'
  | 'password'
  | 'accessKeyId'
  | 'secretAccessKey'
  | 'sessionToken'
  | 'region'
  | 'service'
  | 'keys'
  | 'paths'
  | 'perMinute'
  | 'perDay'
  | 'placeholder';

export type Problems = Partial<Record<Field, string>>;

export type Checked = {
  place: ProxyPlace;
  /** The environment's keys, as its secrets list has them for the editor. */
  keys: readonly SecretKey[];
  /** The names held already: the code's, and this environment's other definitions. */
  code: readonly string[];
  others: readonly string[];
  egresses: readonly ProxyEgress[];
  /** The definition as it was, or null for a new one. */
  before: ProxyDefinition | null;
};

const NAME = /^[a-z][a-z0-9-]{0,39}$/;
const HEADER = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const FORBIDDEN_HEADERS = new Set(['host', 'content-length', 'cookie', 'connection', 'transfer-encoding']);

/** What is wrong with a definition, field by field: the editor's inline errors, and the store's refusals. */
export function definitionProblems(definition: ProxyDefinition, checked: Checked): Problems {
  const problems: Problems = {};
  const { place } = checked;
  const where = `${place.project}/${place.environment}`;

  if (!NAME.test(definition.name)) problems.name = 'Lowercase letters, digits and dashes, starting with a letter.';
  else if (checked.code.includes(definition.name)) problems.name = `The code defines ${definition.name}: pick another name.`;
  else if (checked.others.includes(definition.name)) problems.name = `${where} defines ${definition.name} already.`;

  try {
    const url = new URL(definition.upstream);
    if (url.protocol === 'http:') problems.upstream = 'Plain HTTP is for the code alone (insecureUpstreams).';
    else if (url.protocol !== 'https:' || url.hostname === '') problems.upstream = 'An https:// address.';
    else if (url.search !== '' || url.hash !== '' || url.username !== '' || url.password !== '')
      problems.upstream = 'No query, fragment or credentials: paths go under it.';
  } catch {
    problems.upstream = 'An https:// address, such as https://api.openai.com/v1.';
  }

  if (definition.egress !== null) {
    const egress = checked.egresses.find((one) => one.name === definition.egress);
    const refusal = egress === undefined ? `The code declares no egress ${definition.egress}.` : egressRefusal(egress, definition.upstream);
    if (refusal !== null) problems.egress = refusal;
  }

  const inject = definition.inject;
  const missing = (template: string) =>
    templateParts(template).flatMap((part) => ('key' in part && !checked.keys.some((entry) => entry.key === part.key && !entry.archived) ? [part.key] : []));
  const checkTemplate = (field: Field, template: string) => {
    const absent = missing(template);
    if (absent.length > 0) problems[field] = `No ${absent.join(', ')} in ${where}.`;
  };
  switch (inject.kind) {
    case 'basic':
      checkTemplate('user', inject.user);
      checkTemplate('password', inject.password);
      break;
    case 'sigv4':
      if (soleKey(inject.accessKeyId) === '') problems.accessKeyId = 'Pick the key holding the access key ID.';
      else checkTemplate('accessKeyId', inject.accessKeyId);
      if (soleKey(inject.secretAccessKey) === '') problems.secretAccessKey = 'Pick the key holding the secret.';
      else checkTemplate('secretAccessKey', inject.secretAccessKey);
      checkTemplate('sessionToken', inject.sessionToken);
      if (!/^[a-z]{2}(-[a-z]+)+-\d$/.test(inject.region)) problems.region = 'A region, such as eu-west-3.';
      if (!/^[a-z0-9-]+$/.test(inject.service)) problems.service = 'A service, such as s3.';
      break;
    default:
      if (inject.kind === 'header' && (!HEADER.test(inject.name) || FORBIDDEN_HEADERS.has(inject.name.toLowerCase())))
        problems.injectName = FORBIDDEN_HEADERS.has(inject.name.toLowerCase()) ? `coffre sets ${inject.name.toLowerCase()} itself.` : 'A header name, such as authorization.';
      else if (inject.kind !== 'header' && !/^[A-Za-z0-9_.\-[\]]+$/.test(inject.name)) problems.injectName = 'A field name, such as key.';
      checkTemplate('template', inject.template);
  }

  const named = keysOf(inject);
  if (named.length === 0 && problems.template === undefined && problems.user === undefined)
    problems.keys = 'Name at least one key: a definition sends one.';
  const locked = redirects(checked.before, definition) ? unreadable(named, checked.keys) : [];
  if (locked.length > 0) problems.keys = unreadableInWords(locked);

  const badPath = definition.paths.find((path) => !path.startsWith('/') || /\s|\.\.|[?#]/.test(path));
  if (badPath !== undefined) problems.paths = `${badPath}: a path under the upstream, starting with /.`;

  const { perMinute, perDay } = definition.limit;
  for (const [field, value] of [['perMinute', perMinute], ['perDay', perDay]] as const) {
    if (value !== null && (!Number.isInteger(value) || value < 1)) problems[field] = 'A whole number, at least 1.';
  }
  if (perMinute !== null && perDay !== null && problems.perDay === undefined && perDay < perMinute)
    problems.perDay = 'At least the minute’s limit.';

  const placeholder = definition.placeholder;
  if (placeholder !== null) {
    if (inject.kind === 'basic' || inject.kind === 'sigv4' || named.length !== 1)
      problems.placeholder = 'A placeholder shapes a header, query or field carrying one key.';
    else if (placeholder.kind === 'prefix' && !/^[A-Za-z0-9_-]+$/.test(placeholder.prefix))
      problems.placeholder = 'Letters, digits, dashes and underscores, such as sk_test_.';
    else if (placeholder.kind === 'jwt' && placeholder.claims.some((claim) => claim.trim() === ''))
      problems.placeholder = 'One claim per line.';
  }
  return problems;
}

// --- words ------------------------------------------------------------------------------

/** How a definition sends its keys, in a word, and where. */
export function injectLabel(inject: ProxyInject): string {
  return INJECT_KINDS.find((one) => one.kind === inject.kind)!.label;
}

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
      return `${inject.user} : ${inject.password === '' ? '(empty)' : inject.password}`;
    case 'sigv4':
      return `${inject.service} in ${inject.region}, ${[inject.accessKeyId, inject.secretAccessKey, inject.sessionToken].filter((one) => one !== '').join(', ')}`;
  }
}

export const methodsInWords = (methods: readonly string[]) => (methods.length === 0 ? 'Any method' : methods.join(', '));
export const pathsInWords = (paths: readonly string[]) => (paths.length === 0 ? 'any path' : paths.join(', '));

const count = new Intl.NumberFormat('en');

export function limitInWords(limit: ProxyDefinition['limit'], perService = false): string {
  if (perService) return 'Per service, in code';
  const parts = [
    limit.perMinute !== null && `${count.format(limit.perMinute)} a minute`,
    limit.perDay !== null && `${count.format(limit.perDay)} a day`,
  ].filter((part) => part !== false);
  return parts.length === 0 ? 'None' : parts.join(', ');
}

export function placeholderInWords(placeholder: ProxyPlaceholder): string {
  if (placeholder === null) return 'The handle as it is';
  if (placeholder.kind === 'prefix') return `Starts with ${placeholder.prefix}`;
  return placeholder.claims.length === 0 ? 'A JWT' : `A JWT with ${placeholder.claims.join(', ')}`;
}

export const egressInWords = (egress: string | null) => (egress === null ? 'Direct' : egress);

/** A change, field by field, in words: what the confirm step shows. A field the change leaves is left out. */
export function diffOf(before: ProxyDefinition | null, after: ProxyDefinition | null): { label: string; before: string | null; after: string | null }[] {
  const fields: [string, (definition: ProxyDefinition) => string][] = [
    ['Name', (one) => one.name],
    ['Upstream', (one) => one.upstream],
    ['Egress', (one) => egressInWords(one.egress)],
    ['Sends', (one) => `${injectLabel(one.inject)} ${injectInWords(one.inject)}`],
    ['Placeholder', (one) => placeholderInWords(one.placeholder)],
    ['Methods', (one) => methodsInWords(one.methods)],
    ['Paths', (one) => (one.paths.length === 0 ? 'Any' : one.paths.join(', '))],
    ['Limit', (one) => limitInWords(one.limit)],
  ];
  return fields.flatMap(([label, read]) => {
    const was = before === null ? null : read(before);
    const now = after === null ? null : read(after);
    return was === now ? [] : [{ label, before: was, after: now }];
  });
}
