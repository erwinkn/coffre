// The Proxy tab's store, a prototype (W260, DO NOT MERGE): each
// environment's routes, signers, verifiers and database tunnels in this
// isolate's memory, seeded for market, beside what the code would define.
// Nothing here reaches the vault or `/use`: `/use` still serves only what
// coffre.ts's credentialProxy({ … }) names. A reload of the Worker (an edit
// under `pnpm dev`) starts it over from the seed.
//
// Two server functions: the page's loader reads through `read`, as the
// visitor; `write` checks what the proposal would, as the visitor too
// (through the API, their own reads), then applies every change or none.
import { createServerFn } from '@tanstack/react-start';
import { getGlobalStartContext } from '@tanstack/react-start';
import {
  definitionProblems,
  normalized,
  type CoffreClient,
  type ProxyChange,
  type ProxyConfig,
  type ProxyCredential,
  type ProxyDefinition,
  type ProxyPlace,
  type ProxyStore,
  type ProxyTransport,
} from '@coffre/ui';

/**
 * What the deployment's code would declare beside its items, by name:
 * `egresses` (VPC Service bindings, for routes) and `networks` (VPC
 * Network bindings, for tunnels). None names hosts: each reaches the one
 * its binding was made for.
 */
const EGRESSES: ProxyTransport[] = [
  { name: 'schuman-dev', description: 'VPC Service to Schuman’s sandbox', hosts: null },
  { name: 'schuman-prod', description: 'VPC Service to Schuman’s production API', hosts: null },
];
const NETWORKS: ProxyTransport[] = [{ name: 'replica-net', description: 'VPC Network to the private read replica', hosts: null }];

const NO_LIMIT = { perMinute: null, perDay: null };

/**
 * The code's items. Each serves every environment unless its `environments`
 * names some, by path, as the instance knows them (the config is the whole
 * instance's, so `prod` alone would be every project's), the shape this
 * prototype proposes: `tunnels: { replica: postgres('REPLICA_URL', { hosts:
 * […], connect: env.REPLICA_NET, environments: ['market/prod'] }) }`.
 */
const code = (definition: ProxyDefinition, options: { environments?: string[]; limitPerService?: boolean } = {}): ProxyCredential => ({
  ...definition,
  source: 'code',
  environments: options.environments ?? null,
  limitPerService: options.limitPerService ?? false,
  changedAt: null,
  changedBy: null,
});

const CODE: ProxyCredential[] = [
  code(
    {
      kind: 'route',
      name: 'maps',
      upstream: 'https://maps.googleapis.com/maps/api',
      inject: [{ kind: 'query', name: 'key', template: '{MAPS_API_KEY}' }],
      allow: [{ methods: ['GET'], path: '/geocode' }, { methods: ['GET'], path: '/place' }],
      limit: NO_LIMIT,
      placeholder: null,
      egress: null,
    },
    { limitPerService: true },
  ),
  // As coffre.ts has it: `tunnels: { db: postgres('DATABASE_URL') }`.
  code({ kind: 'tunnel', name: 'db', key: 'DATABASE_URL', hosts: [], network: null }),
  // As the plugin's own header has it: `signers: { 'dfns-key': privateKey('DFNS_PRIVATE_KEY') }`.
  code({ kind: 'signer', name: 'dfns-key', signer: { kind: 'private-key', key: 'DFNS_PRIVATE_KEY' }, limit: { perMinute: 10, perDay: null } }),
  // Scoped: prod's private replica, through its VPC Network, and nowhere else.
  code({ kind: 'tunnel', name: 'replica', key: 'REPLICA_URL', hosts: ['10.0.1.5'], network: 'replica-net' }, { environments: ['market/prod'] }),
];

const defined = (definition: ProxyDefinition, changedAt: string, changedBy: string): ProxyCredential => ({
  ...definition,
  source: 'environment',
  environments: null,
  limitPerService: false,
  changedAt,
  changedBy,
});

const ago = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString();

function seed(environment: 'dev' | 'prod'): ProxyCredential[] {
  const dev = environment === 'dev';
  const items: ProxyCredential[] = [
    defined(
      {
        kind: 'route',
        name: 'openai',
        upstream: 'https://api.openai.com/v1',
        inject: [
          { kind: 'header', name: 'authorization', template: 'Bearer {OPENAI_API_KEY}' },
          { kind: 'header', name: 'openai-organization', template: '{OPENAI_ORG_ID}' },
        ],
        allow: [
          { methods: ['POST'], path: '/chat/completions' },
          { methods: ['POST'], path: '/responses' },
          { methods: ['GET'], path: '/models' },
        ],
        limit: dev ? { perMinute: 60, perDay: 5_000 } : { perMinute: 600, perDay: 200_000 },
        placeholder: null,
        egress: null,
      },
      ago(dev ? 42 : 3 * 24 * 60),
      'lead@acme.example',
    ),
    defined(
      {
        kind: 'route',
        name: 'stripe',
        upstream: 'https://api.stripe.com',
        inject: [{ kind: 'basic', user: '{STRIPE_SECRET_KEY}', password: '' }],
        allow: [{ methods: [], path: '/v1' }],
        limit: NO_LIMIT,
        placeholder: null,
        egress: null,
      },
      ago(dev ? 6 * 60 : 9 * 24 * 60),
      'admin@acme.example',
    ),
    defined(
      {
        kind: 'verifier',
        name: 'yousign',
        hmac: { key: 'YOUSIGN_WEBHOOK_SECRET', encoding: 'hex', prefix: 'sha256=', maxBytes: null },
        limit: NO_LIMIT,
      },
      ago(dev ? 3 * 24 * 60 : 4 * 24 * 60),
      'lead@acme.example',
    ),
  ];
  if (!dev) return items;
  return [
    ...items,
    defined(
      {
        kind: 'route',
        name: 's3',
        upstream: 'https://market-uploads-dev.s3.eu-west-3.amazonaws.com',
        inject: [{ kind: 'sigv4', accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', sessionToken: '', region: 'eu-west-3', service: 's3' }],
        allow: [{ methods: ['GET', 'PUT'], path: '/' }],
        limit: { perMinute: 300, perDay: null },
        placeholder: null,
        egress: null,
      },
      ago(2 * 24 * 60),
      'admin@acme.example',
    ),
    defined(
      {
        kind: 'route',
        name: 'schuman',
        upstream: 'https://dev.api.europ.schuman.io/v1',
        inject: [{ kind: 'header', name: 'x-api-key', template: '{SCHUMAN_API_KEY}' }],
        allow: [
          { methods: ['GET'], path: '/companies/*/documents/**' },
          { methods: ['POST'], path: '/kyc' },
        ],
        limit: { perMinute: 120, perDay: 20_000 },
        placeholder: null,
        egress: 'schuman-dev',
      },
      ago(18),
      'lead@acme.example',
    ),
    defined(
      {
        kind: 'signer',
        name: 'partner-webhooks',
        signer: { kind: 'hmac', key: 'PARTNER_WEBHOOK_SECRET', encoding: 'base64', prefix: '', maxBytes: 65_536 },
        limit: { perMinute: 600, perDay: null },
      },
      ago(5 * 60),
      'admin@acme.example',
    ),
    // Made here before the code took the name: the code's is served, and this one is neither served nor shown.
    defined(
      {
        kind: 'route',
        name: 'maps',
        upstream: 'https://maps.googleapis.com/maps/api',
        inject: [{ kind: 'query', name: 'key', template: '{MAPS_API_KEY}' }],
        allow: [],
        limit: NO_LIMIT,
        placeholder: null,
        egress: null,
      },
      '2026-10-21T09:12:00.000Z',
      'dev@acme.example',
    ),
  ];
}

/** Each environment's own items, by `project/environment`: market's seeded the first time it is read. */
const stored = new Map<string, ProxyCredential[]>();

function itemsOf(place: ProxyPlace): ProxyCredential[] {
  const at = `${place.project}/${place.environment}`;
  if (!stored.has(at)) stored.set(at, place.project === 'market' && (place.environment === 'dev' || place.environment === 'prod') ? seed(place.environment) : []);
  return stored.get(at)!;
}

/** The code's items this environment gets: those for every environment, and those that name it. */
const codeFor = (place: ProxyPlace) => CODE.filter((one) => one.environments === null || one.environments.includes(`${place.project}/${place.environment}`));

async function configOf(place: ProxyPlace): Promise<ProxyConfig> {
  // The Worker's own vars, which only the server reads: the handler's body never reaches a browser.
  const { env } = (await import('cloudflare:workers')) as unknown as { env: { COFFRE_PUBLIC_URL: string } };
  const fromCode = codeFor(place);
  // A name the code takes hides the environment's own: shown once, locked, with the code's values.
  const own = itemsOf(place).filter((one) => !fromCode.some((item) => item.name === one.name));
  const order = { route: 0, tunnel: 1, signer: 2, verifier: 3 };
  const credentials = [...fromCode, ...own].sort((a, b) => order[a.kind] - order[b.kind] || a.name.localeCompare(b.name));
  return { credentials, egresses: EGRESSES, networks: NETWORKS, useUrl: `${env.COFFRE_PUBLIC_URL.replace(/\/+$/, '')}/use` };
}

/** The visitor's API client, which coffre's middleware put in the request's context. */
function visitor(): CoffreClient {
  return (getGlobalStartContext() as unknown as { client: CoffreClient }).client;
}

const place = (input: unknown): ProxyPlace => {
  const { project, environment } = input as Partial<ProxyPlace>;
  if (typeof project !== 'string' || typeof environment !== 'string') throw new Error('Expected a project and an environment.');
  return { project, environment };
};

const readProxy = createServerFn({ method: 'GET' })
  .validator(place)
  .handler(({ data }) => configOf(data));

const writeProxy = createServerFn({ method: 'POST' })
  .validator((input: unknown) => {
    const { changes } = input as { changes?: unknown };
    if (!Array.isArray(changes)) throw new Error('Expected changes.');
    return { ...place(input), changes: changes as ProxyChange[] };
  })
  .handler(async ({ data }) => {
    const { changes, ...at } = data;
    const client = visitor();
    // As the visitor: the environment's keys they may list, whether they hold `proxy.edit` (mocked: an Owner
    // covering the place, the one the API lets loosen a value), and who they are, for the row.
    const [secrets, me] = await Promise.all([client.secrets.list(`${at.project}/${at.environment}`), client.me()]);
    if (!('keys' in secrets)) throw new Error(`${at.project}/${at.environment} is closed to you.`);
    if (secrets.loosenable !== true) throw new Error(`Changing ${at.project}/${at.environment}'s proxy needs proxy.edit, which Owners of ${at.project} and of the instance hold.`);
    const keys = secrets.keys.filter((entry) => !entry.archived);
    const fromCode = codeFor(at).map((one) => one.name);

    const next = [...itemsOf(at)];
    const now = new Date().toISOString();
    for (const { was, definition } of changes) {
      const index = was === null ? -1 : next.findIndex((one) => one.name === was);
      if (was !== null && index === -1) throw new Error(`${was} is no longer here: reload the page.`);
      const before = index === -1 ? null : next[index]!;
      if (definition === null) {
        next.splice(index, 1);
        continue;
      }
      const { problems } = definitionProblems(definition, {
        place: at,
        keys,
        owner: true,
        code: fromCode,
        others: next.filter((_, other) => other !== index).map((one) => one.name),
        egresses: EGRESSES,
        networks: NETWORKS,
        before,
      });
      const first = Object.values(problems)[0];
      if (first !== undefined) throw new Error(`${definition.name}: ${first}`);
      // Every change is audited; one that routes a sensitive key says so (the prototype logs nothing).
      const saved = defined(normalized(definition), now, me.principal.id);
      if (index === -1) next.push(saved);
      else next[index] = saved;
    }
    stored.set(`${at.project}/${at.environment}`, next);
    return configOf(at);
  });

/** The store the Proxy tab reads and writes, through the two functions above. */
export const proxyStore: ProxyStore = {
  read: (at) => readProxy({ data: at }),
  write: (at, changes) => writeProxy({ data: { ...at, changes } }),
};
