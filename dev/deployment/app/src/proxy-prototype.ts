// The Proxy tab's store, a prototype (W260, DO NOT MERGE): each
// environment's credential-proxy definitions in this isolate's memory,
// seeded for market, beside what the code would define. Nothing here
// reaches the vault or `/use`: `/use` still serves only what coffre.ts's
// credentialProxy({ credentials }) names. A reload of the Worker (an edit
// under `pnpm dev`) starts it over from the seed.
//
// Two server functions: the page's loader reads through `read`, as the
// visitor; `write` checks what the proposal would, as the visitor too
// (through the API, their own reads), then applies every change or none.
import { createServerFn } from '@tanstack/react-start';
import { getGlobalStartContext } from '@tanstack/react-start';
import { definitionOf, definitionProblems, type CoffreClient, type ProxyChange, type ProxyConfig, type ProxyCredential, type ProxyDefinition, type ProxyEgress, type ProxyPlace, type ProxyStore } from '@coffre/ui';

/**
 * What the deployment's code would declare: `credentialProxy({ credentials,
 * egresses })`. The egresses are named transports (VPC Service bindings),
 * declaring no hosts: each reaches the one its binding was made for.
 */
const EGRESSES: ProxyEgress[] = [
  { name: 'schuman-dev', description: 'VPC Service to Schuman’s sandbox', hosts: null },
  { name: 'schuman-prod', description: 'VPC Service to Schuman’s production API', hosts: null },
];

const LONG_AGO = '2026-10-21T09:12:00.000Z';

const code = (definition: ProxyDefinition, limitPerService = false): ProxyCredential => ({
  ...definition,
  source: 'code',
  limitPerService,
  changedAt: null,
  changedBy: null,
  shadowedSince: null,
});

const CODE: ProxyCredential[] = [
  code({
    name: 'maps',
    upstream: 'https://maps.googleapis.com/maps/api',
    inject: { kind: 'query', name: 'key', template: '{MAPS_API_KEY}' },
    methods: ['GET'],
    paths: ['/geocode', '/place'],
    limit: { perMinute: null, perDay: null },
    placeholder: null,
    egress: null,
  }, true),
];

const defined = (definition: ProxyDefinition, changedAt: string, changedBy: string): ProxyCredential => ({
  ...definition,
  source: 'environment',
  limitPerService: false,
  changedAt,
  changedBy,
  shadowedSince: null,
});

const ago = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString();

function seed(environment: 'dev' | 'prod'): ProxyCredential[] {
  const dev = environment === 'dev';
  return [
    defined({
      name: 'openai',
      upstream: 'https://api.openai.com/v1',
      inject: { kind: 'header', name: 'authorization', template: 'Bearer {OPENAI_API_KEY}' },
      methods: ['GET', 'POST'],
      paths: ['/chat/completions', '/responses', '/embeddings'],
      limit: dev ? { perMinute: 60, perDay: 5_000 } : { perMinute: 600, perDay: 200_000 },
      placeholder: { kind: 'prefix', prefix: 'sk-proj-' },
      egress: null,
    }, ago(dev ? 42 : 3 * 24 * 60), 'lead@acme.example'),
    defined({
      name: 'stripe',
      upstream: 'https://api.stripe.com',
      inject: { kind: 'basic', user: '{STRIPE_SECRET_KEY}', password: '' },
      methods: [],
      paths: ['/v1'],
      limit: { perMinute: null, perDay: null },
      placeholder: null,
      egress: null,
    }, ago(dev ? 6 * 60 : 9 * 24 * 60), 'admin@acme.example'),
    // prod has neither s3 nor schuman yet: "Copy from environment…" brings schuman over, and refuses s3, whose
    // secret prod holds sensitive.
    ...(dev ? [defined({
      name: 's3',
      upstream: 'https://market-uploads-dev.s3.eu-west-3.amazonaws.com',
      inject: { kind: 'sigv4', accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', sessionToken: '', region: 'eu-west-3', service: 's3' },
      methods: ['GET', 'PUT'],
      paths: [],
      limit: { perMinute: 300, perDay: null },
      placeholder: null,
      egress: null,
    }, ago(2 * 24 * 60), 'admin@acme.example'),
    defined({
      name: 'schuman',
      upstream: 'https://dev.api.europ.schuman.io/v1',
      inject: { kind: 'header', name: 'x-api-key', template: '{SCHUMAN_API_KEY}' },
      methods: ['GET', 'POST'],
      paths: ['/companies', '/kyc'],
      limit: { perMinute: 120, perDay: 20_000 },
      placeholder: null,
      egress: 'schuman-dev',
    }, ago(18), 'lead@acme.example')] : []),
    // Made here before the code took the name: code's is served, and this one shows as shadowed.
    ...(dev
      ? [{
          ...defined({
            name: 'maps',
            upstream: 'https://maps.googleapis.com/maps/api',
            inject: { kind: 'query', name: 'key', template: '{MAPS_API_KEY}' },
            methods: [],
            paths: [],
            limit: { perMinute: null, perDay: null },
            placeholder: null,
            egress: null,
          }, LONG_AGO, 'dev@acme.example'),
          shadowedSince: '2026-10-27T16:40:00.000Z',
        }]
      : []),
  ];
}

/** Each environment's own definitions, by `project/environment`: market's seeded the first time it is read. */
const stored = new Map<string, ProxyCredential[]>();

function definitionsOf(place: ProxyPlace): ProxyCredential[] {
  const at = `${place.project}/${place.environment}`;
  if (!stored.has(at)) stored.set(at, place.project === 'market' && (place.environment === 'dev' || place.environment === 'prod') ? seed(place.environment) : []);
  return stored.get(at)!;
}

async function configOf(place: ProxyPlace): Promise<ProxyConfig> {
  // The Worker's own vars, which only the server reads: the handler's body never reaches a browser.
  const { env } = (await import('cloudflare:workers')) as unknown as { env: { COFFRE_PUBLIC_URL: string } };
  const own = definitionsOf(place);
  // By name, the code's first where both define one: a shadowed row sits under what shadows it.
  const credentials = [...CODE, ...own].sort((a, b) => a.name.localeCompare(b.name) || Number(a.source !== 'code') - Number(b.source !== 'code'));
  return { credentials, egresses: EGRESSES, useUrl: `${env.COFFRE_PUBLIC_URL.replace(/\/+$/, '')}/use` };
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

    const next = [...definitionsOf(at)];
    const now = new Date().toISOString();
    for (const { was, definition } of changes) {
      const index = was === null ? -1 : next.findIndex((one) => one.name === was);
      if (was !== null && index === -1) throw new Error(`${was} is no longer defined here: reload the page.`);
      const before = index === -1 ? null : definitionOf(next[index]!);
      if (definition === null) {
        next.splice(index, 1);
        continue;
      }
      const problems = definitionProblems(definition, {
        place: at,
        keys,
        code: CODE.map((one) => one.name),
        others: next.filter((_, other) => other !== index).map((one) => one.name),
        egresses: EGRESSES,
        before,
      });
      const first = Object.values(problems)[0];
      if (first !== undefined) throw new Error(`${definition.name}: ${first}`);
      const saved = defined(definition, now, me.principal.id);
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
