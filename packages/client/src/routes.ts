// The API's routes, as checks call them: `coffre verify instance` and the
// local conformance run. Both tables are typed over the route map, so a
// route added to the server fails the typecheck here until it is listed,
// and from then on every check that walks a table covers it: the anonymous
// refusal, the canary scans, the cross-site one.
import type { Params, RouteInput, RouteKey } from './index.ts';

export type GetKey = Extract<RouteKey, `GET ${string}`>;

/** Each GET route, with what to ask it. */
export type GetCalls = { [K in GetKey]: { params: Params<K>; input?: RouteInput<K> }[] };

/** What the GET routes are asked about: places, secrets and members to name. */
export type Subjects = {
  places: { project: string; environment: string }[];
  /** Secrets whose history to ask for. */
  secrets: { project: string; environment: string; key: string }[];
  /** `user:…` and `token:…`. */
  members: string[];
  /** Tokens whose credentials to list. */
  services: string[];
};

export function getCalls({ places, secrets, members, services }: Subjects): GetCalls {
  const first = places[0];
  return {
    'GET /me': [{ params: {} }],
    'GET /projects': [{ params: {} }],
    'GET /secrets/:project/:environment': places.map((params) => ({ params })),
    'GET /projects/:project/:environment/missing': places.map((params) => ({ params })),
    'GET /personal/:project': [...new Set(places.map((params) => params.project))].map((project) => ({ params: { project } })),
    'GET /projects/:project/:environment/version': places.map((params) => ({ params })),
    'GET /secrets/:project/:environment/:key/versions': secrets.map((params) => ({ params })),
    'GET /members': [
      { params: {} },
      ...(first === undefined ? [] : [{ params: {}, input: { path: `${first.project}/${first.environment}` } }]),
    ],
    'GET /references': [
      ...(first === undefined ? [] : [{ params: {}, input: { path: first.project } }, { params: {}, input: { path: `${first.project}/${first.environment}` } }]),
    ],
    'GET /members/:member': members.map((member) => ({ params: { member } })),
    'GET /members/:member/access': members.map((member) => ({ params: { member } })),
    'GET /members/:member/tokens': services.map((member) => ({ params: { member } })),
    'GET /members/:member/bindings': services.map((member) => ({ params: { member } })),
    'GET /members/:member/bindings/:id/enrollments': services.map((member) => ({ params: { member, id: '00000000-0000-4000-8000-000000000000' } })),
    'GET /workloads/lookup': [{ params: {}, input: { github: 'acme/api' } }],
    'GET /workloads/repositories': [{ params: {} }],
    'GET /freezes': [{ params: {} }],
    'GET /roles': [{ params: {} }],
    'GET /settings': [{ params: {} }],
    'GET /sessions': [{ params: {} }],
    'GET /identities': [{ params: {} }],
    'GET /device-logins/:code': [{ params: { code: 'BCDF-GHJK' } }],
    'GET /oauth/authorizations': [{ params: {}, input: { client_id: '00000000-0000-4000-8000-000000000000', redirect_uri: 'https://conformance.invalid/callback' } }],
    'GET /approvals/:id': [{ params: { id: '00000000-0000-4000-8000-000000000000' } }],
    'GET /apps': [{ params: {} }],
    'GET /audit': [{ params: {}, input: { limit: 500 } }, { params: {}, input: { limit: 500, detail: '1' } }],
    'GET /audit/verification': [{ params: {} }],
    'GET /audit/trees': [{ params: {} }],
    'GET /audit/keys': [{ params: {} }],
  };
}

/** Each GET call as a URL, with its parameters and query filled in. */
export function getUrls(origin: string, calls: GetCalls): { key: GetKey; url: string }[] {
  const urls: { key: GetKey; url: string }[] = [];
  for (const [key, asks] of Object.entries(calls) as [GetKey, { params: Record<string, string>; input?: object }[]][]) {
    for (const { params, input } of asks) urls.push({ key, url: address(origin, key, params, input) });
  }
  return urls;
}

/** Every route, whatever its method. */
const EVERY_ROUTE: { [K in RouteKey]: true } = {
  'GET /me': true,
  'GET /projects': true,
  'PUT /projects/:project': true,
  'PATCH /projects/:project': true,
  'DELETE /projects/:project': true,
  'PUT /projects/:project/:environment': true,
  'PATCH /projects/:project/:environment': true,
  'DELETE /projects/:project/:environment': true,
  'GET /projects/:project/:environment/missing': true,
  'GET /personal/:project': true,
  'GET /projects/:project/:environment/version': true,
  'PATCH /projects/:project/:environment/dismissals': true,
  'GET /secrets/:project/:environment': true,
  'PATCH /secrets/:project/:environment': true,
  'PATCH /secrets/:project/:environment/:key': true,
  'GET /secrets/:project/:environment/:key/versions': true,
  'POST /secrets/:project/:environment/:key/restore': true,
  'DELETE /secrets/:project/:environment/:key/reference': true,
  'PATCH /folders/:folder': true,
  'DELETE /folders/:folder': true,
  'PATCH /folders/:project/:environment/:folder': true,
  'DELETE /folders/:project/:environment/:folder': true,
  'GET /references': true,
  'POST /reveals': true,
  'GET /members': true,
  'GET /members/:member': true,
  'GET /members/:member/access': true,
  'PUT /members/:member': true,
  'DELETE /members/:member': true,
  'GET /members/:member/tokens': true,
  'POST /members/:member/tokens': true,
  'DELETE /members/:member/tokens/:id': true,
  'POST /handles': true,
  'DELETE /handles/:id': true,
  'GET /members/:member/bindings': true,
  'POST /members/:member/bindings': true,
  'POST /members/:member/bindings/keys': true,
  'DELETE /members/:member/bindings/:id': true,
  'GET /members/:member/bindings/:id/enrollments': true,
  'POST /members/:member/bindings/:id/enrollments': true,
  'POST /members/:member/bindings/:id/enrollments/:enrollment/promote': true,
  'POST /members/:member/tokens/:id/approve': true,
  'GET /freezes': true,
  'POST /freezes': true,
  'DELETE /freezes/:target': true,
  'GET /workloads/lookup': true,
  'GET /workloads/repositories': true,
  'GET /roles': true,
  'PUT /roles/:role': true,
  'DELETE /roles/:role': true,
  'PUT /instance-roles/:role': true,
  'DELETE /instance-roles/:role': true,
  'GET /settings': true,
  'PUT /settings': true,
  'PATCH /access/:member': true,
  'GET /sessions': true,
  'DELETE /sessions/:id': true,
  'GET /identities': true,
  'DELETE /identities/:id': true,
  'GET /device-logins/:code': true,
  'POST /device-logins/:code': true,
  'GET /oauth/authorizations': true,
  'POST /oauth/authorizations': true,
  'GET /approvals/:id': true,
  'POST /approvals/:id': true,
  'GET /apps': true,
  'DELETE /apps/:id': true,
  'GET /audit': true,
  'GET /audit/verification': true,
  'GET /audit/trees': true,
  'GET /audit/keys': true,
  'POST /audit/loss': true,
};

/**
 * Every route as a method and a URL, each parameter a made-up value: what
 * a caller with no right to any of them would send.
 */
export function everyRoute(origin: string): { key: RouteKey; method: string; url: string }[] {
  return (Object.keys(EVERY_ROUTE) as RouteKey[]).map((key) => {
    const [method, pattern] = key.split(' ') as [string, string];
    const path = pattern.replace(/:(\w+)/g, (_, name: string) =>
      encodeURIComponent(name === 'member' ? 'token:conformance-nobody' : 'conformance-nobody'),
    );
    return { key, method, url: `${origin}/api${path}` };
  });
}

function address(origin: string, key: GetKey, params: Record<string, string>, input: object | undefined): string {
  const path = key.slice('GET '.length).replace(/:(\w+)/g, (_, name: string) => encodeURIComponent(params[name]!));
  const url = new URL(`${origin}/api${path}`);
  for (const [name, value] of Object.entries(input ?? {})) url.searchParams.set(name, String(value));
  return url.href;
}
