// Each MCP change tool says what its route answers for a fresh check (`Change.fresh`), so that an approval of a change
// that needs one is refused before it is decided, for a person with no passkey (passkeys.md, section 4.5). That is a
// copy of `FRESH_ROUTES`: this holds each tool's copy to the route its change actually calls.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createClient, type RouteKey } from '@coffre/client';
import { FRESH_ROUTES, freshAnswer, type Asked } from '../src/api/fresh-routes.ts';
import { routeParts } from '../src/api/router.ts';
import { CHANGE_TOOLS, SHOW_VALUE } from '../src/mcp/changes.ts';

const SCOPE = { state: { scope: { 'market/dev': 'developer' } }, details: [] };
const BINDING = '00000000-0000-4000-8000-000000000001';

/** Arguments a person might approve, one set per tool; `given` is what Approve hands `apply`. */
const SAMPLES: Record<string, { args: Record<string, unknown>; given?: Record<string, unknown> }> = {
  show_secret_value: { args: { secret: 'market/dev/KEY' } },
  request_secret_value: { args: { secret: 'market/dev/KEY' }, given: { value: 'v' } },
  generate_secret_value: { args: { secret: 'market/dev/KEY' } },
  rename_secret: { args: { secret: 'market/dev/KEY', newKey: 'OTHER' } },
  archive_secret: { args: { secret: 'market/dev/KEY' } },
  unarchive_secret: { args: { secret: 'market/dev/KEY' } },
  restore_secret_version: { args: { secret: 'market/dev/KEY', version: 1 } },
  create_project: { args: { project: 'market', name: 'Market' } },
  create_environment: { args: { environment: 'market/dev', name: 'Dev' } },
  set_access: { args: { member: 'user:ada@acme.example', changes: { market: 'developer' } } },
  admit_member: { args: { member: 'user:ada@acme.example' } },
  offboard_member: { args: { member: 'user:ada@acme.example' } },
  issue_service_token: { args: { service: 'ci', expiresInDays: 30 }, given: { replaced: SCOPE } },
  revoke_service_token: { args: { service: 'ci', id: BINDING } },
  trust_workload: { args: { service: 'ci', profile: 'github', claims: { repository_id: '1' } }, given: { replaced: SCOPE } },
  untrust_workload: { args: { service: 'ci', id: BINDING } },
};

const SHAPES = (Object.keys(FRESH_ROUTES) as RouteKey[]).map((key) => {
  const [method, shape] = key.split(' ') as [string, string];
  return { key, method, segments: shape.split('/').filter(Boolean) };
});

/** The route a request means, as the router picks it: a literal segment beats a parameter, the first place two differ. */
function routeOf(request: Request): { key: RouteKey; params: Record<string, string> } {
  const parts = routeParts(new URL(request.url).pathname);
  const fits = SHAPES.flatMap(({ key, method, segments }) => {
    if (method !== request.method || segments.length !== parts.length) return [];
    const params: Record<string, string> = {};
    const ok = segments.every((segment, index) => (segment.startsWith(':') ? ((params[segment.slice(1)] = parts[index]!), true) : segment === parts[index]));
    return ok ? [{ key, segments, params }] : [];
  });
  fits.sort((a, b) => {
    const index = a.segments.findIndex((segment, at) => segment.startsWith(':') !== b.segments[at]!.startsWith(':'));
    return index === -1 ? 0 : a.segments[index]!.startsWith(':') ? 1 : -1;
  });
  assert.ok(fits[0], `no route for ${request.method} ${request.url}`);
  return fits[0];
}

/** The first request a tool's change makes that is not a read: what Approve's change goes through. */
async function changeOf(name: string, run: (api: ReturnType<typeof createClient>) => Promise<unknown>) {
  let made: { key: RouteKey; asked: Asked<RouteKey> } | null = null;
  const api = createClient({
    url: 'https://coffre.test',
    transport: async (request) => {
      if (made === null && request.method !== 'GET') {
        const { key, params } = routeOf(request);
        const url = new URL(request.url);
        const body = request.body === null ? undefined : await request.json();
        made = { key, asked: { params, input: body, query: Object.fromEntries(url.searchParams) } as Asked<RouteKey> };
      }
      return Response.json({ error: 'internal', message: 'stopped here' }, { status: 500 });
    },
  });
  await run(api).catch(() => {});
  assert.ok(made, `${name} made no change`);
  return made as { key: RouteKey; asked: Asked<RouteKey> };
}

test('each MCP change tool asks for a fresh check exactly when the route its change calls does', async () => {
  const tools = [SHOW_VALUE, ...CHANGE_TOOLS];
  assert.deepEqual(tools.map((tool) => tool.name).sort(), Object.keys(SAMPLES).sort(), 'every change tool has a sample');
  for (const tool of tools) {
    const { args, given = {} } = SAMPLES[tool.name]!;
    const { key, asked } = await changeOf(tool.name, (api) => tool.change!.apply(api, tool.input.parse(args), given));
    // A connection's session is neither a browser's nor a terminal's: it is the approval's touch that stands for it.
    const answer = freshAnswer(key, asked, { session: null });
    // `handler`: the route decides from what it reads, and asks a check only of a write no tool sends (a sensitive
    // value made a secret in place); were one sent, the route's own check would still refuse it.
    const expected = answer === 'always' ? 'always' : answer === 'never' || answer === 'handler' ? 'never' : answer;
    assert.equal(tool.change!.fresh, expected, `${tool.name} goes through ${key}, which answers ${answer}`);
  }
});
