// The built Workers app as `wrangler dev` can run it, for conformance and
// for the restore drill (scripts/restore-drill.sh), which runs this file:
//
//   node packages/conformance/src/draining.ts examples/workers/app/dist/server
//
// prints the config to pass `wrangler dev -c`.
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

/**
 * The built app as `wrangler dev` can run it: its own build, behind an entry
 * that, once the app has answered, reads whatever the request still sends
 * before passing the answer on. Locally, and only there, a Worker built
 * unbundled with static assets may fail the request after one whose body it
 * left unread, which every refusal does: wrangler retries a GET, not a POST
 * (cloudflare/workers-sdk#15203). Reading it later, after the answer, is too
 * late; deployed, Cloudflare discards such a body, as
 * `vite dev` and `vite preview` do. The app itself must never wait so on what
 * a caller sends; this harness sends only bodies that end.
 *
 * The entry is also a Worker of the account that binds the app's
 * `CoffreWorkload` (docs/design/workload-access.md, section 9.2), each
 * binding with props of its own (`BINDINGS`): `/__conformance/binding`
 * calls one, for the check that such a Worker gets nothing
 * (checks/cloudflare.ts). The entry and its config are written beside the
 * build, which the next `vite build` replaces: nothing of them deploys.
 */
/** The entry's bindings of the app's `CoffreWorkload`, by name, and the props each sets: none, another field, a service no binding trusts. */
export const BINDINGS = {
  NO_PROPS: null,
  EXTRA: { service: 'conformance-edge', place: 'market/prod' },
  UNBOUND: { service: 'conformance-edge' },
} as const;

export function drainingConfig(server: string): string {
  writeFileSync(
    join(server, 'conformance.js'),
    [
      "import app from './index.js';",
      // The app's other exports, its Durable Object classes (`CoffreSockets`), which its config binds by name.
      "export * from './index.js';",
      'export default {',
      '  ...app,',
      '  async fetch(request, env, ctx) {',
      "    const url = new URL(request.url);",
      "    if (url.pathname === '/__conformance/binding') return called(env[`CONFORMANCE_${url.searchParams.get('binding')}`], url.searchParams);",
      '    const response = await app.fetch(request, env, ctx);',
      '    if (request.body !== null && !request.bodyUsed) await request.arrayBuffer().catch(() => {});',
      '    return response;',
      '  },',
      '};',
      '',
      '/** What a call through one of the bindings returned, or threw: a value, an answer, or a refusal. */',
      'async function called(binding, asked) {',
      "  if (binding === undefined) return new Response('no such binding', { status: 404 });",
      '  try {',
      "    if (asked.get('op') === 'sign') return Response.json({ answer: await binding.sign('signer', 'challenge') });",
      "    const answered = await binding.fetch(new Request(`https://coffre${asked.get('path') ?? '/use/conformance/credential'}`));",
      '    return Response.json({ status: answered.status, body: await answered.text() });',
      '  } catch (error) {',
      '    return Response.json({ threw: String(error?.message ?? error) });',
      '  }',
      '}',
      '',
    ].join('\n'),
  );
  const config = JSON.parse(readFileSync(join(server, 'wrangler.json'), 'utf8')) as { name: string; services?: unknown[] } & Record<string, unknown>;
  const services = Object.entries(BINDINGS).map(([name, props]) => ({ binding: `CONFORMANCE_${name}`, service: config.name, entrypoint: 'CoffreWorkload', ...(props === null ? {} : { props }) }));
  const path = join(server, 'conformance.json');
  writeFileSync(path, JSON.stringify({ ...config, main: 'conformance.js', services: [...(config.services ?? []), ...services] }));
  return path;
}

if (import.meta.main) console.log(drainingConfig(resolve(process.argv[2]!)));
