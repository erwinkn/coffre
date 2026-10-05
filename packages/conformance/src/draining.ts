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
 * a caller sends; this harness sends only bodies that end. The entry and its
 * config are written beside the build, which the next `vite build`
 * replaces: nothing of them deploys.
 */
export function drainingConfig(server: string): string {
  writeFileSync(
    join(server, 'conformance.js'),
    [
      "import app from './index.js';",
      'export default {',
      '  ...app,',
      '  async fetch(request, env, ctx) {',
      '    const response = await app.fetch(request, env, ctx);',
      '    if (request.body !== null && !request.bodyUsed) await request.arrayBuffer().catch(() => {});',
      '    return response;',
      '  },',
      '};',
      '',
    ].join('\n'),
  );
  const config = JSON.parse(readFileSync(join(server, 'wrangler.json'), 'utf8')) as Record<string, unknown>;
  const path = join(server, 'conformance.json');
  writeFileSync(path, JSON.stringify({ ...config, main: 'conformance.js' }));
  return path;
}

if (import.meta.main) console.log(drainingConfig(resolve(process.argv[2]!)));
