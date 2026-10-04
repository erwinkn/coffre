import { fileURLToPath } from 'node:url';

import { cloudflare } from '@cloudflare/vite-plugin';
import { coffre } from '@coffre/ui/vite';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import viteReact from '@vitejs/plugin-react';
import { defaultClientConditions, defaultServerConditions, defineConfig, type Plugin } from 'vite';

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));

/**
 * The packages' sources rather than their builds, in every environment: each
 * package's `exports` maps the `coffre:source` condition to its `src/`. It
 * runs last, to add to the conditions the Workers' environments already have.
 */
function workspaceSources(): Plugin {
  return {
    name: 'coffre:workspace-sources',
    enforce: 'post',
    configEnvironment(name, config) {
      const consumer = config.consumer ?? (name === 'client' ? 'client' : 'server');
      const conditions =
        config.resolve?.conditions ?? (consumer === 'client' ? defaultClientConditions : defaultServerConditions);
      config.resolve = { ...config.resolve, conditions: ['coffre:source', ...conditions] };
    },
  };
}

// `vite dev` of a deployment of coffre shaped like examples/workers: this
// app, its pages from @coffre/ui, and its vault beside it (../vault). Two
// things differ, for the loop: the packages' sources rather than their
// builds, so an edit to the server, the vault or a page reloads; and Start
// generating the pages' route tree from packages/ui/src/routes, as it does
// in an app's own src/routes, so a route edited or added reloads too.
export default defineConfig({
  server: {
    // start.sh checks 127.0.0.1 and the seeded links point there, so bind
    // both loopback names rather than only localhost.
    host: '127.0.0.1',
    // The Agentation feedback toolbar (dev only) talks to its annotation
    // server through the app's own origin, so it also works when the dev
    // server is reached through a tunnel, where the browser's localhost is
    // not this machine's.
    proxy: {
      '/_agentation': {
        target: 'http://127.0.0.1:4747',
        rewrite: (path) => path.replace(/^\/_agentation/, ''),
      },
    },
  },

  plugins: [
    cloudflare({
      viteEnvironment: { name: 'ssr' },
      auxiliaryWorkers: [{ configPath: here('../vault/wrangler.jsonc') }],
      // Where wrangler keeps its local state.
      persistState: { path: process.env.COFFRE_STATE_DIR ?? here('../../.wrangler/state') },
    }),
    tanstackStart({
      router: {
        routesDirectory: here('../../../packages/ui/src/routes'),
        generatedRouteTree: here('../../../packages/ui/src/routeTree.gen.ts'),
      },
    }),
    viteReact(),
    coffre(),
    workspaceSources(),
  ],
});
