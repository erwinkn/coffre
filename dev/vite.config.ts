import { fileURLToPath } from 'node:url';

import { cloudflare } from '@cloudflare/vite-plugin';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import viteReact from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));

// `vite dev` of a whole deployment of coffre around the pages
// (deployment/wrangler.jsonc, deployment/app.ts), with its vault beside it
// (deployment/vault.wrangler.jsonc). It imports the packages' sources rather
// than their builds, so an edit to the server or the vault reloads like one
// to a page. packages/ui/vite.config.ts builds the pages alone.
export default defineConfig({
  // The pages' package, as when it builds itself: TanStack Start finds
  // src/routes there and writes src/routeTree.gen.ts beside them.
  root: here('../packages/ui'),

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

  resolve: {
    alias: {
      '@coffre/server/cloudflare': here('../packages/server/src/cloudflare.ts'),
      '@coffre/vault/cloudflare': here('../packages/vault/src/cloudflare.ts'),
      '@coffre/ui': here('../packages/ui/src/entry.ts'),
    },
  },

  plugins: [
    cloudflare({
      viteEnvironment: { name: 'ssr' },
      configPath: here('deployment/wrangler.jsonc'),
      auxiliaryWorkers: [{ configPath: here('deployment/vault.wrangler.jsonc') }],
      // Where local Durable Objects keep their SQLite, the vault's. Its
      // grants and checkpoints belong with one database, so start.sh empties
      // it before it seeds.
      persistState: { path: process.env.COFFRE_STATE_DIR ?? here('.wrangler/state') },
    }),
    // Generates src/routeTree.gen.ts from src/routes, and wires the SSR
    // server. Must come before the React plugin.
    tanstackStart(),
    viteReact(),
  ],
});
