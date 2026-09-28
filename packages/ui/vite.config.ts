import { fileURLToPath } from 'node:url';

import { cloudflare } from '@cloudflare/vite-plugin';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import viteReact from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));

// Two jobs, one config:
//
// - `vite build` builds `@coffre/ui`: `src/entry.ts` and its pages alone
//   (wrangler.jsonc), with their static files under `/_coffre/assets/`.
// - `vite dev` runs a whole deployment of coffre around the pages
//   (dev/wrangler.jsonc, dev/app.ts), with its vault beside it
//   (dev/vault.wrangler.jsonc). It imports the packages' sources rather than
//   their builds, so an edit to the server or the vault reloads like one to
//   a page.
export default defineConfig(({ command }) => {
  const dev = command === 'serve';
  return {
    server: {
      // scripts/dev.sh checks 127.0.0.1 and the seeded links point there, so bind
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

    resolve: dev
      ? {
          alias: {
            '@coffre/server/cloudflare': here('../server/src/cloudflare.ts'),
            '@coffre/vault/cloudflare': here('../vault/src/cloudflare.ts'),
            '@coffre/ui': here('src/entry.ts'),
          },
        }
      : {},

    build: {
      // A deployment serves these from its own origin, beside `/api` and
      // `/auth`; the prefix keeps the two apart.
      assetsDir: '_coffre/assets',
      // Vite inlines files under 4 KiB as data: URLs, which caught one small
      // font subset. The Content-Security-Policy takes fonts from coffre alone.
      assetsInlineLimit: (file) => (/\.woff2?$/.test(file) ? false : undefined),
    },

    plugins: [
      cloudflare(
        dev
          ? {
              viteEnvironment: { name: 'ssr' },
              configPath: 'dev/wrangler.jsonc',
              auxiliaryWorkers: [{ configPath: 'dev/vault.wrangler.jsonc' }],
              // Where local Durable Objects keep their SQLite, the vault's.
              // Its grants and checkpoints belong with one database, so
              // scripts/dev.sh empties it before it seeds.
              persistState: process.env.COFFRE_STATE_DIR ? { path: process.env.COFFRE_STATE_DIR } : true,
            }
          : { viteEnvironment: { name: 'ssr' }, configPath: 'wrangler.jsonc' },
      ),
      // Generates src/routeTree.gen.ts from src/routes, and wires the SSR
      // server. Must come before the React plugin.
      tanstackStart(),
      viteReact(),
    ],
  };
});
