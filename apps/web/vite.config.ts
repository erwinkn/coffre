import { defineConfig } from 'vite';
import viteReact from '@vitejs/plugin-react';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import { cloudflare } from '@cloudflare/vite-plugin';
import { instanceConfig } from './instance.ts';

export default defineConfig({
  server: {
    port: 3000,
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

  build: {
    // Vite inlines files under 4 KiB as data: URLs, which caught one small
    // font subset. The Content-Security-Policy takes fonts from coffre alone.
    assetsInlineLimit: (file) => (/\.woff2?$/.test(file) ? false : undefined),
  },

  plugins: [
    cloudflare({ viteEnvironment: { name: 'ssr' }, config: instanceConfig(process.env) }),
    // Generates src/routeTree.gen.ts from src/routes, and wires the SSR
    // server. Must come before the React plugin.
    tanstackStart(),
    viteReact(),
  ],
});
