import { cloudflare } from '@cloudflare/vite-plugin';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import viteReact from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// Builds `@coffre/ui`: `src/entry.ts` and its pages alone (wrangler.jsonc),
// with their static files under `/_coffre/assets/`. `pnpm dev` runs these
// pages inside a whole deployment instead, with dev/vite.config.ts.
export default defineConfig({
  build: {
    // A deployment serves these from its own origin, beside `/api` and
    // `/auth`; the prefix keeps the two apart.
    assetsDir: '_coffre/assets',
    // Vite inlines files under 4 KiB as data: URLs, which caught one small
    // font subset. The Content-Security-Policy takes fonts from coffre alone.
    assetsInlineLimit: (file) => (/\.woff2?$/.test(file) ? false : undefined),
  },

  plugins: [
    cloudflare({ viteEnvironment: { name: 'ssr' }, configPath: 'wrangler.jsonc' }),
    // Generates src/routeTree.gen.ts from src/routes, and wires the SSR
    // server. Must come before the React plugin.
    tanstackStart(),
    viteReact(),
  ],
});
