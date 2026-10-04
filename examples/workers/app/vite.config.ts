import { cloudflare } from '@cloudflare/vite-plugin';
import { coffre } from '@coffre/ui/vite';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import viteReact from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig(({ command }) => ({
  plugins: [
    cloudflare({
      viteEnvironment: { name: 'ssr' },
      // `vite dev` runs the vault beside the app; it deploys on its own.
      auxiliaryWorkers: command === 'serve' ? [{ configPath: '../vault/wrangler.jsonc' }] : [],
    }),
    tanstackStart(),
    viteReact(),
    coffre(),
  ],
}));
