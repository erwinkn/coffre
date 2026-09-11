import { defineConfig } from 'vite';
import { cloudflare } from '@cloudflare/vite-plugin';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import react from '@vitejs/plugin-react';
import tailwind from '@tailwindcss/vite';
import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';
export default defineConfig(({ command }) => {
  // Local keys and identity never enter a production build or a committed config.
  const local = command === 'serve' ? JSON.parse(readFileSync('.local/config.json', 'utf8')) as { web: Record<string, string>; vault: Record<string, string>; kms: Record<string, string> } : null;
  return {
    root: resolve('apps/web'),
    plugins: [cloudflare({ configPath: resolve('deploy/web.jsonc'), ...(local ? { config: (config) => ({ vars: { ...config.vars, ...local.web } }) } : {}), viteEnvironment: { name: 'ssr' }, auxiliaryWorkers: [{ configPath: resolve('deploy/vault.jsonc'), ...(local ? { config: (config: { vars?: Record<string, unknown> }) => ({ vars: { ...config.vars, ...local.vault } }) } : {}) }, { configPath: resolve('deploy/kms.jsonc'), ...(local ? { config: (config: { vars?: Record<string, unknown> }) => ({ vars: { ...config.vars, ...local.kms } }) } : {}) }], persistState: { path: resolve('.wrangler/state') }, remoteBindings: false, inspectorPort: false }), tanstackStart(), react(), tailwind()],
    server: { host: '127.0.0.1', port: 5173, strictPort: true },
    resolve: { alias: { '@': resolve('apps/web/src') } },
  };
});
