import { defineConfig } from 'vite';
import viteReact from '@vitejs/plugin-react';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import { nitro } from 'nitro/vite';

export default defineConfig({
  server: {
    port: 3000,
    // scripts/dev.sh checks 127.0.0.1 and the seeded links point there, so bind
    // both loopback names rather than only localhost.
    host: '127.0.0.1',
  },

  plugins: [
    // Generates src/routeTree.gen.ts from src/routes, and wires the SSR
    // server. Must come before the React plugin.
    tanstackStart(),
    // Turns Start's fetch handler into a standalone production Node server.
    nitro(),
    viteReact(),
  ],
});
