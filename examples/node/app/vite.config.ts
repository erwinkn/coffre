import { coffre } from '@coffre/ui/vite';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import viteReact from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [tanstackStart(), viteReact(), coffre()],
  // SQLite's driver loads a native binding built for this machine, so the
  // server's build imports it from this project's dependencies rather than
  // carrying it. Only a file: database, for local development, uses it.
  ssr: { external: ['@libsql/client'] },
});
