import { coffre } from '@coffre/ui/vite';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import viteReact from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

import { deployment } from '../deployment';

export default defineConfig({
  plugins: [tanstackStart(), viteReact(), coffre({ deployment })],
});
