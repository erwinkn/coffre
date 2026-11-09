// What `pnpm dev`'s instance allows, as examples/workers/deployment.ts: read by
// the app (app/src/coffre.ts), the vault (vault/src/worker.ts) and the build
// (app/vite.config.ts). The defaults, but for definitions Owners write in the
// Proxy tab, which dev/seed.mjs seeds.
import { defineDeployment } from '@coffre/core/deployment';

export const deployment = defineDeployment({
  proxy: { editable: true },
});
