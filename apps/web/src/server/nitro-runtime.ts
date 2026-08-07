import { definePlugin } from 'nitro';

import { disposeRuntime } from './runtime.ts';

export default definePlugin((nitro) => {
  nitro.hooks.hook('close', disposeRuntime);
});
