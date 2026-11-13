import { USES_IN_FLIGHT } from '@coffre/core/memory';

/**
 * The most entries `check` reads above the newest signed checkpoint (`Vault.check` in @coffre/core/vault): past it, the checkpointer is late, and the check says `late` rather than read on. It is
 * `USES_IN_FLIGHT`, the uses an isolate holds in flight at once: the checkpointer seals every
 * `TICK_MS`, so a live log holds a handful above its newest checkpoint, and 1,250 is far past that while one page's
 * read of them stays one round trip. Nobody sets it.
 */
export const CHECK_TAIL_ENTRIES = USES_IN_FLIGHT;
