import type { AccessChanges } from '@coffre/core/vault';

import type { Operations } from './index.ts';

/** The changes of members, grants, roles and the instance's policy (docs/design/0.16.md, "A change"): none yet. */
export const accessOperations: Operations<AccessChanges> = {};
