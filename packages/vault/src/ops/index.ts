import type { Answers, Change, Presented } from '@coffre/core/vault';

import type { Operation, Parts } from '../change.ts';
import type { Deciding } from '../vault.ts';
import { accessOperations } from './access.ts';
import { placeOperations } from './places.ts';
import { secretOperations } from './secrets.ts';

/**
 * Changes by the name their log entry has: what each reads, and its
 * decision (change.ts). An operation checks its own input, and is given
 * nothing of the vault but what a decision needs of its configuration.
 */
export type Operations<C extends Change> = { [K in C['op']]: (input: Presented & Extract<Change, { op: K }>, vault: Deciding) => Operation<Parts, Answers[K]> };

/** Every change the vault makes: each area's are in a file of its own. */
export const OPERATIONS: Operations<Change> = { ...secretOperations, ...placeOperations, ...accessOperations };
