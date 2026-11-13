import type { Answers, Change, Presented } from '@coffre/core/vault';

import type { Operation, Parts } from '../change.ts';
import type { Deciding } from '../vault.ts';
import { secretWrite } from './secrets.ts';

/**
 * Every change the vault makes, by the name its log entry has: what it
 * reads, and its decision (change.ts). An operation checks its own input,
 * and is given nothing of the vault but what a decision needs of its
 * configuration.
 */
export const OPERATIONS: { [O in Change['op']]: (input: Presented & Extract<Change, { op: O }>, vault: Deciding) => Operation<Parts, Answers[O]> } = {
  'secret.write': secretWrite,
};
