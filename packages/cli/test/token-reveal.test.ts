// `coffre verify instance`'s token reveal check (verify/token.ts) against 0.15's log, whose reads are listed on the
// token's own page once the vault's projector has written them.
import assert from 'node:assert/strict';
import test from 'node:test';

import type { CoffreClient } from '@coffre/client';

import { tokenReveal } from '../src/verify/token.ts';

const CANARY = { project: 'market', environment: 'prod', key: 'CANARY', value: 'canary-value' };
const TOKEN = { member: 'service:ci', credentialId: 'cred-1' };

/** A read of the canary by the token's credential, as 0.15's log lists it. */
const readOf = (seq: number, version: number, at: number) => ({
  seq, log: '0.15', action: 'secret.read', decision: 'allow', key: CANARY.key, project: CANARY.project, environment: CANARY.environment,
  version, occurredAt: new Date(at).toISOString(), metadata: { credentialId: TOKEN.credentialId, purpose: 'reveal' },
});

test("the token reveal waits for the version it revealed: an earlier version's read of the minute before stops no wait (review r11)", async () => {
  // The canary rewritten to the same value at version 2: version 1's read, a moment ago, listed; version 2's listed on
  // the third look.
  const earlier = readOf(7, 1, Date.now() - 30_000);
  let looks = 0;
  const api = {
    secrets: {
      reveal: async () => ({ operationId: 'op-1', values: { [CANARY.key]: CANARY.value } }),
      list: async () => ({ keys: [{ key: CANARY.key, version: 2 }] }),
    },
    audit: {
      list: async (query: { path?: string }) => {
        const reads = { through: new Date().toISOString(), behind: false };
        if (query.path !== undefined) return { entries: [], more: false, next: null, reads, readsOmitted: 'path' };
        looks += 1;
        return { entries: looks >= 3 ? [readOf(9, 2, Date.now()), earlier] : [earlier], more: false, next: null, reads };
      },
    },
  } as unknown as CoffreClient;
  assert.equal(await tokenReveal(api, CANARY, TOKEN), "one secret.read of CANARY, entry 9 of 0.15's log, by the token's credential");
  assert.ok(looks >= 3);
});
