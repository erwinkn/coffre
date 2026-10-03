import test from 'node:test';
import assert from 'node:assert/strict';

import { CoffreError, type CoffreClient } from '@coffre/client';
import { MutationObserver, QueryObserver, type QueryClient } from '@tanstack/react-query';

import { announcements } from '../src/lib/announce.ts';
import { grantAccess, grantId, revokeGrant, type GrantVars } from '../src/lib/changes.ts';
import { changeKey, changeOptions, failedAdds, itemStatus, type ChangeContext } from '../src/lib/optimistic.ts';
import { createQueryClient, keys, queries } from '../src/lib/queries.ts';
import type { GrantRow } from '../src/shared/models.ts';

const lead: GrantRow = {
  id: 'g-lead',
  principalType: 'user',
  principalId: 'lead@acme.example',
  role: 'owner',
  roleName: 'Owner',
  permissions: ['grant.manage'],
  scope: 'project',
  environmentSlug: null,
  expiresAt: null,
};

const dev: GrantVars = {
  principalType: 'user',
  principalId: 'dev@acme.example',
  role: 'viewer',
  roleName: 'Viewer',
  environmentSlug: 'prod',
  expiresAt: null,
};

/** An answer the test gives when it chooses. */
function later<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

/**
 * The server, as far as a project's grants go: what it lists, and each
 * access change held until the test answers it.
 */
function server(grants: GrantRow[]) {
  const held: ReturnType<typeof later<unknown>>[] = [];
  const client = {
    members: {
      list: async () => ({
        members: grants.map((grant) => ({
          principalType: grant.principalType,
          principalId: grant.principalId,
          grants: [
            {
              id: grant.id,
              role: grant.role,
              roleName: grant.roleName,
              permissions: grant.permissions,
              environment: grant.environmentSlug,
              expiresAt: grant.expiresAt,
            },
          ],
        })),
        removed: [],
      }),
    },
    access: {
      set: () => {
        const answer = later<unknown>();
        held.push(answer);
        return answer.promise;
      },
    },
    me: async () => null,
    projects: { list: async () => ({ projects: [] }) },
  } as unknown as CoffreClient;
  return { client, grants, held };
}

/** The project's grants on screen, as its page shows them. */
async function onScreen(queryClient: QueryClient, client: CoffreClient) {
  await queryClient.fetchQuery(queries.grants(client, 'market'));
  return new QueryObserver(queryClient, queries.grants(client, 'market')).subscribe(() => {});
}

function listed(queryClient: QueryClient): GrantRow[] {
  const data = queryClient.getQueryData(keys.grants('market')) as { ok: boolean; grants?: GrantRow[] };
  return data.grants ?? [];
}

function changes(queryClient: QueryClient) {
  return queryClient
    .getMutationCache()
    .findAll({ mutationKey: changeKey(keys.grants('market')) })
    .map((mutation) => ({
      mutationId: mutation.mutationId,
      state: mutation.state as typeof mutation.state & { context: ChangeContext | undefined },
    }));
}

/** Until whatever the change set off has run. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

test('an optimistic add shows at once as saving, then as confirmed', async () => {
  const { client, grants, held } = server([lead]);
  const queryClient = createQueryClient();
  const stop = await onScreen(queryClient, client);
  const add = new MutationObserver(queryClient, changeOptions(queryClient, grantAccess(client, 'market')));

  const done = add.mutate(dev);
  await settle();
  assert.deepEqual(listed(queryClient).map(grantId), [grantId(lead), grantId(dev)]);
  assert.deepEqual(itemStatus(changes(queryClient), grantId(dev)), {
    state: 'pending',
    kind: 'saving',
    words: { pending: 'Saving…', done: 'saved', failed: 'Not saved.' },
  });
  assert.equal(announcements().polite?.text, 'Viewer for dev@acme.example: Saving…');

  grants.push({ ...lead, id: 'g-dev', principalId: dev.principalId, role: 'viewer', roleName: 'Viewer', environmentSlug: 'prod', scope: 'environment' });
  held[0]!.resolve({ changes: { 'market/prod': 'granted' } });
  await done;
  await settle();
  assert.deepEqual(itemStatus(changes(queryClient), grantId(dev)), { state: 'idle' });
  // Read back from the server, with the id it gave.
  assert.equal(listed(queryClient).find((grant) => grantId(grant) === grantId(dev))?.id, 'g-dev');
  assert.equal(announcements().polite?.text, 'Viewer for dev@acme.example saved');
  stop();
});

test('a refused add rolls back and says why, in the API’s words, on a row of its own', async () => {
  const { client, held } = server([lead]);
  const queryClient = createQueryClient();
  const stop = await onScreen(queryClient, client);
  const add = new MutationObserver(queryClient, changeOptions(queryClient, grantAccess(client, 'market')));

  const done = add.mutate(dev).catch(() => {});
  await settle();
  held[0]!.reject(new CoffreError(409, 'conflict', 'dev@acme.example was removed; add them back before granting access'));
  await done;
  await settle();

  assert.deepEqual(listed(queryClient).map(grantId), [grantId(lead)]);
  const status = itemStatus(changes(queryClient), grantId(dev));
  assert.equal(status.state, 'failed');
  assert.equal(status.state === 'failed' && status.error, 'dev@acme.example was removed; add them back before granting access');
  // Nothing is left in the list to carry the error, so the refused add is listed itself.
  const refused = failedAdds<GrantVars>(changes(queryClient), listed(queryClient).map(grantId));
  assert.deepEqual(refused.map((entry) => entry.vars), [dev]);
  assert.match(announcements().urgent?.text ?? '', /Not saved\. dev@acme\.example was removed/);
  stop();
});

test('a removal keeps its row, marked, until the server confirms it', async () => {
  const { client, grants, held } = server([lead]);
  const queryClient = createQueryClient();
  const stop = await onScreen(queryClient, client);
  const revoke = new MutationObserver(queryClient, changeOptions(queryClient, revokeGrant(client, 'market')));

  const done = revoke.mutate(lead);
  await settle();
  assert.deepEqual(listed(queryClient).map(grantId), [grantId(lead)]);
  assert.deepEqual(itemStatus(changes(queryClient), grantId(lead)), {
    state: 'pending',
    kind: 'removing',
    words: { pending: 'Revoking…', done: 'revoked', failed: 'Not revoked.' },
  });

  grants.length = 0;
  held[0]!.resolve({ changes: { market: 'revoked' } });
  await done;
  await settle();
  assert.deepEqual(listed(queryClient), []);
  stop();
});

test('a failed revocation leaves the row as it was, flagged', async () => {
  const { client, held } = server([lead]);
  const queryClient = createQueryClient();
  const stop = await onScreen(queryClient, client);
  const revoke = new MutationObserver(queryClient, changeOptions(queryClient, revokeGrant(client, 'market')));

  const done = revoke.mutate(lead).catch(() => {});
  await settle();
  held[0]!.reject(new CoffreError(503, 'unavailable', 'the vault is unavailable'));
  await done;
  await settle();

  assert.deepEqual(listed(queryClient), [lead]);
  const status = itemStatus(changes(queryClient), grantId(lead));
  assert.equal(status.state, 'failed');
  assert.equal(status.state === 'failed' && status.words.failed, 'Not revoked.');
  assert.equal(status.state === 'failed' && status.error, 'coffre is unavailable. Nothing was read or written.');
  stop();
});

test('two changes in flight do not undo each other', async () => {
  const { client, grants, held } = server([lead]);
  const queryClient = createQueryClient();
  const stop = await onScreen(queryClient, client);
  const add = () => new MutationObserver(queryClient, changeOptions(queryClient, grantAccess(client, 'market')));
  const ops: GrantVars = { ...dev, principalId: 'ops@acme.example' };

  const first = add().mutate(dev).catch(() => {});
  const second = add().mutate(ops);
  await settle();
  assert.deepEqual(listed(queryClient).map(grantId), [grantId(lead), grantId(dev), grantId(ops)]);

  // The first is refused while the second is still on its way: only the first goes.
  held[0]!.reject(new CoffreError(409, 'conflict', 'no'));
  await first;
  await settle();
  assert.deepEqual(listed(queryClient).map(grantId), [grantId(lead), grantId(ops)]);
  assert.equal(itemStatus(changes(queryClient), grantId(ops)).state, 'pending');

  grants.push({ ...lead, id: 'g-ops', principalId: ops.principalId, role: 'viewer', roleName: 'Viewer', environmentSlug: 'prod', scope: 'environment' });
  held[1]!.resolve({ changes: { 'market/prod': 'granted' } });
  await second;
  await settle();
  assert.deepEqual(listed(queryClient).map(grantId), [grantId(lead), grantId(ops)]);
  stop();
});

test('an add refused twice is listed once, as its latest refusal', async () => {
  const { client, held } = server([lead]);
  const queryClient = createQueryClient();
  const stop = await onScreen(queryClient, client);
  const add = () => new MutationObserver(queryClient, changeOptions(queryClient, grantAccess(client, 'market')));

  for (const [index, reason] of ['first', 'second'].entries()) {
    const done = add().mutate(dev).catch(() => {});
    await settle();
    held[index]!.reject(new CoffreError(409, 'conflict', reason));
    await done;
    await settle();
  }
  const refused = failedAdds<GrantVars>(changes(queryClient), listed(queryClient).map(grantId));
  assert.deepEqual(refused.map((entry) => entry.status.error), ['second']);
  stop();
});
