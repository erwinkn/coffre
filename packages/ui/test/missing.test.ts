import test from 'node:test';
import assert from 'node:assert/strict';

import { CoffreError, type CoffreClient, type MissingKey } from '@coffre/client';
import { MutationObserver, QueryObserver, type QueryClient } from '@tanstack/react-query';

import { announcements } from '../src/lib/announce.ts';
import { dismissMissing, missingList, restoreMissing } from '../src/lib/changes.ts';
import { changeKey, changeOptions, itemStatus, type ChangeContext } from '../src/lib/optimistic.ts';
import { createQueryClient, queries } from '../src/lib/queries.ts';

const place = { project: 'market', environment: 'dev' };
const list = missingList(place);

const key = (name: string): MissingKey => ({ key: name, in: ['prod'], folder: null });

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
 * The server, as far as market/dev's missing keys go: what prod has and dev
 * lacks, what the team dismissed, and each dismissal patch held until the
 * test answers it.
 */
function server(names: string[]) {
  const dismissed = new Set<string>();
  const held: { patch: Record<string, true | null>; answer: ReturnType<typeof later<unknown>> }[] = [];
  const client = {
    environments: {
      missing: async () => ({
        missing: names.filter((name) => !dismissed.has(name)).map(key),
        dismissed: names.filter((name) => dismissed.has(name)).map((name) => ({ ...key(name), dismissedBy: 'admin@acme.example', dismissedAt: '2026-10-17T10:00:00.000Z' })),
      }),
      dismiss: (_path: string, patch: Record<string, true | null>) => {
        const answer = later<unknown>();
        held.push({ patch, answer });
        return answer.promise.then((result) => {
          for (const [name, value] of Object.entries(patch)) {
            if (value === true) dismissed.add(name);
            else dismissed.delete(name);
          }
          return result;
        });
      },
    },
    me: async () => null,
    projects: { list: async () => ({ projects: [] }) },
  } as unknown as CoffreClient;
  return { client, held };
}

/** The panel's read, on screen as the environment page has it. */
async function onScreen(queryClient: QueryClient, client: CoffreClient) {
  await queryClient.fetchQuery(queries.missing(client, place));
  return new QueryObserver(queryClient, queries.missing(client, place)).subscribe(() => {});
}

/** What the panel lists: when nothing, it does not show at all. */
function listed(queryClient: QueryClient): string[] {
  const data = queryClient.getQueryData(list.queryKey) as Parameters<typeof list.items>[0] | undefined;
  return data === undefined ? [] : list.items(data).map((entry) => entry.key);
}

function changes(queryClient: QueryClient) {
  return queryClient
    .getMutationCache()
    .findAll({ mutationKey: changeKey(list.queryKey) })
    .map((mutation) => ({
      mutationId: mutation.mutationId,
      state: mutation.state as typeof mutation.state & { context: ChangeContext | undefined },
    }));
}

/** Until whatever the change set off has run. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

test('dismissing every missing key empties the panel at once, and it stays empty with the dismissed keys read back', async () => {
  const { client, held } = server(['MAILGUN_KEY', 'SENTRY_DSN']);
  const queryClient = createQueryClient();
  const stop = await onScreen(queryClient, client);
  const dismiss = new MutationObserver(queryClient, changeOptions(queryClient, dismissMissing(client, place)));

  const done = dismiss.mutate([key('MAILGUN_KEY'), key('SENTRY_DSN')]);
  await settle();
  assert.deepEqual(listed(queryClient), [], 'gone before the server answers');
  assert.deepEqual(held.map((each) => each.patch), [{ MAILGUN_KEY: true, SENTRY_DSN: true }], 'one call for all of them');
  assert.equal(announcements().polite?.text, '2 missing keys: Dismissing…');

  held[0]!.answer.resolve({ operationId: 'op', keys: { MAILGUN_KEY: 'dismissed', SENTRY_DSN: 'dismissed' } });
  await done;
  await settle();
  const read = queryClient.getQueryData(list.queryKey) as { dismissed: MissingKey[] };
  assert.deepEqual(read.dismissed.map((entry) => entry.key), ['MAILGUN_KEY', 'SENTRY_DSN'], 'read back from the server');
  assert.deepEqual(listed(queryClient), [], 'the dismissed are not listed');
  stop();
});

test('a refused dismissal puts its key back where it was and says why, in the API’s words', async () => {
  const { client, held } = server(['FEATURE_FLAGS', 'MAILGUN_KEY', 'SENTRY_DSN']);
  const queryClient = createQueryClient();
  const stop = await onScreen(queryClient, client);
  const dismiss = new MutationObserver(queryClient, changeOptions(queryClient, dismissMissing(client, place)));

  const done = dismiss.mutate([key('MAILGUN_KEY')]).catch(() => {});
  await settle();
  assert.deepEqual(listed(queryClient), ['FEATURE_FLAGS', 'SENTRY_DSN']);

  held[0]!.answer.reject(new CoffreError(409, 'conflict', 'market/dev was archived while you looked'));
  await done;
  await settle();
  assert.deepEqual(listed(queryClient), ['FEATURE_FLAGS', 'MAILGUN_KEY', 'SENTRY_DSN'], 'back in its place');
  const status = itemStatus(changes(queryClient), 'MAILGUN_KEY');
  assert.equal(status.state, 'failed');
  assert.equal(status.state === 'failed' && `${status.words.failed} ${status.error}`, 'Not dismissed. market/dev was archived while you looked');
  assert.match(announcements().urgent?.text ?? '', /MAILGUN_KEY: Not dismissed\./);
  stop();
});

test('undo lists dismissed keys again at once, in name order, and a refused one takes them away again', async () => {
  const { client, held } = server(['FEATURE_FLAGS', 'MAILGUN_KEY', 'SENTRY_DSN']);
  const queryClient = createQueryClient();
  const stop = await onScreen(queryClient, client);
  const dismiss = new MutationObserver(queryClient, changeOptions(queryClient, dismissMissing(client, place)));
  const restore = new MutationObserver(queryClient, changeOptions(queryClient, restoreMissing(client, place)));

  const dismissed = dismiss.mutate([key('FEATURE_FLAGS'), key('SENTRY_DSN')]);
  await settle();
  held[0]!.answer.resolve({});
  await dismissed;
  await settle();
  assert.deepEqual(listed(queryClient), ['MAILGUN_KEY']);

  const undone = restore.mutate([key('FEATURE_FLAGS'), key('SENTRY_DSN')]);
  await settle();
  assert.deepEqual(listed(queryClient), ['FEATURE_FLAGS', 'MAILGUN_KEY', 'SENTRY_DSN'], 'before the server answers');
  assert.deepEqual(held[1]!.patch, { FEATURE_FLAGS: null, SENTRY_DSN: null });
  held[1]!.answer.resolve({});
  await undone;
  await settle();
  assert.deepEqual(listed(queryClient), ['FEATURE_FLAGS', 'MAILGUN_KEY', 'SENTRY_DSN'], 'read back the same');

  const again = dismiss.mutate([key('SENTRY_DSN')]);
  await settle();
  held[2]!.answer.resolve({});
  await again;
  await settle();
  const refused = restore.mutate([key('SENTRY_DSN')]).catch(() => {});
  await settle();
  assert.deepEqual(listed(queryClient), ['FEATURE_FLAGS', 'MAILGUN_KEY', 'SENTRY_DSN']);
  held[3]!.answer.reject(new CoffreError(500, 'internal', 'the database is unavailable'));
  await refused;
  await settle();
  assert.deepEqual(listed(queryClient), ['FEATURE_FLAGS', 'MAILGUN_KEY'], 'not restored: dismissed still');
  stop();
});
