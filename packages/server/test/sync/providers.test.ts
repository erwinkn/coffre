import test from 'node:test';
import assert from 'node:assert/strict';

import { configFromArguments, configFromForm, firstMissing, initialValues, type SyncProviderInfo } from '@coffre/client';

import {
  githubActions,
  resolveSyncProviders,
  SyncConfigError,
  type SyncField,
  type SyncProvider,
} from '../../src/sync/index.ts';

const defaults = resolveSyncProviders();
const offered = (id: string): SyncProviderInfo => {
  const provider = defaults.find((candidate) => candidate.id === id);
  assert.ok(provider, id);
  return provider;
};

test('a deployment that lists none gets the four built-ins, in order', () => {
  assert.deepEqual(
    defaults.map(({ id, label, brand }) => [id, label, brand]),
    [
      ['github-actions', 'GitHub Actions', 'github'],
      ['vercel', 'Vercel', 'vercel'],
      ['railway', 'Railway', 'railway'],
      ['cloudflare-workers', 'Cloudflare Workers', 'cloudflare'],
    ],
  );
  assert.deepEqual(resolveSyncProviders([]), [], 'an empty list offers no syncs at all');
});

// The form builds what each provider's own parser accepts; the parser is the
// judge, so a field renamed on one side fails here rather than in a dialog.
test('every provider’s form maps onto its config', () => {
  const filled: Record<string, Record<string, string>> = {
    'github-actions': { owner: 'erwinkn', repo: 'app', environment: 'production' },
    vercel: { projectId: 'prj_abc123', teamId: 'team_abc123' },
    railway: {
      projectId: '2f7c1c7e-5a4b-4c1e-9c61-0d0f8b0a9d11',
      environmentId: '6b2e4a1f-3c5d-4e7f-8a9b-0c1d2e3f4a5b',
    },
    'cloudflare-workers': { accountId: '0123456789abcdef0123456789abcdef', scriptName: 'api' },
  };
  for (const provider of defaults) {
    const values = { ...initialValues(provider), ...filled[provider.id] };
    assert.equal(firstMissing(provider, values), null, provider.id);
    assert.doesNotThrow(() => provider.parseConfig(configFromForm(provider, values)), provider.id);
  }
});

test('empty optional fields are left out, and text is trimmed', () => {
  const github = offered('github-actions');
  const values = { ...initialValues(github), owner: ' erwinkn ', repo: 'app' };
  assert.deepEqual(configFromForm(github, values), { owner: 'erwinkn', repo: 'app' });
  assert.equal(firstMissing(github, { ...values, repo: '  ' }), 'Repository');
});

test('Vercel asks for a branch only when previews are the only target', () => {
  const vercel = offered('vercel');
  const base = { ...initialValues(vercel), projectId: 'prj_abc123', gitBranch: 'staging' };
  assert.deepEqual(configFromForm(vercel, base), { projectId: 'prj_abc123', targets: ['production'] });
  assert.deepEqual(configFromForm(vercel, { ...base, targets: ['preview'] }), {
    projectId: 'prj_abc123',
    targets: ['preview'],
    gitBranch: 'staging',
  });
  assert.equal(firstMissing(vercel, { ...base, targets: [] }), 'Targets');
});

test('CLI arguments become the same config, with the form’s preselected options', () => {
  const vercel = offered('vercel');
  assert.deepEqual(configFromArguments(vercel, ['projectId=prj_abc123']), {
    projectId: 'prj_abc123',
    targets: ['production'],
  });
  const previews = configFromArguments(vercel, ['projectId=prj_abc123', 'targets=preview, development']);
  assert.deepEqual(previews.targets, ['preview', 'development']);
  assert.deepEqual(configFromArguments(offered('railway'), ['projectId=p', 'environmentId=e']), {
    projectId: 'p',
    environmentId: 'e',
    tokenKind: 'project',
  });
  // Whatever parseConfig makes of it is the server's call; this only refuses
  // what could never be a field.
  assert.throws(() => configFromArguments(vercel, ['project=prj_abc123']), /takes projectId, teamId, targets, gitBranch/);
  assert.throws(() => configFromArguments(vercel, ['prj_abc123']), /as name=value/);
  assert.throws(() => configFromArguments(vercel, ['teamId=a', 'teamId=b']), /teamId is given twice/);
});

// --- a deployment's own provider --------------------------------------------

/** The smallest provider that passes, for each case below to break one way. */
function own(changes: Partial<SyncProvider<string>> = {}): SyncProvider<string> {
  return {
    id: 'fly',
    label: 'Fly.io',
    brand: 'other',
    fields: [
      { type: 'text', name: 'app', label: 'App', placeholder: 'my-app' },
      {
        type: 'options',
        name: 'stage',
        label: 'Stage',
        options: [
          { value: 'deploy', label: 'Deploy' },
          { value: 'stage', label: 'Stage only' },
        ],
        multiple: false,
        initial: ['deploy'],
      },
      { type: 'text', name: 'note', label: 'Note', placeholder: '', optional: true, when: { field: 'stage', is: ['stage'] } },
    ],
    credential: { placeholder: 'ops/sync/FLY_TOKEN', hint: 'A deploy token for this one app.' },
    parseConfig: (input) => {
      const app = (input as { app?: unknown } | null)?.app;
      if (typeof app !== 'string') throw new SyncConfigError('Fly.io: app is required');
      return app;
    },
    describe: (app) => app,
    checkKey: () => ({ ok: true }),
    listKeys: async () => [],
    apply: async (_ctx, _app, plan) => ({ upserted: plan.upsert.map(({ key }) => key), deleted: plan.delete, failed: [] }),
    ...changes,
  };
}

const withField = (field: SyncField) => own({ fields: [...own().fields, field] });

test('a deployment lists its own provider beside the built-ins, guarded like them', async () => {
  const sent: string[] = [];
  const fly = own({
    checkKey: (key) => (key.startsWith('FLY_') ? { ok: false, reason: 'names starting with FLY_ are Fly’s own' } : { ok: true }),
    apply: async (ctx, _app, plan) => {
      sent.push(...plan.upsert.map(({ key }) => key));
      throw new Error(`token ${ctx.token} was refused`);
    },
  });
  const [github, guarded] = resolveSyncProviders([githubActions(), fly]);
  assert.deepEqual([github!.id, guarded!.id], ['github-actions', 'fly']);
  const plan = { upsert: [{ key: 'FLY_REGION', value: 'cdg' }], delete: [] };
  assert.deepEqual(await guarded!.apply({ token: 'fly-token-secret' }, 'app', plan), {
    upserted: [],
    deleted: [],
    failed: [{ key: 'FLY_REGION', operation: 'upsert', message: 'names starting with FLY_ are Fly’s own' }],
  });
  await assert.rejects(
    guarded!.apply({ token: 'fly-token-secret' }, 'app', { upsert: [{ key: 'API_KEY', value: 'v' }], delete: [] }),
    { message: 'token [redacted] was refused' },
  );
  assert.deepEqual(sent, ['API_KEY'], 'a key the provider refuses is never sent');
});

test('a provider’s shape is checked with the rest of the configuration', () => {
  const refused: [SyncProvider<any>[], RegExp][] = [
    [[own(), own()], /id "fly" is used twice/],
    [[githubActions(), own({ id: 'github-actions' })], /id "github-actions" is used twice/],
    [[own({ id: 'Fly.io' })], /id "Fly.io" must be 1-32 lowercase letters/],
    [[own({ label: ' ' })], /fly needs a label/],
    [[own({ brand: 'fly' as 'other' })], /fly has a brand that is not one of github, vercel, railway, cloudflare, other/],
    [[own({ credential: { placeholder: 'ops/sync/FLY_TOKEN', hint: '' } })], /fly needs a credential placeholder and hint/],
    [[own({ listKeys: undefined as never })], /fly needs listKeys\(\)/],
    [[withField({ type: 'text', name: 'app', label: 'Again', placeholder: '' })], /fly has two fields named app/],
    [[withField({ type: 'text', name: 'region', label: 'Region' } as SyncField)], /field "region" needs a placeholder/],
    [
      [withField({ type: 'text', name: 'region', label: 'Region', placeholder: '', when: { field: 'app', is: ['x'] } })],
      /field "region" must depend on an options field/,
    ],
    [
      [withField({ type: 'options', name: 'size', label: 'Size', options: [], multiple: true, initial: [] })],
      /field "size" needs options, each with a value/,
    ],
    [
      [
        withField({
          type: 'options',
          name: 'size',
          label: 'Size',
          options: [{ value: 'small', label: 'Small' }],
          multiple: true,
          initial: ['large'],
        }),
      ],
      /field "size" can only start with its own options/,
    ],
    [
      [
        withField({
          type: 'options',
          name: 'size',
          label: 'Size',
          options: [{ value: 'small', label: 'Small' }],
          multiple: false,
          initial: [],
        }),
      ],
      /field "size" takes one option, so starts with exactly one/,
    ],
  ];
  for (const [listed, message] of refused) assert.throws(() => resolveSyncProviders(listed), message);
});
