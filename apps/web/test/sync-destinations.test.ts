import test from 'node:test';
import assert from 'node:assert/strict';

import { getProvider } from '../../../packages/sync/src/index.ts';
import {
  DESTINATIONS,
  destination,
  destinationConfig,
  firstMissing,
  initialValues,
} from '../src/lib/sync-destinations.ts';

// The form builds what each provider's own parser accepts; the parser is the
// judge, so a field renamed on one side fails here rather than in a dialog.
test('every destination form maps onto its provider’s config', () => {
  const filled: Record<string, Record<string, string>> = {
    'github-actions': { owner: 'erwinkn', repo: 'app', environment: 'production' },
    vercel: { projectId: 'prj_abc123', teamId: 'team_abc123' },
    railway: {
      projectId: '2f7c1c7e-5a4b-4c1e-9c61-0d0f8b0a9d11',
      environmentId: '6b2e4a1f-3c5d-4e7f-8a9b-0c1d2e3f4a5b',
    },
    'cloudflare-workers': { accountId: '0123456789abcdef0123456789abcdef', scriptName: 'api' },
  };
  for (const entry of DESTINATIONS) {
    const values = { ...initialValues(entry), ...filled[entry.kind] };
    assert.equal(firstMissing(entry, values), null, entry.kind);
    const provider = getProvider(entry.kind);
    assert.ok(provider, entry.kind);
    assert.doesNotThrow(() => provider.parseConfig(destinationConfig(entry, values)), entry.kind);
  }
});

test('empty optional fields are left out, and text is trimmed', () => {
  const github = destination('github-actions');
  const values = { ...initialValues(github), owner: ' erwinkn ', repo: 'app' };
  assert.deepEqual(destinationConfig(github, values), { owner: 'erwinkn', repo: 'app' });
  assert.equal(firstMissing(github, { ...values, repo: '  ' }), 'Repository');
});

test('Vercel asks for a branch only when previews are the only target', () => {
  const vercel = destination('vercel');
  const base = { ...initialValues(vercel), projectId: 'prj_abc123', gitBranch: 'staging' };
  assert.deepEqual(destinationConfig(vercel, base), { projectId: 'prj_abc123', targets: ['production'] });
  assert.deepEqual(destinationConfig(vercel, { ...base, targets: ['preview'] }), {
    projectId: 'prj_abc123',
    targets: ['preview'],
    gitBranch: 'staging',
  });
  assert.equal(firstMissing(vercel, { ...base, targets: [] }), 'Targets');
});
