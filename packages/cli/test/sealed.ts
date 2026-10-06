// The packed CLI seals a secret as its sources do. The consumer test runs
// this with the unpacked tarball's dist/deploy-on-push.js: it sets a
// secret through the stand-in for GitHub, which opens it with libsodium,
// as GitHub does. Nothing is installed beside the tarball, so what seals is
// the libsodium the CLI bundles.
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';

import type * as Sources from '../src/deploy-on-push.ts';
import { fakeGitHub } from './fakes.ts';

const { GitHubRepository } = (await import(pathToFileURL(process.argv[2]!).href)) as typeof Sources;
const github = await fakeGitHub();
try {
  const token = `gho_${'s'.repeat(36)}`;
  github.state.tokens.set(token, new Set(['acme/secrets']));
  const repository = new GitHubRepository(github.github, 'acme/secrets', token);
  await repository.set('DATABASE_OWNER_URL', 'postgresql://owner:hunter2@db.acme.test/coffre', await repository.publicKey());
  assert.equal(github.state.secrets.get('acme/secrets')?.get('DATABASE_OWNER_URL'), 'postgresql://owner:hunter2@db.acme.test/coffre');
} finally {
  github.close();
}
