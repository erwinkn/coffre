import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { ACTION_VALUES, maskProbes, verifyMasks } from './action-fixtures.ts';

const [command, path] = process.argv.slice(2);

switch (command) {
  case 'serve':
    if (!path || !process.env.GITHUB_ENV) throw new Error('serve needs a ready-file path and GITHUB_ENV');
    await serve(path, process.env.GITHUB_ENV);
    break;
  case 'assert-env':
    for (const [key, value] of Object.entries(ACTION_VALUES)) {
      if (process.env[key] !== value) throw new Error(`${key} was not exported intact`);
    }
    for (const [marker, value] of maskProbes()) console.log(marker + value);
    console.log('All exported values match, including multiline, punctuation, empty and GITHUB_TOKEN.');
    break;
  case 'verify-masks':
    if (!path) throw new Error('verify-masks needs a completed job log');
    verifyMasks(readFileSync(path, 'utf8'));
    console.log('The GitHub runner masked every probe, including each multiline value line.');
    break;
  default:
    throw new Error('usage: action-test.ts serve <ready-file> | assert-env | verify-masks <job-log>');
}

async function serve(readyFile: string, environmentFile: string): Promise<void> {
  // The log-verification job needs only Node, not installed packages. Load
  // the harness and its API client only in the job that boots the server.
  const { boot } = await import('../src/harness.ts');
  const { signInAdmin } = await import('../src/checks/people.ts');
  const stopped = new Promise<void>((resolve) => {
    process.once('SIGTERM', resolve);
    process.once('SIGINT', resolve);
  });
  const deployment = await boot('node', fileURLToPath(new URL('../../../examples/node', import.meta.url)), { port: 3982 });
  try {
    const { value: admin } = await signInAdmin(deployment);
    await admin.api.projects.create('action-test', { name: 'Action test' });
    await admin.api.environments.create('action-test/ci', { name: 'CI' });
    await admin.api.environments.create('action-test/deploy', { name: 'Deploy' });
    // Two environments, read together by the Action: GITHUB_TOKEN from the second.
    const { GITHUB_TOKEN, ...values } = ACTION_VALUES;
    await admin.api.secrets.set('action-test/ci', values);
    await admin.api.secrets.set('action-test/deploy', { GITHUB_TOKEN: GITHUB_TOKEN! });
    const member = 'token:action-test';
    await admin.api.members.add(member);
    await admin.api.access.set(member, { 'action-test/ci': 'viewer', 'action-test/deploy': 'viewer' });
    const { token } = await admin.api.tokens.issue(member, { label: 'Action test', expiresInDays: 1 });
    // The foreground setup step forwards this command from the fixture log.
    // Only the credential is masked here; the Action must mask all values.
    console.log(`::add-mask::${token}`);
    // Not COFFRE_*: the CLI refuses the variables it no longer reads, and the Action's step inherits these.
    appendFileSync(environmentFile, `ACTION_TEST_URL=${deployment.origin}\nACTION_TEST_TOKEN=${token}\n`);
    writeFileSync(readyFile, String(process.pid), { mode: 0o600 });
    await stopped;
  } finally {
    await deployment.stop();
  }
}
