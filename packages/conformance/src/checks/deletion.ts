// Deleting an archived project, and an archived environment, for good, as an
// owner does it with the CLI: shown first, then done with --apply. Its values
// are erased in the database, it leaves every list, its slug is free for
// another, and the log, which still names it by its tombstone, verifies.
import { randomBytes } from 'node:crypto';

import { CoffreError } from '@coffre/client';

import { using } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect } from '../report.ts';
import type { Cli } from './cli.ts';
import type { Person } from './people.ts';
import { query } from './storage.ts';

const PROJECT = 'conformance-gone';
const SERVICE = 'token:conformance-gone-ci';

/** Each version under a project, by whether it still holds a ciphertext or a wrapped key. */
async function sealed(deployment: Deployment, projectId: string): Promise<{ versions: number; sealed: number }> {
  const rows = await using(deployment.database(), (sql) =>
    query<{ ciphertext: number | string; wrapped: number | string }>(
      sql,
      `SELECT length(v.ciphertext) AS ciphertext, length(v.wrapped_dek) AS wrapped
       FROM secret_versions v JOIN secrets s ON s.id = v.secret_id WHERE s.project_id = $1`,
      [projectId],
    ));
  return { versions: rows.length, sealed: rows.filter((row) => Number(row.ciphertext) > 0 || Number(row.wrapped) > 0).length };
}

async function projectId(deployment: Deployment, slug: string): Promise<string | undefined> {
  const [row] = await using(deployment.database(), (sql) => query<{ id: string }>(sql, 'SELECT id FROM projects WHERE slug = $1', [slug]));
  return row?.id;
}

export async function deletion(deployment: Deployment, cli: Cli, admin: Person): Promise<string> {
  const run = async (args: string[], code = 0): Promise<string> => {
    const result = await cli.run(args);
    expect(result.code === code, `coffre ${args.join(' ')} exited ${result.code}, not ${code}`, result.output);
    return result.output;
  };
  const value = () => `deleted-value-${randomBytes(8).toString('hex')}`;
  await admin.api.projects.create(PROJECT, { name: 'Gone' });
  for (const environment of ['prod', 'dev']) {
    await admin.api.environments.create(`${PROJECT}/${environment}`, { name: environment });
    await admin.api.secrets.set(`${PROJECT}/${environment}`, { API_KEY: value(), DATABASE_URL: value() });
  }
  await admin.api.secrets.set(`${PROJECT}/prod`, { API_KEY: value() });
  await admin.api.members.add(SERVICE);
  await admin.api.access.set(SERVICE, { [`${PROJECT}/prod`]: 'viewer' });
  const id = (await projectId(deployment, PROJECT))!;

  // Live, it is refused; archived, it is shown first and nothing changes.
  const live = await run(['projects', 'delete', PROJECT, '--apply'], 1);
  expect(/not archived/.test(live), 'deleting a live project was not refused as not archived', live);
  await run(['projects', 'archive', PROJECT]);
  const preview = await run(['projects', 'delete', PROJECT]);
  expect(/erased: 5 versions/.test(preview) && /revoked: 1 grant/.test(preview) && preview.includes('service:conformance-gone-ci would hold nothing anywhere'),
    'the preview does not say what the deletion takes', preview);
  expect(/Backups taken before the deletion still hold the encrypted values/.test(preview) && /Nothing changed/.test(preview),
    'the preview does not warn of backups, or changed something', preview);
  expect((await sealed(deployment, id)).sealed === 5, 'the preview erased something');

  const done = await run(['projects', 'delete', PROJECT, '--apply']);
  expect(/^deleted conformance-gone, for good/.test(done), 'the deletion did not say it was done', done);

  // The values are erased; the names stay, under the tombstone's slug.
  const after = await sealed(deployment, id);
  expect(after.versions === 5 && after.sealed === 0, 'a deleted project still holds a ciphertext or a wrapped key', after);
  const [tombstone] = await using(deployment.database(), (sql) => query<{ slug: string }>(sql, 'SELECT slug FROM projects WHERE id = $1', [id]));
  expect(/^conformance-gone~deleted-\d{4}-\d{2}-\d{2}$/.test(tombstone?.slug ?? ''), 'the tombstone is not named for the day', tombstone);
  expect((await admin.api.projects.list()).projects.every((project) => !project.slug.startsWith(PROJECT)), 'a deleted project is still listed');
  expect((await admin.api.members.get(SERVICE)).live.grants === 0, 'a grant on the deleted project is still live');
  const revealed = await admin.api.secrets.reveal(`${tombstone!.slug}/prod`).then(() => null, (error: unknown) => error);
  expect(revealed instanceof CoffreError && revealed.status === 404, 'a deleted project is still revealed by its tombstone', revealed);

  // Its slug is another project's now; the log tells the two apart.
  const fresh = value();
  await admin.api.projects.create(PROJECT, { name: 'Gone, again' });
  await admin.api.environments.create(`${PROJECT}/prod`, { name: 'prod' });
  await admin.api.secrets.set(`${PROJECT}/prod`, { API_KEY: fresh });
  expect((await projectId(deployment, PROJECT)) !== id, 'the new project took the deleted one\'s row');
  expect((await admin.api.secrets.reveal(`${PROJECT}/prod/API_KEY`)).values.API_KEY === fresh, 'the new project does not read its own value');
  const { entries } = await admin.api.audit.list({ path: tombstone!.slug, limit: 500 });
  expect(entries.some((entry) => entry.action === 'project.delete' && entry.decision === 'allow'), 'the deletion is not in the log under its tombstone', entries.slice(0, 5));

  // An environment alone, the same way.
  await admin.api.environments.update(`${PROJECT}/prod`, { archived: true });
  await run(['environments', 'delete', `${PROJECT}/prod`, '--apply']);
  await admin.api.environments.create(`${PROJECT}/prod`, { name: 'prod, again' });
  const environments = (await admin.api.projects.list()).projects.find((project) => project.slug === PROJECT)?.environments ?? [];
  expect(environments.length === 1 && environments[0]!.name === 'prod, again', 'a deleted environment is still listed, or its slug is not free', environments);
  expect((await sealed(deployment, (await projectId(deployment, PROJECT))!)).sealed === 0, 'a deleted environment still holds a value');

  const verified = await admin.api.audit.verify();
  expect(verified.ok, 'the log does not verify after the deletions', verified);
  return `${PROJECT} and ${PROJECT}/prod deleted by the CLI: 5 versions erased, a grant revoked, both unlisted and their slugs reused; ${verified.entries} entries verify`;
}
