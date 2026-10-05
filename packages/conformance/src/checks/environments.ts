// What arranges and fills environments: folders, which change nothing but
// how lists read, and forks (docs/design/environments.md).
import { expect, refused } from '../report.ts';
import { DEV, PROJECT, valuesIn, type Canaries, type People } from './people.ts';

/** Where the fork check copies dev to; archived once checked. */
const FORKED = `${PROJECT}/forked`;

/**
 * A folder grants, hides and renames nothing: a secret filed in one is
 * still read, run and exported by its own name, by the same people, and
 * only those who may write may file it.
 */
export async function folders({ admin, reader }: People, canaries: Canaries): Promise<string> {
  const keys = Object.keys(valuesIn(canaries, DEV));
  const key = keys[0];
  expect(key !== undefined, 'dev holds no secret to file');
  await admin.api.projects.update(PROJECT, { folder: 'Conformance' });
  await admin.api.secrets.update(`${DEV}/${key}`, { folder: 'filed' });
  try {
    const project = (await reader.api.projects.list()).projects.find((each) => each.slug === PROJECT);
    expect(project?.folder === 'Conformance', 'a project filed in a folder is not listed in it', project);
    const listed = (await reader.api.secrets.list(DEV)).keys.find((each) => each.key === key);
    expect(listed?.folder === 'filed', 'a secret filed in a folder is not listed in it', listed);
    const read = await reader.api.secrets.reveal(DEV);
    expect(JSON.stringify(Object.keys(read.values).sort()) === JSON.stringify([...keys].sort()), 'filing a secret changed the names a run injects', Object.keys(read.values));
    expect(read.values[key] === canaries[`${DEV}/${key}`], 'filing a secret changed its value');
    await refused('a viewer filed a secret', reader.api.secrets.update(`${DEV}/${key}`, { folder: 'elsewhere' }));
    await refused('a viewer filed a project', reader.api.projects.update(PROJECT, { folder: 'Elsewhere' }));
    await refused('a folder name with a slash was taken', admin.api.secrets.update(`${DEV}/${key}`, { folder: 'a/b' }));
  } finally {
    await admin.api.secrets.update(`${DEV}/${key}`, { folder: null });
    await admin.api.projects.update(PROJECT, { folder: null });
  }
  return 'a filed secret is read and run by its own name, by the same people; only writers file it';
}

/**
 * A fork copies dev's values into a new environment, and nothing of who
 * may read dev: a viewer on dev reads neither the fork nor makes one.
 */
export async function forks({ admin, reader }: People, canaries: Canaries): Promise<string> {
  const dev = valuesIn(canaries, DEV);
  await refused('a viewer forked an environment', reader.api.environments.create(FORKED, { name: 'Forked', from: DEV.split('/')[1]! }));
  const made = await admin.api.environments.create(FORKED, { name: 'Forked', from: DEV.split('/')[1]! });
  try {
    expect(made.forked?.keys === Object.keys(dev).length, "the fork did not copy each of dev's keys", made);
    const read = await admin.api.secrets.reveal(FORKED);
    expect(JSON.stringify(Object.entries(read.values).sort()) === JSON.stringify(Object.entries(dev).sort()), "the fork's values are not dev's");
    const history = await admin.api.secrets.history(`${FORKED}/${Object.keys(dev)[0]}`);
    expect(history.versions.length === 1, 'the fork carried history', history.versions);
    await refused("a viewer on dev read dev's fork", reader.api.secrets.reveal(FORKED));
  } finally {
    await admin.api.environments.update(FORKED, { archived: true });
  }
  return "a fork holds dev's values and no history, and a viewer on dev neither makes one nor reads it";
}
