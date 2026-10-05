// What arranges and fills environments: folders, which change nothing but
// how lists read (docs/design/environments.md).
import { expect, refused } from '../report.ts';
import { DEV, PROJECT, valuesIn, type Canaries, type People } from './people.ts';

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
