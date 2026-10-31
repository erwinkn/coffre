// What arranges and fills environments: folders, which change nothing but
// how lists read, forks, and references, which the vault seals
// (docs/design/environments.md).
import { randomUUID } from 'node:crypto';

import { CoffreError } from '@coffre/client';

import { using } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect, refused } from '../report.ts';
import { canary, DEV, PROD, PROJECT, valuesIn, type Canaries, type People } from './people.ts';
import { query } from './storage.ts';
import { listed } from './audit.ts';

/** A read of one key refused, whatever the reason (D153): `outcome`'s status and code. */
const NO = '404 not_available';

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

/** Where the inheritance check forks prod; archived once checked. */
const INHERITS = `${PROJECT}/prod-inherits`;

/**
 * A fork that inherits reads its parent's values live and copies none, and
 * lends nothing (docs/design/forking.md): the reader, a viewer on dev given
 * the fork alone, reads none of what it inherits from prod.
 */
export async function inheritance({ admin, reader }: People, canaries: Canaries): Promise<string> {
  const prod = valuesIn(canaries, PROD);
  const [key] = Object.keys(prod);
  expect(key !== undefined, 'prod holds no secret to inherit');
  const made = await admin.api.environments.create(INHERITS, { from: PROD.split('/')[1]!, inherit: true });
  try {
    expect(made.forked?.inherits === true && made.forked.keys === 0, 'a fork that inherits copied something', made);
    const read = await admin.api.secrets.reveal(INHERITS);
    expect(JSON.stringify(Object.entries(read.values).sort()) === JSON.stringify(Object.entries(prod).sort()), "the fork does not read prod's values");
    const listed = await admin.api.secrets.list(INHERITS);
    expect(listed.keys.every((each) => each.parent?.state === 'inherited'), 'a key the fork inherits is not listed as inherited', listed.keys);

    await admin.api.access.set(reader.member, { [INHERITS]: 'viewer' });
    try {
      await refused("a reader of the fork alone read what it inherits from prod", reader.api.secrets.reveal(INHERITS));
      await refused("a reader of the fork alone read one key it inherits from prod", reader.api.secrets.reveal(`${INHERITS}/${key}`));
    } finally {
      await admin.api.access.set(reader.member, { [INHERITS]: null });
    }
  } finally {
    await admin.api.environments.update(INHERITS, { archived: true });
  }
  return "a fork that inherits prod reads prod's values, copies none, and lends none to a reader of the fork alone";
}

/** The key the reader keeps in their personal dev, which goes with it once checked. */
const PERSONAL = 'CONFORMANCE_PERSONAL';

/**
 * A personal config's values are its owner's alone (docs/design/forking.md,
 * R8): the reader, a viewer on dev, keeps a value in `dev@me` and reads it;
 * the admin, an Owner of the whole instance, sees that it exists and its
 * key's name, and reads none of it, and their own `dev@me` is dev; and a
 * row made the admin's around coffre, in the database, opens nothing,
 * since the vault bound the value to its owner.
 */
export async function personalConfigs(deployment: Deployment, { admin, reader }: People): Promise<string> {
  const mine = `${DEV}@me`;
  const value = canary();
  await reader.api.secrets.set(mine, { [PERSONAL]: value });
  try {
    expect((await reader.api.secrets.reveal(`${mine}/${PERSONAL}`)).values[PERSONAL] === value, 'the reader did not read their own personal value');
    const config = (await admin.api.environments.personal(PROJECT)).configs.find((each) => each.owner === reader.member);
    expect(config?.keys.includes(PERSONAL) === true, "the reader's personal config, or its key's name, is not listed to the admin", config);
    expect((await outcome(admin.api.secrets.reveal(`${PROJECT}/${config!.slug}`))).startsWith('403 '), "an Owner of the instance read a member's personal config");
    const theirs = await admin.api.secrets.reveal(mine);
    expect(!(PERSONAL in theirs.values), "the admin's dev@me read the reader's personal value");

    const owner = async (member: string) => using(deployment.database(), (sql) =>
      query(sql, 'UPDATE environments SET owner = $1 WHERE slug = $2', [member, config!.slug]));
    await owner(admin.member);
    try {
      const forged = await outcome(admin.api.secrets.reveal(`${mine}/${PERSONAL}`));
      expect(forged !== 'let through', 'a personal config made the admin\'s in the database opened for them');
    } finally {
      await owner(reader.member);
    }
  } finally {
    await reader.api.environments.delete(mine);
  }
  return "a personal value is read by its owner alone: an Owner sees its key's name, reads none of it, and a forged owner opens nothing";
}

/** The key in dev the reference check makes, archived once checked. */
const HELD = 'CONFORMANCE_REFERENCE';
/** The key a forged reference row is held by, a new one each run: it is archived after, and its name stays taken (`references`). */
const FORGED = `CONFORMANCE_FORGED_${randomUUID().slice(0, 8).toUpperCase()}`;

/** The status a call failed with and its reason, the vault's or the app's, or that it went through. */
async function outcome(call: Promise<unknown>): Promise<string> {
  try {
    await call;
    return 'let through';
  } catch (error) {
    if (!(error instanceof CoffreError)) throw error;
    return `${error.status} ${error.reason ?? error.code}`;
  }
}

/**
 * A reference lets whoever reads its holder read its source, so only the
 * vault makes one, and a read through one is checked against the vault's
 * own entry: the reader, a viewer on dev with no grant on prod, reads
 * prod's value through dev's reference, and the read is in prod's log and
 * dev's; a reference row the vault never made, written straight into the
 * database, reads nothing; a developer on dev who cannot read prod makes
 * none; and once broken, it reads no more.
 */
export async function references(deployment: Deployment, { admin, reader, leaver }: People, canaries: Canaries): Promise<string> {
  const [sourceKey] = Object.keys(valuesIn(canaries, PROD));
  expect(sourceKey !== undefined, 'prod holds no secret to refer to');
  const source = `${PROD}/${sourceKey}`;
  await refused('a viewer on dev read prod directly', reader.api.secrets.reveal(source));
  expect(await outcome(leaver.api.secrets.set(DEV, { [HELD]: { ref: source } })) === '403 missing_secret_read',
    "a developer on dev who cannot read prod made a reference to prod's secret");

  await admin.api.secrets.set(DEV, { [HELD]: { ref: source } });
  try {
    const read = await reader.api.secrets.reveal(`${DEV}/${HELD}`);
    expect(read.values[HELD] === canaries[source], "a viewer on dev did not read prod's value through dev's reference");
    const logged = async (path: string) => (await admin.api.audit.list({ path, limit: 200, sealed: '1' })).entries
      .filter((entry) => entry.action === 'secret.read' && entry.actorId === reader.email && entry.metadata.via !== undefined).length;
    // Listed once sealed and projected, a tick or two on (T166).
    expect(await listed(async () => await logged(PROD) >= 1 && await logged(DEV) >= 1), "the read through the reference is not in both the source's log and the holder's");

    // What it reads cannot be archived while it reads it (D41): not the key, nor its environment. Its
    // project could be, since the reference is held there too, and archiving it stops no one else's read.
    const archives: [string, (archived: boolean) => Promise<unknown>][] = [
      [source, (archived) => admin.api.secrets.update(source, { archived })],
      [PROD, (archived) => admin.api.environments.update(PROD, { archived })],
    ];
    for (const [what, archive] of archives) {
      const refusal = await archive(true).then(() => null, (error: unknown) => error);
      if (refusal === null) await archive(false);
      expect(refusal instanceof CoffreError && refusal.status === 409 && refusal.message.includes(`${DEV}/${HELD} reads ${source}`),
        `${what} was archived, or refused without naming the reference, while a reference read it`, refusal instanceof Error ? refusal.message : refusal);
    }
    // Unless what holds it is archived (D58): nobody reads through it then, so its source archives. Restored,
    // the holder reads nothing through it until its source is back, and says so.
    await admin.api.secrets.update(`${DEV}/${HELD}`, { archived: true });
    const underArchived = await outcome(admin.api.secrets.update(source, { archived: true })).finally(() => admin.api.secrets.update(`${DEV}/${HELD}`, { archived: false }));
    try {
      expect(underArchived === 'let through', `${source} could not be archived while only an archived key referred to it: ${underArchived}`);
      const restored = await outcome(reader.api.secrets.reveal(`${DEV}/${HELD}`));
      // One key's refusal is the one "no" (D153): no reason, which the audit log keeps.
      expect(restored === NO, `a reference read a source archived while its holder was: ${restored}`);
    } finally {
      if (underArchived === 'let through') await admin.api.secrets.update(source, { archived: false });
    }
    const back = await reader.api.secrets.reveal(`${DEV}/${HELD}`);
    expect(back.values[HELD] === canaries[source], 'a reference did not read its source again once both were restored');

    // A row the vault never sealed: a reference to prod, held in dev, pointing at a vault entry about something else.
    const forged = await using(deployment.database(), async (sql) => {
      const [holder] = await query<{ id: string; project_id: string; environment_id: string }>(sql,
        'SELECT id, project_id, environment_id FROM secrets WHERE key = $1', [HELD]);
      const [target] = await query<{ id: string; project_id: string; environment_id: string }>(sql,
        'SELECT s.id, s.project_id, s.environment_id FROM secrets s JOIN environments e ON e.id = s.environment_id WHERE s.key = $1 AND e.slug = $2', [sourceKey, PROD.split('/')[1]]);
      const [entry] = await query<{ seq: number | string | bigint }>(sql,
        "SELECT seq FROM audit_log WHERE author = 'vault' AND action = 'access.grant' AND decision = 'allow' ORDER BY seq DESC LIMIT 1");
      const id = randomUUID();
      await query(sql, 'INSERT INTO secrets (id, project_id, environment_id, key, current_version) VALUES ($1, $2, $3, $4, 0)', [id, holder!.project_id, holder!.environment_id, FORGED]);
      await query(sql, `INSERT INTO secret_references (id, project_id, environment_id, secret_id, source_project_id, source_environment_id, source_secret_id, created_seq, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, [randomUUID(), holder!.project_id, holder!.environment_id, id, target!.project_id, target!.environment_id, target!.id, String(entry!.seq), admin.member]);
      return id;
    });
    try {
      const forgedRead = await outcome(reader.api.secrets.reveal(`${DEV}/${FORGED}`));
      // Read from its seal, the row is no reference at all, and its key holds no value; the vault would refuse it anyway.
      expect(['404 no_value', '404 not_found', '403 bad_claim', NO].includes(forgedRead), `a reference row the vault never made was read: ${forgedRead}`);
    } finally {
      // Its row goes, and the key is archived, not deleted: with 0.15's log, the refused read is the app's entry, which
      // names the key, and the log keeps every entry.
      await using(deployment.database(), async (sql) => {
        await query(sql, 'DELETE FROM secret_references WHERE secret_id = $1', [forged]);
        await query(sql, sql.engine === 'postgres' ? 'UPDATE secrets SET archived_at = now() WHERE id = $1' : 'UPDATE secrets SET archived_at = CAST(unixepoch(\'subsec\') * 1000 AS INTEGER) WHERE id = $1', [forged]);
      });
    }

    await admin.api.references.break(`${DEV}/${HELD}`);
    const after = await outcome(reader.api.secrets.reveal(`${DEV}/${HELD}`));
    expect(after === NO, `a broken reference still read: ${after}`);
  } finally {
    await admin.api.secrets.update(`${DEV}/${HELD}`, { archived: true });
  }
  return "a viewer on dev reads prod's value through a reference, logged in both; prod and its key cannot be archived while it reads them, but can once its holder is archived, which then reads nothing until they are back; a forged row is refused, a broken one reads no more, and none is made without read on the source";
}

/** A key prod has and dev does not, for the missing-keys check; archived once checked. */
const PROD_ONLY = 'CONFORMANCE_PROD_ONLY';

const LOOSE = 'CONFORMANCE_LOOSENED';

/**
 * A sensitive value is made a secret in place by an Owner alone (R30): the
 * leaver, a developer on dev, is refused, and told the listing does not
 * offer it; the admin's mark answers no value, and the reader, a viewer on
 * dev, reads it after, as a secret, its old version still sensitive. Its
 * own `secret.loosen`, which "keys behind writes" holds to the vault's
 * `key.rewrap`. The key is archived after.
 */
export async function loosening({ admin, reader, leaver }: People): Promise<string> {
  const value = canary();
  const path = `${DEV}/${LOOSE}`;
  await admin.api.secrets.set(DEV, { [LOOSE]: { value, sensitivity: 'sensitive' } });
  try {
    await refused('a viewer read a sensitive value', reader.api.secrets.reveal(path));
    expect((await leaver.api.secrets.list(DEV)).loosenable === false, 'a developer on dev is told they make a sensitive value a secret in place');
    await refused('a developer on dev made a sensitive value a secret in place', leaver.api.secrets.set(DEV, { [LOOSE]: { sensitivity: 'secret' } }));
    expect((await admin.api.secrets.list(DEV)).loosenable === true, 'the admin, an Owner of the whole instance, is told they do not loosen');
    const marked = await admin.api.secrets.set(DEV, { [LOOSE]: { sensitivity: 'secret' } });
    expect(!JSON.stringify(marked).includes(value), "the admin's loosening answered the value", marked);
    expect(JSON.stringify(marked.keys[LOOSE]) === JSON.stringify({ version: 2, sensitivity: 'secret' }), 'the loosening made no new secret version', marked.keys);
    const read = await reader.api.secrets.reveal(path);
    expect(read.values[LOOSE] === value, "the reader did not read the loosened value as dev's secret");
    const versions = (await admin.api.secrets.history(path)).versions.map((version) => version.sensitivity);
    expect(versions.join() === 'secret,sensitive', 'the loosening changed the old version too, or made none', versions);
    const logged = (await admin.api.audit.list({ path, limit: 50 })).entries.filter((entry) => entry.action === 'secret.loosen');
    expect(logged.length === 1 && logged[0]!.metadata.from === 'sensitive' && logged[0]!.metadata.to === 'secret', 'the loosening is not its own entry, saying both levels', logged);
  } finally {
    await admin.api.secrets.set(DEV, { [LOOSE]: null });
  }
  return 'the admin makes a sensitive value a secret in place, answered no value, as a new version, logged as secret.loosen; a developer on dev may not';
}

/**
 * Within a project, key names are not secret; values are. What dev is
 * missing is compared with every sibling: the reader, a viewer on dev who
 * cannot read prod, is told prod has the key, as the admin is, and nothing
 * of its value, and dismisses nothing. A dismissal is the team's, and
 * restoring undoes it.
 */
export async function missingKeys({ admin, reader }: People): Promise<string> {
  const value = canary();
  await admin.api.secrets.set(PROD, { [PROD_ONLY]: value });
  try {
    const seen = await admin.api.environments.missing(DEV);
    expect(seen.missing.some((key) => key.key === PROD_ONLY), "the admin was not told dev lacks prod's key", seen);
    const told = await reader.api.environments.missing(DEV);
    expect(told.missing.some((key) => key.key === PROD_ONLY && key.in.includes('prod')), "a viewer on dev was not told dev lacks prod's key, by name", told);
    expect(!JSON.stringify(told).includes(value), "a viewer on dev was told prod's value with its key's name");
    await refused('a viewer dismissed a missing key', reader.api.environments.dismiss(DEV, { [PROD_ONLY]: true }));
    await admin.api.environments.dismiss(DEV, { [PROD_ONLY]: true });
    const dismissed = await admin.api.environments.missing(DEV);
    expect(dismissed.dismissed.some((key) => key.key === PROD_ONLY) && !dismissed.missing.some((key) => key.key === PROD_ONLY), 'a dismissed key was still listed as missing', dismissed);
    await admin.api.environments.dismiss(DEV, { [PROD_ONLY]: null });
    expect((await admin.api.environments.missing(DEV)).missing.some((key) => key.key === PROD_ONLY), 'a restored key was not missing again');
  } finally {
    await admin.api.secrets.update(`${PROD}/${PROD_ONLY}`, { archived: true });
  }
  return "a viewer on dev learns prod's key name, not its value, and dismisses nothing; a dismissal is listed, and restored";
}
