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

/** The key in dev the reference check makes, archived once checked. */
const HELD = 'CONFORMANCE_REFERENCE';
const FORGED = 'CONFORMANCE_FORGED';

/** The status a call failed with, and the vault's reason, or the value it gave. */
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
  expect(await outcome(leaver.api.secrets.set(DEV, { [HELD]: { ref: source } })) === '403 forbidden',
    "a developer on dev who cannot read prod made a reference to prod's secret");

  await admin.api.secrets.set(DEV, { [HELD]: { ref: source } });
  try {
    const read = await reader.api.secrets.reveal(`${DEV}/${HELD}`);
    expect(read.values[HELD] === canaries[source], "a viewer on dev did not read prod's value through dev's reference");
    const logged = async (path: string) => (await admin.api.audit.list({ path, limit: 200 })).entries
      .filter((entry) => entry.action === 'secret.read' && entry.actorId === reader.email && entry.metadata.via !== undefined).length;
    expect(await logged(PROD) >= 1 && await logged(DEV) >= 1, "the read through the reference is not in both the source's log and the holder's");

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
      expect(['404 not_found', '403 bad_claim'].includes(forgedRead), `a reference row the vault never made was read: ${forgedRead}`);
    } finally {
      await using(deployment.database(), async (sql) => {
        await query(sql, 'DELETE FROM secret_references WHERE secret_id = $1', [forged]);
        await query(sql, 'DELETE FROM secrets WHERE id = $1', [forged]);
      });
    }

    await admin.api.references.break(`${DEV}/${HELD}`);
    const after = await outcome(reader.api.secrets.reveal(`${DEV}/${HELD}`));
    expect(after === '409 conflict', `a broken reference still read: ${after}`);
  } finally {
    await admin.api.secrets.update(`${DEV}/${HELD}`, { archived: true });
  }
  return "a viewer on dev reads prod's value through a reference, logged in both; prod and its key cannot be archived while it reads them; a forged row is refused, a broken one reads no more, and none is made without read on the source";
}

/** A key prod has and dev does not, for the missing-keys check; archived once checked. */
const PROD_ONLY = 'CONFORMANCE_PROD_ONLY';

/**
 * Key names are metadata: what dev is missing is compared only with the
 * environments the viewer reads. The admin sees prod's key missing from dev;
 * the reader, a viewer on dev alone, sees nothing of prod, and dismisses
 * nothing. A dismissal is the team's, and restoring undoes it.
 */
export async function missingKeys({ admin, reader }: People): Promise<string> {
  await admin.api.secrets.set(PROD, { [PROD_ONLY]: canary() });
  try {
    const seen = await admin.api.environments.missing(DEV);
    expect(seen.missing.some((key) => key.key === PROD_ONLY), "the admin was not told dev lacks prod's key", seen);
    const hidden = await reader.api.environments.missing(DEV);
    expect(![...hidden.missing, ...hidden.dismissed].some((key) => key.key === PROD_ONLY), "a viewer on dev learned a key name from prod, which they cannot read", hidden);
    await refused('a viewer dismissed a missing key', reader.api.environments.dismiss(DEV, { [PROD_ONLY]: true }));
    await admin.api.environments.dismiss(DEV, { [PROD_ONLY]: true });
    const dismissed = await admin.api.environments.missing(DEV);
    expect(dismissed.dismissed.some((key) => key.key === PROD_ONLY) && !dismissed.missing.some((key) => key.key === PROD_ONLY), 'a dismissed key was still listed as missing', dismissed);
    await admin.api.environments.dismiss(DEV, { [PROD_ONLY]: null });
    expect((await admin.api.environments.missing(DEV)).missing.some((key) => key.key === PROD_ONLY), 'a restored key was not missing again');
  } finally {
    await admin.api.secrets.update(`${PROD}/${PROD_ONLY}`, { archived: true });
  }
  return "only who reads prod learns what dev lacks of it; a viewer dismisses nothing; a dismissal is listed, and restored";
}
