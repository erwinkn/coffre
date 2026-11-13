import { createHash, createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

import { definitionProblem, EVERYWHERE, INSTANCE_ROLES, isInstanceRole, isScope, ROLES, type RoleDefinition } from '@coffre/core/access';
import { decrypt, ownerKey } from '@coffre/core/envelope';
import type { Database, Transaction } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { auditArchive, environments, policy, principals, roles, secrets, secretVersions } from '@coffre/db/schema';
import { and, desc, eq, inArray, sql } from 'drizzle-orm';

import type { ResolvedVaultConfig } from './config.ts';
import { CHANGE_LOCK, type Running } from './change.ts';
import { pending } from './entry.ts';
import { fromWire, seal, shapeOf, toWire, type Wire } from './rows.ts';
import { ADOPTION, MIRRORED } from './signer.ts';

/**
 * The vault's adoption of a database (docs/design/0.16.md, "Upgrade from
 * 0.14"): what the upgrade needs the vault's keys for, which `coffre
 * migrate` does not hold, in one transaction. The migration left 0.14's rows
 * reshaped, every starred one with an empty MAC; a fresh install's are
 * empty. The adoption
 *
 * 1. writes the roles, the policy row, which environments are protected and
 *    whether the instance is frozen, from 0.14's newest `policy.change` and
 *    `settings.change`, each held to 0.14's vault MAC, and makes the Owners
 *    the configuration names;
 * 2. wraps each version's data key again, as envelope format 2, which names
 *    its number and whether it is plain;
 * 3. MACs every starred row;
 * 4. writes the log's first entry, which pins 0.14's chain and counts what
 *    it adopted.
 *
 * Then the signer, taking that first entry, fills its mirror from the rows
 * (`sign` in signer.ts). Until it has, the database is not `adopted`.
 */

/** Who wrote what the vault writes of itself, as 0.14 named it. */
const VAULT = 'system:vault';

/** What the adoption needs of the vault's configuration: its keys, and its Owners. */
type Config = Pick<ResolvedVaultConfig, 'keks' | 'owners' | 'signingKeys'>;

/**
 * Adopt the database, unless it began a log already: then nothing is done.
 * Whether it adopted it now. Taken under the change lock, so two vaults
 * starting at once adopt once: the second waits, then finds the first's
 * entry. Throws, having written nothing, on anything it cannot vouch for.
 */
export async function adopt(vault: Running, config: Config): Promise<boolean> {
  const entry = await vault.db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${sql.raw(String(CHANGE_LOCK))})`);
    // An entry waiting is a log begun, as much as a head: one adopted and not yet signed.
    const [{ begun }] = await rowsOf<{ begun: boolean }>(tx, sql`SELECT EXISTS (SELECT FROM log_head) OR EXISTS (SELECT FROM log) OR EXISTS (SELECT FROM log_pending) AS begun`);
    if (begun) return null;
    const archive = { keys: config.signingKeys.map(legacyKey), tx };
    const edits = editsOf(await newest(archive, 'policy.change'));
    const stored = await newest(archive, 'settings.change');
    const settings = stored === null ? EVERYWHERE : stored.serviceAccounts;
    if (!isScope(settings)) throw new Error("0.14's newest settings.change holds no service account setting");
    const [freeze] = await tx
      .select({ action: auditArchive.action, at: auditArchive.occurredAt })
      .from(auditArchive)
      .where(and(eq(auditArchive.author, 'app'), inArray(auditArchive.action, ['workload.freeze', 'workload.unfreeze']), eq(auditArchive.decision, 'allow'), sql`${auditArchive.metadata}::jsonb ->> 'target' = 'instance'`))
      .orderBy(desc(auditArchive.seq))
      .limit(1);
    const wrapped = await wrapAgain(tx, config.keks);

    const at = new Date(vault.now());
    await tx.insert(roles).values([...roleRows(false, { ...ROLES, ...edits.roles }), ...roleRows(true, { ...INSTANCE_ROLES, ...edits.instanceRoles })]);
    await tx.insert(policy).values({ onlyRow: true, serviceAccounts: JSON.stringify(settings), workloadsFrozenAt: freeze?.action === 'workload.freeze' ? new Date(freeze.at) : null, changedAt: at, changedBy: VAULT });
    if (edits.protected.length > 0) await tx.update(environments).set({ protected: true }).where(inArray(environments.id, edits.protected));
    if (config.owners.length > 0) {
      const named = config.owners.map((email) => ({ id: `user:${email}`, status: 'active', role: 'owner', scope: null, generation: 0, createdAt: at, createdBy: VAULT, statusChangedAt: at, statusChangedBy: VAULT, frozenAt: null }));
      // One the deployment names is an Owner of the whole instance, brought back if removed, as 0.14 made one at each start.
      const kept = sql`${principals.status} = 'active'`;
      await tx.insert(principals).values(named).onConflictDoUpdate({
        target: principals.id,
        set: { role: 'owner', scope: null, status: 'active', statusChangedAt: sql`CASE WHEN ${kept} THEN ${principals.statusChangedAt} ELSE excluded.status_changed_at END`, statusChangedBy: sql`CASE WHEN ${kept} THEN ${principals.statusChangedBy} ELSE excluded.status_changed_by END` },
      });
    }
    if (wrapped.length > 0) {
      await tx.execute(sql`UPDATE secret_versions v SET envelope_version = 2, wrapped_dek = decode(j.dek, 'hex'), kek_provider = j.provider, kek_id = j.kek, kek_version = j.version
        FROM jsonb_to_recordset(${JSON.stringify(wrapped)}::jsonb) AS j(id uuid, dek text, provider text, kek text, version text) WHERE v.id = j.id`);
    }

    const counts: Record<string, number> = { secret_versions: wrapped.length };
    for (const table of MIRRORED) counts[shapeOf(table).name] = await sealAll(tx, vault.keys[0]!, table);
    const [last] = await tx.select({ seq: auditArchive.seq, hash: auditArchive.hash }).from(auditArchive).orderBy(desc(auditArchive.seq)).limit(1);
    const first = pending(
      vault.keys[0]!,
      { kept: true, action: ADOPTION, actor: null, credential: null, request: null, ip: null, objects: [], detail: { archive: last === undefined ? null : { seq: Number(last.seq), hash: last.hash.toString('hex') }, rows: counts } },
      vault.now(),
      [],
    );
    await tx.execute(sql`INSERT INTO log_pending (kept, body, mac) VALUES (true, ${first.body}, decode(${first.mac.toString('hex')}, 'hex'))`);
    return first;
  });
  if (entry === null) return false;
  vault.wake(entry.hash);
  return true;
}

/** Whether the vault may serve: the adoption's entry is signed, and the signer's mirror filled. */
export async function adopted(db: Database): Promise<boolean> {
  const [{ signed }] = await rowsOf<{ signed: boolean }>(db, sql`SELECT EXISTS (SELECT FROM log_head) AS signed`);
  return signed;
}

/** MAC every row of `table` as it stands: how many. One statement to read them, one to write their MACs. */
async function sealAll(tx: Transaction, key: Running['keys'][number], table: (typeof MIRRORED)[number]): Promise<number> {
  const shape = shapeOf(table);
  const found = await rowsOf<{ row: Wire }>(tx, sql`SELECT to_jsonb(${table}) AS row FROM ${table}`);
  if (found.length === 0) return 0;
  const macs = found.map(({ row: wire }) => {
    const row = fromWire(table, wire);
    return { ...toWire(table, row, shape.key), mac: `\\x${seal(key, table, row).toString('hex')}` };
  });
  const onKey = sql.join(shape.key.map(({ name }) => sql`${table}.${sql.identifier(name)} = j.${sql.identifier(name)}`), sql` AND `);
  await tx.execute(sql`UPDATE ${table} SET mac = j.mac FROM jsonb_populate_recordset(null::${table}, ${JSON.stringify(macs)}::jsonb) j WHERE ${onKey}`);
  return found.length;
}

/**
 * Each version 0.14 wrote, its data key wrapped again as format 2: opened
 * under what 0.14's wrap names (its secret, a personal config's owner,
 * whether it is sensitive), its value decrypted, and wrapped under its
 * number and, for one 0.14 marked plain, as plain. 0.14 knew a plain value
 * only by its `plaintext` column, which nothing protects, so one is taken as
 * plain only if its value is that column's. A version 0.14 erased, with no
 * ciphertext and no key, has nothing to wrap, and keeps its label.
 */
async function wrapAgain(tx: Transaction, keks: Config['keks']) {
  const versions = await tx
    .select({ version: secretVersions, projectId: secrets.projectId, environmentId: secrets.environmentId, owner: environments.owner })
    .from(secretVersions)
    .innerJoin(secrets, eq(secrets.id, secretVersions.secretId))
    .innerJoin(environments, eq(environments.id, secrets.environmentId))
    .where(and(eq(secretVersions.envelopeVersion, 1), sql`octet_length(${secretVersions.ciphertext}) + octet_length(${secretVersions.wrappedDek}) > 0`));
  return Promise.all(
    versions.map(async ({ version, projectId, environmentId, owner }) => {
      const ids = { projectId, environmentId, secretId: version.secretId };
      const named = { ...ids, ...(owner === null ? {} : { owner: ownerKey(owner) }), ...(version.sensitive ? { sensitive: true as const } : {}) };
      const what = `version ${version.version} of secret ${version.secretId}`;
      const dek = await keks.unwrap({ kekProvider: version.kekProvider, kekId: version.kekId, kekVersion: version.kekVersion, bytes: version.wrappedDek }, named).catch((error: unknown) => {
        throw new Error(`${what} does not open: ${String(error)}`, { cause: error });
      });
      try {
        const plain = version.plaintext !== null;
        let value: Buffer;
        try {
          value = decrypt(version, ids, dek);
        } catch (error) {
          throw new Error(`${what} does not open: ${String(error)}`, { cause: error });
        }
        const same = !plain || value.equals(Buffer.from(version.plaintext!, 'utf8'));
        value.fill(0);
        if (!same) throw new Error(`${what} is marked plain, and its value is not its plaintext column: someone wrote the row behind 0.14`);
        const again = await keks.wrap(dek, { ...named, version: version.version, ...(plain ? { plain: true as const } : {}) });
        return { id: version.id, dek: again.bytes.toString('hex'), provider: again.kekProvider, kek: again.kekId, version: again.kekVersion };
      } finally {
        dek.fill(0);
      }
    }),
  );
}

function roleRows(instance: boolean, definitions: Readonly<Record<string, RoleDefinition>>) {
  return Object.entries(definitions).map(([id, definition]) => ({ instance, id, name: definition.name, description: definition.description, permissions: [...definition.permissions], protected: [...definition.protected] }));
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * What 0.14's `policy.change` keeps (`PolicyEdits` in its vault): the roles
 * an Owner edited or made, each whole, and the protected environments. A
 * role as it ships is in none: its definition is the code's. None, for an
 * instance whose policy nobody changed.
 */
function editsOf(metadata: Record<string, unknown> | null): { roles: Record<string, RoleDefinition>; instanceRoles: Record<string, RoleDefinition>; protected: string[] } {
  if (metadata === null) return { roles: {}, instanceRoles: {}, protected: [] };
  const { roles: edited, instanceRoles, protected: places } = (metadata.policy ?? {}) as { roles?: unknown; instanceRoles?: unknown; protected?: unknown };
  const definitions = (table: unknown): table is Record<string, RoleDefinition> => typeof table === 'object' && table !== null && Object.values(table).every((definition) => definitionProblem(definition as RoleDefinition) === null);
  if (!definitions(edited) || !definitions(instanceRoles) || !Object.keys(instanceRoles).every(isInstanceRole) || !Array.isArray(places)) throw new Error("0.14's newest policy.change holds no policy");
  const ids = places.map((place) => (place as { environmentId?: unknown } | null)?.environmentId);
  if (!ids.every((id): id is string => typeof id === 'string' && UUID.test(id))) throw new Error("0.14's newest policy.change names a protected environment by no id");
  return { roles: edited, instanceRoles, protected: ids };
}

// 0.14's audit chain (its @coffre/core/audit), as much of it as checks that an entry is its vault's.

/** 0.14's vault log key from one of the vault's signing keys, and the id its entries record. */
function legacyKey(seed: Uint8Array): { id: string; key: Buffer } {
  const key = Buffer.from(hkdfSync('sha256', seed, new Uint8Array(0), 'coffre.audit.vault.v2', 32));
  return { id: `vault:${createHash('sha256').update(key).digest('hex').slice(0, 16)}`, key };
}

/** What an entry's MAC covers, in its order, after its previous hash. */
const FIELDS = ['seq', 'author', 'keyId', 'occurredAt', 'actor', 'action', 'decision', 'code', 'subjectPrincipal', 'projectId', 'environmentId', 'secretId', 'secretVersionId', 'operationId', 'requestId', 'sourceIp', 'relatedSeq', 'metadata'] as const;

/**
 * The newest entry 0.14's vault allowed with `action`, by what it holds,
 * once held to its MAC: HMAC-SHA256 over a domain, the previous hash, then
 * each field, its length first (-1 for null), numbers in decimal. One in
 * the vault's name it did not write stops the adoption.
 */
async function newest(archive: { keys: { id: string; key: Buffer }[]; tx: Transaction }, action: string): Promise<Record<string, unknown> | null> {
  const [entry] = await archive.tx.select().from(auditArchive).where(and(eq(auditArchive.author, 'vault'), eq(auditArchive.action, action), eq(auditArchive.decision, 'allow'))).orderBy(desc(auditArchive.seq)).limit(1);
  if (entry === undefined) return null;
  const key = archive.keys.find((candidate) => candidate.id === entry.keyId);
  const mac = createHmac('sha256', key?.key ?? Buffer.alloc(32)).update('coffre.audit.mac.v2').update(entry.prevHash);
  for (const field of FIELDS) {
    const value = entry[field] === null ? null : Buffer.from(String(entry[field]), 'utf8');
    const length = Buffer.alloc(4);
    length.writeInt32BE(value === null ? -1 : value.length);
    mac.update(length);
    if (value !== null) mac.update(value);
  }
  if (key === undefined || entry.mac.length !== 32 || !timingSafeEqual(mac.digest(), entry.mac)) {
    throw new Error(`0.14's newest ${action}, entry ${entry.seq} of audit_archive, does not carry its vault's MAC: it was written behind 0.14, or the vault is given another signing key than 0.14's`);
  }
  return JSON.parse(entry.metadata) as Record<string, unknown>;
}
