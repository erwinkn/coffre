// Holds coffre's access rules, the vault's per-key decision, the AAD encoding
// and the audit chain's verifier to their Lean model, case by case
// (docs/formal.md). Each case runs through the TypeScript here and through
// formal/lean's oracle, which runs the model the proofs are about; any answer
// that differs fails the run and prints the case.
//
//   node --conditions=coffre:source scripts/formal-lean.ts <oracle> [--long] [--seed=<n>]
//
// scripts/formal-lean.sh builds the oracle and runs this.
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';

import {
  allows,
  DEFAULT_POLICY,
  givesService,
  heldColumns,
  INSTANCE_ROLES,
  issuedGrant,
  issuesCredential,
  makesProjects,
  managesService,
  mayManageAccess,
  ownsProject,
  PERMISSIONS,
  readsSensitive,
  readsWholeLog,
  ROLES,
  runsInstance,
  withinCredential,
  type Columns,
  type CredentialScope,
  type Filter,
  type Holdings,
  type Permission,
  type Place,
  type Policy,
  type RoleDefinition,
  type Scope,
  type ScopeGrant,
  type ServiceAccount,
} from '../packages/core/src/access.ts';
import { deriveLogKey, GENESIS_HASH, entryHash, entryMac, sealEntry, verifyEntries, type LogFields, type LogKey, type StoredEntry } from '../packages/core/src/audit/chain.ts';
import { encodeAad, type SecretContext } from '../packages/core/src/context.ts';
import { handsBack, type RefusalCode } from '../packages/core/src/vault.ts';
import { keyRefusals, referenceRefusal, sensitiveRefusals, type Reader, type SecretPlace } from '../packages/vault/src/decide.ts';
import type { EnvironmentRow } from '../packages/vault/src/store.ts';

const [oracle, ...flags] = process.argv.slice(2);
if (oracle === undefined || !flags.every((flag) => flag === '--long' || /^--seed=\d+$/.test(flag))) {
  throw new Error('Usage: scripts/formal-lean.ts <oracle> [--long] [--seed=<unsigned integer>]');
}
const seedFlag = flags.find((flag) => flag.startsWith('--seed='));
const seed = seedFlag === undefined ? 20261024 : Number(seedFlag.slice('--seed='.length));
const scale = flags.includes('--long') ? 10 : 1;

// mulberry32: a seeded generator, so that a run's cases are the same everywhere.
let state = seed >>> 0;
function random(): number {
  state = (state + 0x6d2b79f5) >>> 0;
  let t = state;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const chance = (p: number) => random() < p;
const pick = <T>(items: readonly T[]): T => items[Math.floor(random() * items.length)]!;
const some = <T>(items: readonly T[], max = items.length): T[] => {
  const n = Math.floor(random() * (max + 1));
  return Array.from({ length: n }, () => pick(items));
};
const unique = <T>(items: T[]): T[] => [...new Set(items)];

// A small world, so that places, grants and scopes meet often: two projects, their environments by id
// (`<project>/<slug>`), a fork, a personal config, and ids no row has.
const PROJECTS = ['market', 'ops'] as const;
// Names a plain object holds already: no lookup of the code's may find them.
const INHERITED = ['constructor', '__proto__', 'toString'] as const;
const SLUGS = ['dev', 'prod', 'fork'] as const;
const ENVIRONMENTS = [...PROJECTS.flatMap((project) => SLUGS.map((slug) => `${project}/${slug}`)), 'market/dev@ada', 'ghost', ''];
const ROLE_NAMES = [...Object.keys(ROLES), 'custom', 'ghost', ...INHERITED];
const INSTANCE_ROLE_NAMES = [...Object.keys(INSTANCE_ROLES), 'ghost', ...INHERITED];
const PEOPLE = ['user:ada', 'user:bo', 'token:ci', 'service:deploy'];

const slugOf = (environmentId: string): string | null => (environmentId.includes('/') ? environmentId.split('/')[1]!.replace('@ada', '') : null);
const projectOf = (environmentId: string): string => (environmentId.includes('/') ? environmentId.split('/')[0]! : pick(PROJECTS));

const column = (): Permission[] => unique(some(PERMISSIONS, 5));
function definition(): RoleDefinition {
  const permissions = column();
  // Mostly valid, as `definitionProblem` keeps them; now and then not, which the rules must still decide.
  const guarded = chance(0.8) ? permissions.filter(() => chance(0.6)) : column();
  return { name: 'Edited', description: '', permissions, protected: guarded };
}
function filter(values: readonly string[]): Filter {
  const roll = random();
  if (roll < 0.5) return 'all';
  if (roll < 0.75) return { only: unique(some(values, 2)) };
  return { except: unique(some(values, 2)) };
}
const scope = (): Scope => ({ projects: filter([...PROJECTS, 'ghost']), environments: filter([...SLUGS, 'ghost']) });

function policy(): Policy {
  if (chance(0.15)) return DEFAULT_POLICY;
  const roles: Record<string, RoleDefinition> = { ...ROLES };
  for (const role of Object.keys(ROLES)) if (role !== 'owner' && chance(0.25)) roles[role] = definition();
  if (chance(0.5)) roles.custom = definition();
  const instanceRoles = { ...INSTANCE_ROLES } as Record<string, RoleDefinition>;
  for (const role of ['auditor', 'developer', 'admin']) if (chance(0.2)) instanceRoles[role] = definition();
  const guarded = unique(some(ENVIRONMENTS.filter((id) => id.includes('/')), 3));
  const protect = chance(0.05) ? ['*'] : guarded;
  const protectedIn: Record<string, { environmentId: string; slug: string | null }[]> = {};
  for (const id of guarded) {
    if (chance(0.15)) continue;
    (protectedIn[projectOf(id)] ??= []).push({ environmentId: id, slug: chance(0.1) ? null : slugOf(id) });
  }
  return { roles, instanceRoles: instanceRoles as Policy['instanceRoles'], protected: protect, protectedIn };
}

function place(): Place {
  const projectId = chance(0.9) ? pick(PROJECTS) : pick(['ghost', ...INHERITED]);
  if (chance(0.3)) return { projectId };
  const environmentId = chance(0.8) ? pick(ENVIRONMENTS.filter((id) => id.startsWith(projectId))) ?? pick(ENVIRONMENTS) : pick(ENVIRONMENTS);
  return { projectId, environmentId: environmentId ?? 'ghost', environmentSlug: chance(0.1) ? null : slugOf(environmentId ?? '') };
}
function grant(): { projectId: string | null; environmentId: string | null; role: string } {
  const projectId = chance(0.95) ? pick(PROJECTS) : null;
  return { projectId, environmentId: chance(0.5) ? null : pick(ENVIRONMENTS), role: pick(ROLE_NAMES) };
}
const columns = (): Columns => ({ normal: column(), protected: column() });
function scopeGrant(): ScopeGrant {
  const legacy = chance(0.2);
  return {
    // A scope the vault stores names a project; the type, and so `issuedGrant`, takes none too.
    projectId: chance(0.05) ? null : pick([...PROJECTS, 'ghost']),
    environmentId: chance(0.5) ? null : pick(ENVIRONMENTS),
    role: legacy ? pick([...Object.keys(ROLES), 'custom']) : pick(ROLE_NAMES),
    ...(legacy ? {} : { permissions: columns() }),
    ...(chance(0.5) ? { sensitive: chance(0.5) } : {}),
  };
}
function holdings(given?: Policy): Holdings {
  const credential = random();
  return {
    role: pick(INSTANCE_ROLE_NAMES) as Holdings['role'],
    scope: scope(),
    grants: some([grant(), grant(), grant(), grant()], 4),
    ...(credential < 0.4 ? {} : credential < 0.5 ? { credentialScope: null } : { credentialScope: some([scopeGrant(), scopeGrant(), scopeGrant()], 3) }),
    // No policy, now and then: the code reads DEFAULT_POLICY.
    ...(given === undefined && chance(0.1) ? {} : { policy: given ?? policy() }),
    ...(chance(0.7) ? {} : { service: chance(0.5) }),
  };
}
const EVERYWHERE_SCOPE: Scope = { projects: 'all', environments: 'all' };
const setting = (): Scope | null => (chance(0.2) ? null : scope());
function account(): ServiceAccount {
  return { grants: some([{ role: pick(ROLE_NAMES), place: place() }, { role: pick(ROLE_NAMES), place: place() }], 2), admittedBy: chance(0.5) ? pick(PEOPLE) : null };
}

/** One case: its arguments for the oracle, as the code takes them, and the code's answer. */
type Case = { op: string; [argument: string]: unknown };
// Cases run through the oracle a batch at a time, so that ten times as many need no more memory.
const BATCH = 20_000;
let cases: { input: Case; expected: unknown }[] = [];
let total = 0;
const add = (input: Case, expected: unknown) => {
  cases.push({ input, expected });
  if (cases.length >= BATCH) compare();
};
// Both sides as JSON, keys sorted: the oracle writes objects in its own order.
const canonical = (value: unknown): unknown =>
  Array.isArray(value) ? value.map(canonical)
    : value !== null && typeof value === 'object' ? Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined).sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => [k, canonical(v)]))
      : value;
// How often each yes-or-no function says yes, or a decision allows every key: a generator that only ever met one
// answer would hold the model to nothing. Undefined for functions that answer otherwise.
const yes = (op: string, value: unknown): boolean | undefined => {
  if (op === 'referenceRefusal') return value === null;
  if (typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.length > 0 && value.every((code) => code === null);
  if (typeof value === 'object' && value !== null && 'ok' in value) return value.ok === true;
  return undefined;
};
const counts = new Map<string, { cases: number; differ: number; yes: number | undefined }>();
const differing: string[] = [];

function compare(): void {
  if (cases.length === 0) return;
  const run = spawnSync(oracle!, { input: cases.map(({ input }) => JSON.stringify(input)).join('\n') + '\n', maxBuffer: 1 << 30, encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`the oracle failed (${run.status}): ${run.stderr}`);
  const answers = run.stdout.trimEnd().split('\n');
  if (answers.length !== cases.length) throw new Error(`the oracle answered ${answers.length} of ${cases.length} cases`);
  cases.forEach(({ input, expected }, i) => {
    const count = counts.get(input.op) ?? { cases: 0, differ: 0, yes: yes(input.op, expected) === undefined ? undefined : 0 };
    counts.set(input.op, count);
    count.cases += 1;
    if (count.yes !== undefined && yes(input.op, expected) === true) count.yes += 1;
    const answer = JSON.parse(answers[i]!) as unknown;
    if (JSON.stringify(canonical(answer)) === JSON.stringify(canonical(expected))) return;
    count.differ += 1;
    if (differing.length < 5) differing.push(`${input.op}: TypeScript ${JSON.stringify(expected)}, Lean ${answers[i]}\n  case ${JSON.stringify(input)}`);
  });
  total += cases.length;
  cases = [];
}

const repeat = (n: number, f: () => void) => {
  for (let i = 0; i < n * scale; i += 1) f();
};

// --- access ------------------------------------------------------------------
repeat(20000, () => {
  const holder = holdings();
  const permission = pick(PERMISSIONS);
  const at = place();
  add({ op: 'allows', holder, permission, place: at }, allows(holder, permission, at));
  add({ op: 'withinCredential', holder, permission, place: at }, withinCredential(holder, permission, at));
});
repeat(4000, () => {
  const holder = holdings();
  const at = place();
  add({ op: 'heldColumns', holder, place: at }, heldColumns(holder, at));
  add({ op: 'mayManageAccess', holder, place: at }, mayManageAccess(holder, at));
  const projectId = pick([...PROJECTS, 'ghost', ...INHERITED]);
  // Services on sensitive grants, and Owners, as often as not: what these two are about.
  const service = { ...holder, service: chance(0.7), credentialScope: some([scopeGrant(), { ...scopeGrant(), projectId, sensitive: true }], 2) };
  add({ op: 'readsSensitive', holder: service, projectId }, readsSensitive(service, projectId));
  const owner = chance(0.5) ? { ...holder, role: 'owner' as const } : { ...holder, grants: [...holder.grants, { projectId, environmentId: chance(0.7) ? null : pick(ENVIRONMENTS), role: 'owner' }] };
  add({ op: 'ownsProject', holder: owner, projectId }, ownsProject(owner, projectId));
  add({ op: 'runsInstance', holder }, runsInstance(holder));
  add({ op: 'readsWholeLog', holder }, readsWholeLog(holder));
  add({ op: 'makesProjects', holder }, makesProjects(holder));
});
repeat(4000, () => {
  const given = policy();
  const g = { projectId: chance(0.05) ? null : pick(PROJECTS), environmentId: chance(0.5) ? null : pick(ENVIRONMENTS), role: pick(ROLE_NAMES) };
  const held = chance(0.3) ? undefined : heldColumns(holdings(given), place());
  add({ op: 'issuedGrant', grant: g, policy: given, ...(held === undefined ? {} : { held }) }, issuedGrant(g, given, held));
});
repeat(6000, () => {
  const holder = holdings();
  const at = place();
  const where = setting();
  const role = pick(ROLE_NAMES);
  const kept = chance(0.3) ? definition() : undefined;
  add({ op: 'givesService', holder, setting: where, role, place: at, ...(kept === undefined ? {} : { kept }) }, givesService(holder, where, role, at, kept));
  // An unscoped Developer giving viewer on a whole project of an inherited name: what reaches `protectedWithin` there.
  if (chance(0.1)) {
    const developer: Holdings = { ...holder, role: 'developer', scope: { projects: 'all', environments: 'all' }, credentialScope: null, service: false };
    const odd = { projectId: pick(INHERITED) };
    add({ op: 'givesService', holder: developer, setting: EVERYWHERE_SCOPE, role: 'viewer', place: odd }, givesService(developer, EVERYWHERE_SCOPE, 'viewer', odd));
  }
  const actor = pick(PEOPLE);
  const of = account();
  add({ op: 'managesService', holder, setting: where, actor, account: of }, managesService(holder, where, actor, of));
  const asked = some([{ role: pick(ROLE_NAMES), place: place() }, { role: pick(ROLE_NAMES), place: place(), kept: definition() }], 2);
  add({ op: 'issuesCredential', holder, setting: where, actor, account: of, scope: asked }, issuesCredential(holder, where, actor, of, asked));
});
for (const purpose of ['reveal', 'run', 'compare', 'copy', 'use', 'expose', '', 'other']) {
  for (const keepsSensitive of [true, false]) add({ op: 'handsBack', purpose, keepsSensitive }, handsBack({ purpose, keepsSensitive }));
}

// --- the vault's decision ----------------------------------------------------
function environments(): Map<string, EnvironmentRow> {
  const rows = new Map<string, EnvironmentRow>();
  for (const id of ENVIRONMENTS) {
    if (id === '' || id === 'ghost' || chance(0.1)) continue;
    const personal = id.endsWith('@ada');
    rows.set(id, {
      projectId: chance(0.95) ? projectOf(id) : pick(PROJECTS),
      slug: slugOf(id) ?? 'none',
      owner: personal ? (chance(0.8) ? 'user:ada' : null) : chance(0.05) ? pick(PEOPLE) : null,
      parentId: personal || id.endsWith('fork') ? (chance(0.9) ? `${projectOf(id)}/dev` : pick(ENVIRONMENTS)) : null,
      deleted: chance(0.08),
      archived: chance(0.1),
    });
  }
  return rows;
}
const STATUSES = ['active', 'active', 'active', 'active', 'active', 'active', 'removed', 'unknown', 'tampered'] as const;
function reader(): Reader {
  // Half the time someone who holds much: an Owner or Developer of everything, on a session.
  const live = chance(0.5) ? holdings() : { ...holdings(), role: pick(['owner', 'developer'] as const), scope: { projects: 'all' as const, environments: 'all' as const }, credentialScope: chance(0.6) ? null : [scopeGrant()] };
  return { status: pick(STATUSES), live, all: { ...live, grants: [...live.grants, ...some([grant(), grant()], 2)] } };
}
const secretPlace = (): SecretPlace => {
  // A personal config's key a fifth of the time: its owner's rules are the least common, and the strictest.
  const environmentId = chance(0.2) ? 'market/dev@ada' : pick(ENVIRONMENTS);
  return { projectId: chance(0.9) ? projectOf(environmentId) : pick(PROJECTS), environmentId };
};
const CODES: (RefusalCode | null)[] = [null, null, null, 'no_grant', 'personal', 'deleted', 'ended'];
repeat(10000, () => {
  const who = reader();
  const principal = chance(0.4) ? 'user:ada' : pick(PEOPLE);
  const permission = pick(PERMISSIONS);
  const secrets = chance(0.5) ? [secretPlace()] : some([secretPlace(), secretPlace(), secretPlace()], 3);
  const at = secrets.map((secret) => (chance(0.6) ? secret : secretPlace()));
  const rows = environments();
  const needs = secrets.map(() => (chance(0.6) ? null : unique(some(PERMISSIONS, 2))));
  const owns = secrets.map(() => chance(0.2));
  add(
    { op: 'keyRefusals', reader: who, principal, permission, secrets, at, environments: [...rows].map(([id, row]) => ({ id, row })), needs, owns },
    keyRefusals(who, { principal, permission, secrets, at, environments: rows, needs, owns }),
  );
  const action = pick(['secret.read', 'secret.read', 'key.wrap', 'key.rewrap'] as const);
  const purpose = chance(0.1) ? undefined : pick(['reveal', 'run', 'compare', 'copy', 'use', 'expose', 'other']);
  const keepsSensitive = chance(0.3) ? undefined : chance(0.5);
  const codes = secrets.map(() => pick(CODES));
  const flagged = secrets.map((secret) => ({ projectId: secret.projectId, ...(chance(0.3) ? {} : { sensitive: chance(0.6) }) }));
  add(
    { op: 'sensitiveRefusals', codes, reader: who, action, principal, ...(purpose === undefined ? {} : { purpose }), ...(keepsSensitive === undefined ? {} : { keepsSensitive }), secrets: flagged },
    sensitiveRefusals(codes, who, { action, principal, purpose, keepsSensitive, secrets: flagged }),
  );
});

// A personal config's key read by its owner, whose credential and holdings at its parent decide.
repeat(3000, () => {
  const live: Holdings = { ...holdings(), role: pick(['developer', 'auditor', 'member'] as const), scope: { projects: 'all', environments: 'all' }, credentialScope: chance(0.3) ? null : some([scopeGrant(), { ...scopeGrant(), projectId: 'market', environmentId: 'market/dev' }], 2) };
  const who: Reader = { status: 'active', live, all: live };
  const rows = environments();
  rows.set('market/dev@ada', { projectId: 'market', slug: 'dev', owner: 'user:ada', parentId: 'market/dev', deleted: chance(0.05), archived: false });
  const secrets = [{ projectId: 'market', environmentId: 'market/dev@ada' }];
  const permission = pick(PERMISSIONS);
  add(
    { op: 'keyRefusals', reader: who, principal: 'user:ada', permission, secrets, at: secrets, environments: [...rows].map(([id, row]) => ({ id, row })), needs: [null], owns: [false] },
    keyRefusals(who, { principal: 'user:ada', permission, secrets, at: secrets, environments: rows, needs: [null], owns: [false] }),
  );
});

// Making a reference: the maker's rights at both ends, the source's nature, and personal configs at either.
repeat(6000, () => {
  const who = reader();
  const holder = secretPlace();
  const source = secretPlace();
  const rows = environments();
  const sensitive = chance(0.4);
  add(
    { op: 'referenceRefusal', reader: who, holder, source, environments: [...rows].map(([id, row]) => ({ id, row })), sensitive },
    referenceRefusal(who, holder, source, rows, sensitive),
  );
});

// --- envelope: the AAD -------------------------------------------------------
const hex = (bytes: number) => randomFrom(bytes).toString('hex');
function randomFrom(bytes: number): Buffer {
  return Buffer.from(Array.from({ length: bytes }, () => Math.floor(random() * 256)));
}
const uuid = () => {
  const h = hex(16);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
};
repeat(2000, () => {
  const ctx: SecretContext = { projectId: uuid(), environmentId: uuid(), secretId: uuid(), ...(chance(0.5) ? { owner: hex(32) } : {}), ...(chance(0.5) ? { sensitive: true as const } : {}) };
  add({ op: 'encodeAad', ctx }, encodeAad(ctx).toString('utf8'));
});

// --- the audit chain ---------------------------------------------------------
const keys: LogKey[] = [deriveLogKey('app', randomBytes(32)), deriveLogKey('vault', randomBytes(32))];
const strangerKey = deriveLogKey('app', randomBytes(32));
/** A chain as its authors write it, but for a number skipped at `gapAt`, its entries sealed over the gap. */
function chain(length: number, start: bigint, prev: Buffer, gapAt = -1): StoredEntry[] {
  const log: StoredEntry[] = [];
  for (let i = 0; i < length; i += 1) {
    const key = chance(0.05) ? strangerKey : pick(keys);
    const fields: LogFields = {
      seq: start + BigInt(i) + (gapAt >= 0 && i >= gapAt ? 1n : 0n), author: key.author, keyId: key.keyId, occurredAt: 1_700_000_000_000 + i, actor: pick(PEOPLE), action: 'secret.read',
      decision: 'allow', code: null, subjectPrincipal: null, projectId: null, environmentId: null, secretId: null, secretVersionId: null,
      operationId: null, requestId: null, sourceIp: null, relatedSeq: null, metadata: '{}',
    };
    log.push({ ...fields, prevHash: prev, ...sealEntry(key, prev, fields) });
    prev = log.at(-1)!.hash;
  }
  return log;
}
function tamper(log: StoredEntry[]): StoredEntry[] {
  const out = log.map((entry) => ({ ...entry }));
  if (out.length === 0) return out;
  const i = Math.floor(random() * out.length);
  switch (pick(['none', 'field', 'mac', 'prev', 'hash', 'drop', 'swap', 'seq'] as const)) {
    case 'none': break;
    case 'field': out[i] = { ...out[i]!, actor: 'user:mallory' }; break;
    case 'mac': out[i] = { ...out[i]!, mac: randomFrom(32) }; break;
    case 'prev': out[i] = { ...out[i]!, prevHash: randomFrom(32) }; break;
    case 'hash': out[i] = { ...out[i]!, hash: randomFrom(32) }; break;
    case 'drop': out.splice(i, 1); break;
    case 'swap': if (i + 1 < out.length) [out[i], out[i + 1]] = [out[i + 1]!, out[i]!]; break;
    case 'seq': out[i] = { ...out[i]!, seq: out[i]!.seq + 1n }; break;
  }
  return out;
}
repeat(2000, () => {
  const startSeq = chance(0.5) ? 0n : BigInt(Math.floor(random() * 50));
  const startPrevHash = startSeq === 0n ? GENESIS_HASH : randomFrom(32);
  const length = Math.floor(random() * 6);
  const entries = tamper(chain(length, chance(0.1) ? startSeq + 1n : startSeq, startPrevHash, chance(0.15) ? Math.floor(random() * length) : -1));
  const verifier = chance(0.7) ? keys : [keys[0]!];
  const chainOnly = verifier.length === 1 && chance(0.7) ? (['vault'] as const) : ([] as const);
  const authors = new Set(verifier.map((key) => key.author));
  // What verifyEntries asks of each entry besides its place: its hash, and its MAC by the authors it holds keys of.
  const macOk = (entry: StoredEntry) => {
    if (!authors.has(entry.author)) return (chainOnly as readonly string[]).includes(entry.author);
    const key = verifier.find((candidate) => candidate.keyId === entry.keyId && candidate.author === entry.author);
    return key !== undefined && entryMac(key.key, entry.prevHash, entry).equals(entry.mac);
  };
  const result = verifyEntries(entries, { startSeq, startPrevHash, keys: verifier, chainOnly });
  add(
    {
      op: 'verifyEntries', startSeq: Number(startSeq), startPrev: startPrevHash.toString('hex'),
      entries: entries.map((entry) => ({
        seq: Number(entry.seq), prev: entry.prevHash.toString('hex'), hash: entry.hash.toString('hex'),
        hashOk: entry.mac.length === 32 && entryHash(entry.prevHash, entry, entry.mac).equals(entry.hash), macOk: macOk(entry),
      })),
    },
    result.ok ? { ok: true, head: result.head.toString('hex'), nextSeq: Number(result.nextSeq) } : { ok: false, failedAtSeq: Number(result.failedAtSeq) },
  );
});

// --- the last batch, and the counts -----------------------------------------
compare();
for (const [op, { cases: n, differ, yes: hits }] of [...counts].sort(([a], [b]) => (a < b ? -1 : 1))) {
  const share = hits === undefined ? '' : `, ${`${Math.round((100 * hits) / n)}%`.padStart(4)} yes or allowed`;
  console.log(`${op.padEnd(18)} ${String(n).padStart(8)} cases${share}${differ === 0 ? '' : `, ${differ} differ`}`);
}
console.log(`seed ${seed}: ${total} cases`);
if (differing.length > 0) {
  console.error(`\nThe model and the code disagree:\n${differing.join('\n')}`);
  process.exit(1);
}
