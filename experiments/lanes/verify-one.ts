// Variant `one`'s log (W208), from the database alone, then replayed:
//
// 1. Integrity, as verify-simple.ts: the checkpoints tile, each one's hash is
//    the entries it covers (number and MAC), chained to the one before, and
//    its signature is the vault's; every entry after the first checkpoint
//    carries its MAC; numbers never repeat, nor request ids (a replayed call
//    finds its entry; a second one is a copy). Gaps in the numbers are not
//    deletions: a call that fails or a replay uses one up. Only the
//    checkpoints say an entry is missing.
// 2. The replay: the state, built from the change entries alone in number
//    order (the seed's included), and each use decided again on the state
//    of the changes numbered before it, at the entry's time (`decide`). The
//    log stores no outcome, so this is the only record of one. With
//    --outcomes (bench-simple.ts's, one file or several), each replayed
//    decision is held to what the live path answered: they must agree. A
//    use answered on a cover (a repeat, no entry of its own) must name a
//    cover the replay allows.
//
//   node experiments/lanes/verify-one.ts --url postgresql://… [--outcomes run.jsonl[,run2.jsonl]]
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { keysFrom } from './src/model.ts';
import {
  checkpointHash, checkpointSignature, decide, ENTRIES, entryMac, grantsAfter, memberSeal, rowEntry, type Grant, type Member, type Op, type Row, type View,
} from './src/one.ts';

const { values } = parseArgs({ options: { url: { type: 'string' }, outcomes: { type: 'string' }, seed: { type: 'string', default: 'w194-synthetic' } } });
const keys = keysFrom(values.seed);
const client = new pg.Client({ connectionString: values.url });
await client.connect();

type Outcome = { status: number; code: string };
const live = new Map<string, Outcome>();
const coveredBy: string[] = [];
for (const file of values.outcomes?.split(',') ?? []) {
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    if (line === '') continue;
    const o = JSON.parse(line) as Outcome & { requestId: string; number: string | null; covered?: boolean };
    if (o.covered) coveredBy.push(o.number!);
    else live.set(o.requestId, { status: o.status, code: o.code });
  }
}

// The state a decision reads, as the changes left it.
const members = new Map<string, Member>();
const grants = new Map<string, Grant[]>();
const lastSeal = new Map<string, string | null>();
const credentials = new Map<string, { principal: string; revoked: boolean; expiresAt: string | null }>();
const environments = new Map<string, { id: string; deleted: boolean }>();
const secrets = new Map<string, { id: string; environmentId: string; nature: string }>();
let sealMismatches = 0;

function apply(r: Row): void {
  const op = JSON.parse(r.payload) as Op | { op: string; [k: string]: string | null };
  const p = r.principal;
  switch (op.op) {
    case 'environment.create': environments.set(op.environment as string, { id: op.environment as string, deleted: false }); break;
    case 'secret.create': secrets.set(op.secret as string, { id: op.secret as string, environmentId: op.environment as string, nature: op.nature as string }); break;
    case 'member.add': members.set(p, { principal: p, status: op.status as string, role: (op.role as string | null) ?? null }); grants.set(p, []); break;
    case 'access.grant': case 'access.revoke': grants.set(p, grantsAfter(grants.get(p) ?? [], op as Op)); break;
    case 'credential.issue': credentials.set(op.credential as string, { principal: p, revoked: false, expiresAt: (op.expiresAt as string | null) ?? null }); break;
    case 'credential.revoke': case 'credential.restore': {
      const c = credentials.get(op.credential as string);
      if (c !== undefined && c.principal === p) c.revoked = op.op === 'credential.revoke';
      break;
    }
    default: throw new Error(`${r.number}: unknown change ${op.op}`);
  }
  lastSeal.set(p, r.seal === null ? null : r.seal.toString('hex'));
  // The seal the vault wrote must be the member it left, as the replay has it.
  const m = members.get(p);
  if (m !== undefined && r.seal !== null && !memberSeal(keys.row, m, grants.get(p) ?? []).equals(r.seal)) sealMismatches += 1;
}

function view(r: Row, environment: string, secret: string): View {
  const m = members.get(r.principal);
  const seal = lastSeal.get(r.principal) ?? null;
  return {
    member: m === undefined || seal === null ? null : { ...m, seal },
    grants: grants.get(r.principal) ?? [],
    lastSeal: seal,
    credential: r.credential === null ? null : credentials.get(r.credential) ?? null,
    environment: environments.get(environment) ?? null,
    secret: secrets.get(secret) ?? null,
  };
}

const failures: string[] = [];
const allowedEntries = new Set<string>();
const replay = { uses: 0, withLive: 0, agree: 0, disagree: [] as string[], noLive: 0, allowed: 0, refused: new Map<string, number>() };
let lastNumber = -1n;
const requests = new Set<string>();

function walk(rows: readonly Row[], checkMac: boolean): void {
  for (const r of rows) {
    const n = BigInt(r.number);
    if (n <= lastNumber) failures.push(`${r.number}: number repeats or goes back (after ${lastNumber})`);
    lastNumber = n;
    const request = `${r.kind}:${r.request_id}`;
    if (requests.has(request)) failures.push(`${r.number}: request ${r.request_id} has another entry`);
    requests.add(request);
    if (checkMac && !entryMac(keys.log, rowEntry(r)).equals(r.mac)) failures.push(`${r.number}: mac`);
    if (r.kind === 'change') {
      apply(r);
      continue;
    }
    if (!checkMac) continue; // history before the first checkpoint: synthetic, nothing to replay
    replay.uses += 1;
    const asked = JSON.parse(r.payload) as { environment: string; secret: string };
    const code = decide(keys, view(r, asked.environment, asked.secret), { principal: r.principal, credential: r.credential ?? '', environmentId: asked.environment, secretId: asked.secret }, Number(r.at));
    if (code === null) {
      replay.allowed += 1;
      allowedEntries.add(r.number);
    }
    else replay.refused.set(code, (replay.refused.get(code) ?? 0) + 1);
    const o = live.get(r.request_id);
    if (o === undefined || (o.status !== 200 && o.status !== 403)) {
      replay.noLive += 1;
      continue;
    }
    replay.withLive += 1;
    const agrees = code === null ? o.status === 200 : o.status === 403 && o.code === code;
    if (agrees) replay.agree += 1;
    else if (replay.disagree.length < 10) replay.disagree.push(`${r.number} ${r.request_id}: replay ${code ?? 'allow'}, live ${o.status} ${o.code}`);
    else replay.disagree.push('');
  }
}

const started = performance.now();
try {
  const { rows: checkpoints } = await client.query('SELECT upto::text, from_number::text, entries, hash, signature, at_floor::text FROM checkpoints c ORDER BY c.upto');
  if (checkpoints.length === 0) throw new Error('no checkpoint');
  const [genesis, ...rest] = checkpoints;
  if (genesis.from_number !== genesis.upto || genesis.entries !== 0) failures.push('the first checkpoint is not an empty one');
  if (!checkpointSignature(keys.log, genesis.from_number, genesis.upto, genesis.hash).equals(genesis.signature)) failures.push('genesis: signature');
  // Before the first checkpoint: the seed's changes (MAC'd) and any synthetic history.
  const { rows: before } = await client.query(`SELECT number::text, at::text, kind, principal, credential, request_id, payload, seal, mac FROM entries_changes e WHERE e.number <= $1 ORDER BY e.number`, [genesis.upto]);
  for (const r of before as Row[]) if (!entryMac(keys.log, rowEntry(r)).equals(r.mac)) failures.push(`${r.number}: mac`);
  walk(before as Row[], false);
  lastNumber = BigInt(genesis.upto);
  let prev = genesis;
  let sealed = 0;
  for (const c of rest) {
    if (c.from_number !== prev.upto) failures.push(`checkpoint ${c.upto}: starts at ${c.from_number}, not at ${prev.upto}`);
    const { rows } = await client.query(ENTRIES, [c.from_number, c.upto, prev.at_floor]);
    if (rows.length !== c.entries) failures.push(`checkpoint ${c.upto}: ${rows.length} entries, signed ${c.entries}`);
    if (!checkpointHash(prev.hash, rows as Row[]).equals(c.hash)) failures.push(`checkpoint ${c.upto}: hash`);
    if (!checkpointSignature(keys.log, c.from_number, c.upto, c.hash).equals(c.signature)) failures.push(`checkpoint ${c.upto}: signature`);
    walk(rows as Row[], true);
    sealed += rows.length;
    prev = c;
  }
  const { rows: open } = await client.query(ENTRIES, [prev.upto, '9223372036854775807', prev.at_floor]);
  walk(open as Row[], true);
  if (sealMismatches > 0) failures.push(`${sealMismatches} change(s) whose seal is not the member the replay has`);
  const disagree = replay.disagree.length;
  if (live.size > 0 && disagree > 0) failures.push(`${disagree} replayed decision(s) disagree with the live answer: ${replay.disagree.filter(Boolean).join('; ')}`);
  console.log(`${checkpoints.length} checkpoints tiling ${genesis.upto}..${prev.upto}, ${sealed} entries sealed, ${open.length} above the last checkpoint, in ${(performance.now() - started).toFixed(0)} ms`);
  console.log(`replay: ${replay.uses} uses decided again from the log: ${replay.allowed} allowed, refused ${JSON.stringify(Object.fromEntries(replay.refused))}`);
  if (live.size > 0) {
    const answered = [...live.values()].filter((o) => o.status === 200 || o.status === 403).length;
    console.log(`  against the live answers: ${replay.withLive} with one, ${replay.agree} agree, ${disagree} disagree; ${replay.noLive} entries with no 200/403 answer (the Worker gave up or failed after the call); ${answered - replay.withLive} 200/403 answers with no entry (must be 0)`);
    if (answered !== replay.withLive) failures.push(`${answered - replay.withLive} live answers with no entry`);
    if (coveredBy.length > 0) {
      const unbacked = coveredBy.filter((n) => !allowedEntries.has(n)).length;
      console.log(`  repeats answered on a cover: ${coveredBy.length}, on ${new Set(coveredBy).size} covers; on a cover the replay does not allow: ${unbacked} (must be 0)`);
      if (unbacked > 0) failures.push(`${unbacked} repeats on a cover the replay does not allow`);
    }
  }
  console.log(failures.length === 0 ? 'all hold' : `${failures.length} FAILURES: ${failures.slice(0, 8).join('; ')}`);
  process.exitCode = failures.length === 0 ? 0 : 1;
} finally {
  await client.end();
}
