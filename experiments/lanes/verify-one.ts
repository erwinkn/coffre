// Variant `one`'s log (W208, W211), from the database alone, then replayed:
//
// 1. Integrity, as verify-simple.ts: the checkpoints tile, each one's hash is
//    the entries it covers (number and MAC), chained to the one before, and
//    its signature is the vault's; every entry after the first checkpoint
//    carries its MAC; numbers never repeat, nor requests (a replayed call
//    finds its entry; a second one is a copy). Gaps in the numbers are not
//    deletions: a call that fails or a replay uses one up. Only the
//    checkpoints say an entry is missing.
// 2. The replay: the state, built from the change entries alone in number
//    order (the seed's included) with the same `applyOp` a change seals
//    with, and each use decided again on the state of the entries numbered
//    before it (the changes, and the uses for the bulk cap), at the entry's
//    time (`decide`). The log stores no outcome, so this is the only record
//    of one. With --outcomes (bench-simple.ts's, one file or several), each
//    replayed decision is held to what the live path answered: they must
//    agree, refusal codes included. A use answered on a cover (a repeat, no
//    entry of its own) must name a cover the replay allows.
// 3. The rows (W211): every input as it stands in its table (member and
//    grants, credential, secret, environment) must be the state the replay
//    built, seal included. A row put back from before a change, or written
//    by anyone but a change, fails here even if no use ever read it. The
//    bulk cap's rows must be the replay's too.
//
//   node experiments/lanes/verify-one.ts --url postgresql://… [--outcomes run.jsonl[,run2.jsonl]]
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { keysFrom } from './src/model.ts';
import {
  applyOp, bulkStep, checkpointHash, DEADLINE_MAX, checkpointSignature, credentialSeal, decide, emptyState, ENTRIES, environmentSeal, limits, memberSeal, rowMac,
  secretSeal, type Limits, type Op, type Row, type View,
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

// The state a decision reads, as the changes left it; each object's newest seal; each principal's bulk rows.
const state = emptyState();
const lastSeal = new Map<string, Buffer | null>();
const bulk = new Map<string, Map<string, number>>();
let sealMismatches = 0;

function apply(r: Row): void {
  const seal = applyOp(keys, state, r.object!, JSON.parse(r.payload!) as Op);
  lastSeal.set(r.object!, r.seal);
  // The seal the vault wrote must be the object it left, as the replay has it.
  if ((seal === null) !== (r.seal === null) || (seal !== null && !seal.equals(r.seal!))) sealMismatches += 1;
}

const sealed = <T extends object>(row: T | undefined, seal: (x: T) => Buffer, object: string) =>
  row === undefined ? null : { ...row, seal: seal(row), last: lastSeal.get(object) ?? null };

function view(credential: string, secret: string, cap: Limits, at: number): View {
  const c = state.credentials.get(credential);
  const s = state.secrets.get(secret);
  const m = c === undefined ? undefined : state.members.get(c.principal);
  const e = s === undefined ? undefined : state.environments.get(s.environmentId);
  let rows: Map<string, number> | undefined;
  if (c !== undefined) bulk.set(c.principal, (rows = bulk.get(c.principal) ?? new Map()));
  return {
    credential: sealed(c, (x) => credentialSeal(keys.row, x), `credential:${credential}`),
    member: sealed(m, (x) => memberSeal(keys.row, x), `member:${c?.principal}`),
    secret: sealed(s, (x) => secretSeal(keys.row, x), `secret:${secret}`),
    environment: sealed(e, (x) => environmentSeal(keys.row, x), `environment:${s?.environmentId}`),
    // Every request moves the cap as use_credential does, whatever else refuses it.
    bulk: rows === undefined ? { inSet: false, others: 0 } : bulkStep(rows, secret, at, cap),
    logged: {
      credential: (lastSeal.get(`credential:${credential}`) ?? null) !== null,
      member: c !== undefined && (lastSeal.get(`member:${c.principal}`) ?? null) !== null,
      secret: (lastSeal.get(`secret:${secret}`) ?? null) !== null,
      environment: s !== undefined && (lastSeal.get(`environment:${s.environmentId}`) ?? null) !== null,
    },
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
    // A use is one request per (at, request_id), as its unique index says (the MAC covers both, so a copy keeps both).
    const request = r.kind === 'use' ? `use:${r.at}:${r.request_id}` : `change:${r.request_id}`;
    if (requests.has(request)) failures.push(`${r.number}: request ${r.request_id} has another entry`);
    requests.add(request);
    if (checkMac && !rowMac(keys, r).equals(r.mac)) failures.push(`${r.number}: mac`);
    if (r.kind === 'change') {
      apply(r);
      continue;
    }
    if (!checkMac) continue; // history before the first checkpoint: synthetic, nothing to replay
    replay.uses += 1;
    const cap = state.limits ?? limits();
    const input = { credential: r.credential!, secretId: r.secret! };
    const code = decide(keys, view(r.credential!, r.secret!, cap, Number(r.at)), input, Number(r.at), cap);
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

/** Every input's row against the replay's state: content and seal, both ways. */
async function audit(): Promise<string[]> {
  const out: string[] = [];
  const same = (what: string, row: object | undefined, rowSeal: Buffer, want: object | undefined, object: string) => {
    if (want === undefined) out.push(`${what}: a row the log never made`);
    else if (JSON.stringify(row) !== JSON.stringify(want)) out.push(`${what}: ${JSON.stringify(row)}, the log has ${JSON.stringify(want)}`);
    else if (!rowSeal.equals(lastSeal.get(object) ?? Buffer.alloc(0))) out.push(`${what}: its seal is not its newest change's`);
  };
  const { rows: members } = await client.query(`SELECT principal, status, role, seal,
    (SELECT coalesce(array_agg(environment_id::text || ':' || role ORDER BY environment_id), '{}') FROM grants g WHERE g.principal = m.principal) AS grants FROM members m`);
  for (const m of members) {
    const want = state.members.get(m.principal);
    same(`member ${m.principal}`, { status: m.status, role: m.role, grants: m.grants }, m.seal,
      want && { status: want.status, role: want.role, grants: want.grants.map((g) => `${g.environment_id}:${g.role}`).sort() }, `member:${m.principal}`);
  }
  const { rows: orphans } = await client.query('SELECT principal FROM grants g WHERE NOT EXISTS (SELECT 1 FROM members m WHERE m.principal = g.principal)');
  for (const g of orphans) out.push(`grant of ${g.principal}: no member`);
  const { rows: credentials } = await client.query('SELECT id::text, principal, revoked, expires_at::text AS "expiresAt", seal FROM credentials');
  for (const { seal, ...c } of credentials) same(`credential ${c.id}`, c, seal, state.credentials.get(c.id), `credential:${c.id}`);
  const { rows: secrets } = await client.query(`SELECT id::text, environment_id::text AS "environmentId", nature, encode(wrapped, 'hex') AS wrapped, encode(iv, 'hex') AS iv, seal FROM secrets`);
  for (const { seal, ...s } of secrets) same(`secret ${s.id}`, s, seal, state.secrets.get(s.id), `secret:${s.id}`);
  const { rows: environments } = await client.query('SELECT id::text, deleted, seal FROM environments');
  for (const { seal, ...e } of environments) same(`environment ${e.id}`, e, seal, state.environments.get(e.id), `environment:${e.id}`);
  const present = new Set(credentials.map((c) => c.id));
  for (const id of state.credentials.keys()) if (!present.has(id)) out.push(`credential ${id}: the log has it, the table does not`);
  const counts = [[members.length, state.members.size, 'members'], [credentials.length, state.credentials.size, 'credentials'],
    [secrets.length, state.secrets.size, 'secrets'], [environments.length, state.environments.size, 'environments']] as const;
  for (const [rows, want, what] of counts) if (rows !== want) out.push(`${what}: ${rows} rows, the log has ${want}`);
  // The bulk cap's rows: each one the replay's; one the replay has may be missing only once pruning may take it.
  const cap = state.limits ?? limits();
  const { rows: held } = await client.query('SELECT principal, secret::text, last::text FROM bulk');
  const seen = new Set<string>();
  for (const b of held) {
    seen.add(`${b.principal}/${b.secret}`);
    const want = bulk.get(b.principal)?.get(b.secret);
    if (String(want) !== b.last) out.push(`bulk ${b.principal}/${b.secret}: last ${b.last}, the replay has ${want}`);
  }
  for (const [p, rows] of bulk) {
    for (const [k, t] of rows) if (!seen.has(`${p}/${k}`) && t > Date.now() - cap.windowMs - cap.refreshMs - DEADLINE_MAX) out.push(`bulk ${p}/${k}: missing`);
  }
  return out;
}

const started = performance.now();
try {
  const { rows: checkpoints } = await client.query('SELECT upto::text, from_number::text, entries, hash, signature, at_floor::text FROM checkpoints c ORDER BY c.upto');
  if (checkpoints.length === 0) throw new Error('no checkpoint');
  const [genesis, ...rest] = checkpoints;
  if (genesis.from_number !== genesis.upto || genesis.entries !== 0) failures.push('the first checkpoint is not an empty one');
  if (!checkpointSignature(keys.log, genesis.from_number, genesis.upto, genesis.hash).equals(genesis.signature)) failures.push('genesis: signature');
  // Before the first checkpoint: the seed's changes (MAC'd) and any synthetic history.
  const { rows: before } = await client.query(ENTRIES, ['-1', genesis.upto, '0']);
  for (const r of before as Row[]) if (r.kind === 'change' && !rowMac(keys, r).equals(r.mac)) failures.push(`${r.number}: mac`);
  walk(before as Row[], false);
  lastNumber = BigInt(genesis.upto);
  let prev = genesis;
  let sealedEntries = 0;
  for (const c of rest) {
    if (c.from_number !== prev.upto) failures.push(`checkpoint ${c.upto}: starts at ${c.from_number}, not at ${prev.upto}`);
    const { rows } = await client.query(ENTRIES, [c.from_number, c.upto, prev.at_floor]);
    if (rows.length !== c.entries) failures.push(`checkpoint ${c.upto}: ${rows.length} entries, signed ${c.entries}`);
    if (!checkpointHash(prev.hash, rows as Row[]).equals(c.hash)) failures.push(`checkpoint ${c.upto}: hash`);
    if (!checkpointSignature(keys.log, c.from_number, c.upto, c.hash).equals(c.signature)) failures.push(`checkpoint ${c.upto}: signature`);
    walk(rows as Row[], true);
    sealedEntries += rows.length;
    prev = c;
  }
  const { rows: open } = await client.query(ENTRIES, [prev.upto, '9223372036854775807', prev.at_floor]);
  walk(open as Row[], true);
  if (sealMismatches > 0) failures.push(`${sealMismatches} change(s) whose seal is not the object the replay has`);
  const rows = await audit();
  if (rows.length > 0) failures.push(`${rows.length} row(s) not the log's: ${rows.slice(0, 8).join('; ')}`);
  const disagree = replay.disagree.length;
  if (live.size > 0 && disagree > 0) failures.push(`${disagree} replayed decision(s) disagree with the live answer: ${replay.disagree.filter(Boolean).join('; ')}`);
  console.log(`${checkpoints.length} checkpoints tiling ${genesis.upto}..${prev.upto}, ${sealedEntries} entries sealed, ${open.length} above the last checkpoint, in ${(performance.now() - started).toFixed(0)} ms`);
  console.log(`replay: ${replay.uses} uses decided again from the log: ${replay.allowed} allowed, refused ${JSON.stringify(Object.fromEntries(replay.refused))}`);
  console.log(`rows: ${state.members.size} members, ${state.credentials.size} credentials, ${state.secrets.size} secrets, ${state.environments.size} environments, ${[...bulk.values()].reduce((s, m) => s + m.size, 0)} bulk rows; ${rows.length === 0 ? 'all as the log has them' : `${rows.length} NOT the log's`}`);
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
  console.log(failures.length === 0 ? 'all hold' : `${failures.length} FAILURES: ${failures.slice(0, 8).join('\n  ')}`);
  process.exitCode = failures.length === 0 ? 0 : 1;
} finally {
  await client.end();
}
