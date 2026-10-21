// Do open VPC sockets count toward Workers' six simultaneous open connections
// per invocation? Inside one Durable Object call: hold `count` logged-in
// sessions (logged in, because Postgres drops a socket that sends no startup
// message within a minute), then see whether a fresh fetch() and a fresh
// connect() still go through, right away and after the hold, and whether the
// held sessions survive. A last fresh connect() waits while one held session
// is closed: one that goes through just after that close was queued for a slot.
import { Connection, describe, login, selectOne, sleep, StageFailure, type Dial, type Report, type Target } from './pg.ts';

/** A small public page: the plain subrequest beside the held sockets. */
const FETCH_URL = 'https://www.cloudflare.com/cdn-cgi/trace';
const FETCH_TIMEOUT_MS = 20_000;
/** How long the release check waits before closing a held session. */
const RELEASE_AFTER_SECONDS = 5;

export interface Attempt {
  ok: boolean;
  ms: number;
  dialMs?: number;
  status?: number;
  stage?: string;
  error?: string;
}

export interface Check {
  fetch: Attempt;
  connect: Attempt;
  /** How many held sessions still answer `select 1`, and the ones that do not. */
  alive: number;
  dead: (Attempt & { socket: number })[];
}

export interface SocketsReport {
  ok: boolean;
  error?: string;
  count: number;
  holdSeconds: number;
  /** Each session's dial and login, all started at once; failures say their stage. */
  opened?: (Attempt & { socket: number })[];
  openedOk?: number;
  beside?: Check;
  afterHold?: Check;
  /** A fresh connect() started RELEASE_AFTER_SECONDS before a held session closed. */
  release?: { closedAtMs: number; connect: Attempt };
  totalMs?: number;
}

/** The measurement; every failure is reported, never thrown. */
export async function holdSockets(dial: Dial, target: Target, count: number, holdSeconds: number): Promise<SocketsReport> {
  const started = Date.now();
  const report: SocketsReport = { ok: false, count, holdSeconds };
  const held = new Map<number, Connection>();
  try {
    const results = await Promise.all(Array.from({ length: count }, () => open(dial, target)));
    report.opened = results.map(({ attempt }, socket) => ({ socket, ...attempt }));
    results.forEach(({ connection }, socket) => connection && held.set(socket, connection));
    report.openedOk = held.size;

    report.beside = await check(dial, target, held);
    if (holdSeconds > 0) {
      await sleep(holdSeconds);
      report.afterHold = await check(dial, target, held);
    }

    const at = Date.now();
    const connecting = connect(dial, target);
    await sleep(RELEASE_AFTER_SECONDS);
    const [first] = held;
    if (first) {
      held.delete(first[0]);
      await first[1].close(true);
    }
    report.release = { closedAtMs: Date.now() - at, connect: await connecting };
    report.ok = true;
  } catch (error) {
    report.error = describe(error);
  } finally {
    await Promise.all([...held.values()].map((connection) => connection.close(true)));
  }
  return { ...report, totalMs: Date.now() - started };
}

/** A fresh fetch(), then a fresh connect(), then `select 1` on every held session. Dead sessions are closed and dropped. */
async function check(dial: Dial, target: Target, held: Map<number, Connection>): Promise<Check> {
  const fetched = await fetchOnce();
  const connected = await connect(dial, target);
  const answers = await Promise.all(
    [...held].map(async ([socket, connection]) => {
      const at = Date.now();
      try {
        await selectOne(connection);
        return null;
      } catch (error) {
        held.delete(socket);
        await connection.close(false);
        return { socket, ...failed(at, error, 'query') };
      }
    }),
  );
  const dead = answers.filter((answer) => answer !== null);
  return { fetch: fetched, connect: connected, alive: held.size, dead };
}

async function open(dial: Dial, target: Target): Promise<{ attempt: Attempt; connection?: Connection }> {
  const at = Date.now();
  const report: Report = { ok: false };
  try {
    const connection = await login(dial, target, report);
    return { attempt: { ok: true, ms: Date.now() - at, dialMs: report.dialMs }, connection };
  } catch (error) {
    return { attempt: { ...failed(at, error), dialMs: report.dialMs } };
  }
}

/** Dial, log in, `select 1`, close. */
async function connect(dial: Dial, target: Target): Promise<Attempt> {
  const at = Date.now();
  const { attempt, connection } = await open(dial, target);
  if (!connection) return attempt;
  try {
    await selectOne(connection);
    return { ...attempt, ms: Date.now() - at };
  } catch (error) {
    return failed(at, error, 'query');
  } finally {
    await connection.close(true);
  }
}

async function fetchOnce(): Promise<Attempt> {
  const at = Date.now();
  try {
    const response = await fetch(FETCH_URL, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    await response.arrayBuffer();
    return { ok: response.ok, ms: Date.now() - at, status: response.status };
  } catch (error) {
    return failed(at, error);
  }
}

function failed(at: number, error: unknown, stage?: string): Attempt {
  return { ok: false, ms: Date.now() - at, stage: error instanceof StageFailure ? error.stage : stage, error: describe(error) };
}
