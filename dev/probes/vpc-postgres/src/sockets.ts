// Do open VPC sockets count toward Workers' six simultaneous open connections
// per invocation? Inside one Durable Object call: hold `count` logged-in
// sessions (logged in, because Postgres drops a socket that sends no startup
// message within a minute), then see whether a fresh fetch() and a fresh
// connect() still go through, right away and after the hold, and whether the
// held sessions survive: idle, and beside those fresh ones. A last fresh
// connect() waits while one held session is closed: one that goes through just
// after that close was queued for a slot.
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
  /** Held sessions that no longer answered `select 1` before this check opened anything: dropped while idle. */
  dead: (Attempt & { socket: number })[];
  fetch: Attempt;
  connect: Attempt;
  /** Held sessions that answered before the fresh fetch() and connect() and not after: closed to make room for them. */
  evicted: (Attempt & { socket: number })[];
  /** Held sessions that still answer at the end of the check. */
  alive: number;
}

export interface SocketsReport {
  /** At least one session opened, so the rest of the report measures something. */
  ok: boolean;
  error?: string;
  count: number;
  holdSeconds: number;
  /** Each session's dial and login, all started at once; failures say their stage. */
  opened?: (Attempt & { socket: number })[];
  openedOk?: number;
  beside?: Check;
  afterHold?: Check;
  /**
   * A fresh connect() started RELEASE_AFTER_SECONDS before held session `closedSocket` closed,
   * with `heldAtClose` sessions answering just before (`dead`: the ones that no longer did);
   * `closedSocket` is null when none was left to close.
   */
  release?: { dead: (Attempt & { socket: number })[]; closedSocket: number | null; heldAtClose: number; closedAtMs: number; connect: Attempt };
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
    if (held.size === 0) throw new Error('no session opened: see `opened` for why');

    report.beside = await check(dial, target, held);
    if (holdSeconds > 0) {
      await sleep(holdSeconds);
      report.afterHold = await check(dial, target, held);
    }

    const at = Date.now();
    const connecting = connect(dial, target);
    await sleep(RELEASE_AFTER_SECONDS);
    // Asked again, so the session closed is one that was still holding a slot.
    const dead = await answer(held);
    const heldAtClose = held.size;
    const [first] = held;
    if (first) {
      held.delete(first[0]);
      await first[1].close(true);
    }
    report.release = { dead, closedSocket: first?.[0] ?? null, heldAtClose, closedAtMs: Date.now() - at, connect: await connecting };
    report.ok = true;
  } catch (error) {
    report.error = describe(error);
  } finally {
    await Promise.all([...held.values()].map((connection) => connection.close(true)));
  }
  return { ...report, totalMs: Date.now() - started };
}

/**
 * The held sessions first, so a drop while idle is told apart from an eviction; then a fresh
 * fetch() and connect(); then the held sessions again. Dead sessions are closed and dropped.
 */
async function check(dial: Dial, target: Target, held: Map<number, Connection>): Promise<Check> {
  const dead = await answer(held);
  const fetched = await fetchOnce();
  const connected = await connect(dial, target);
  const evicted = await answer(held);
  return { dead, fetch: fetched, connect: connected, evicted, alive: held.size };
}

/** `select 1` on every held session; the ones that fail are closed, dropped and returned. */
async function answer(held: Map<number, Connection>): Promise<(Attempt & { socket: number })[]> {
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
  return answers.filter((dead) => dead !== null);
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
