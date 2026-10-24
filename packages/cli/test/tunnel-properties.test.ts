// `coffre run`'s end of the Postgres tunnel (`carry`, src/tunnels.ts), driven
// with a fake app socket and WebSocket against coffre's end written from the
// protocol (docs/design/credential-proxy.md, "Postgres through a tunnel"):
// a Workers coffre, which says it paces with a first `0` and counts back what
// it took, or a coffre on Node, which sends a byte first and counts nothing.
// Hegel draws the schedule: who writes, how much, when each frame arrives (in
// order, each way), when the app and the database read, the keepalive, and
// when either side closes or the network goes. coffre's end has its own
// properties (packages/server/test/tunnel-properties.test.ts).
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import type { Socket } from 'node:net';
import test, { type TestContext } from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';
import type { WebSocket } from 'ws';

import { propertySettings } from '../../../scripts/property-settings.ts';
import { carry } from '../src/tunnels.ts';

const KiB = 1024;
/** The protocol's numbers, from the design: a window, and a count at least this often. */
const WINDOW = 1024 * KiB;
const COUNT_EVERY = 128 * KiB;
/** What the listener lets wait in its WebSocket before it stops reading the app (tunnels.ts's `HIGH_WATER`). */
const HIGH_WATER = 1024 * KiB;
/** The fake app socket's high-water mark, Node's default. */
const SOCKET_HIGH_WATER = 64 * KiB;
/** The largest message either side sends: the app's write, or a database read. */
const BIGGEST = 300 * KiB;
const KEEPALIVE_MS = 30_000;
const COUNT = /^\d{1,10}$/;
const OPEN = 1;
const CLOSING = 2;
const CLOSED = 3;

/**
 * Each direction's bytes are a long pseudo-random sequence, so a chunk
 * dropped, repeated or out of order does not line up with what was written
 * at its offset.
 */
const PERIOD = 1_000_003;
const pattern = (() => {
  const bytes = Buffer.alloc(PERIOD + BIGGEST);
  let x = 0x9e3779b9;
  for (let i = 0; i < PERIOD; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    bytes[i] = x & 0xff;
  }
  bytes.copy(bytes, PERIOD, 0, BIGGEST);
  return bytes;
})();

/** One direction: what its writer wrote, and what its reader took, which must be a prefix of it. */
class Flow {
  written = 0;
  taken = 0;
  write(size: number) {
    const chunk = pattern.subarray(this.written % PERIOD, (this.written % PERIOD) + size);
    this.written += size;
    return chunk;
  }
  take(chunk: Buffer) {
    assert.ok(chunk.length <= BIGGEST && this.taken + chunk.length <= this.written, `${chunk.length} bytes arrived past the ${this.written} written`);
    assert.ok(chunk.equals(pattern.subarray(this.taken % PERIOD, (this.taken % PERIOD) + chunk.length)), `the bytes at ${this.taken} are not the ones written there`);
    this.taken += chunk.length;
  }
}

type Frame = { kind: 'binary'; data: Buffer } | { kind: 'text'; data: string } | { kind: 'close' };
type Flushed = (error?: Error) => void;

/**
 * The listener's WebSocket, as `ws` gives it: what it sends goes on the wire
 * to coffre, in order, and is buffered until it arrives; paused, it takes no
 * message off the wire. Coffre's edge answers each ping.
 */
class ListenerSocket extends EventEmitter {
  readyState = 0;
  bufferedAmount = 0;
  isPaused = false;
  terminated = false;
  pings = 0;
  readonly wire: { frame: Frame; flushed?: Flushed }[] = [];
  send(data: Buffer | string, options?: { binary?: boolean } | Flushed, callback?: Flushed) {
    const flushed = typeof options === 'function' ? options : callback;
    if (this.readyState !== OPEN) return void process.nextTick(() => flushed?.(new Error('WebSocket is not open')));
    const frame: Frame = typeof data === 'string' ? { kind: 'text', data } : { kind: 'binary', data: Buffer.from(data) };
    this.bufferedAmount += frame.data.length;
    this.wire.push({ frame, flushed });
  }
  ping() {
    this.pings += 1;
    process.nextTick(() => this.emit('pong'));
  }
  pause() {
    this.isPaused = true;
  }
  resume() {
    this.isPaused = false;
  }
  close() {
    if (this.readyState !== OPEN) return;
    this.readyState = CLOSING;
    this.wire.push({ frame: { kind: 'close' } });
  }
  terminate() {
    if (this.readyState === CLOSED) return;
    this.terminated = true;
    this.end();
  }
  /** The connection is gone: what was on its way is lost, and the socket closes. */
  end() {
    if (this.readyState === CLOSED) return;
    this.readyState = CLOSED;
    const lost = this.wire.splice(0);
    this.bufferedAmount = 0;
    process.nextTick(() => {
      for (const { flushed } of lost) flushed?.(new Error('the connection closed'));
      this.emit('close');
    });
  }
  /** A frame from coffre. */
  receive(frame: Frame) {
    if (this.readyState === CLOSED) return;
    if (frame.kind === 'close') {
      // ws answers a close, and closes.
      if (this.readyState === OPEN) this.wire.push({ frame: { kind: 'close' } });
      this.readyState = CLOSED;
      return void process.nextTick(() => this.emit('close'));
    }
    this.emit('message', frame.kind === 'text' ? Buffer.from(frame.data) : frame.data, frame.kind === 'binary');
  }
  /** The next frame arrives at coffre. */
  deliver() {
    const { frame, flushed } = this.wire.shift()!;
    if (frame.kind !== 'close') this.bufferedAmount -= frame.data.length;
    if (flushed) process.nextTick(flushed);
    return frame;
  }
}

/** The app's connection to the listener, as Node gives it: the app writes, and reads what the listener wrote when the schedule lets it. */
class AppSocket extends EventEmitter {
  paused = false;
  destroyed = false;
  /** What the app wrote that the listener has not read; what it emitted; what the listener wrote that the app has not read. */
  readonly outbox: Buffer[] = [];
  emitted = 0;
  readonly inbox: { data: Buffer; written: Flushed }[] = [];
  writableLength = 0;
  #needDrain = false;
  pause() {
    this.paused = true;
    return this;
  }
  resume() {
    this.paused = false;
    process.nextTick(() => this.flow());
    return this;
  }
  flow() {
    while (!this.paused && !this.destroyed && this.outbox.length > 0) {
      const chunk = this.outbox.shift()!;
      this.emitted += chunk.length;
      this.emit('data', chunk);
    }
  }
  write(data: Buffer, written: Flushed) {
    if (this.destroyed) {
      process.nextTick(() => written(new Error('write after destroy')));
      return false;
    }
    this.inbox.push({ data, written });
    this.writableLength += data.length;
    if (this.writableLength >= SOCKET_HIGH_WATER) this.#needDrain = true;
    return !this.#needDrain;
  }
  /** The app reads up to `messages` of the listener's writes. */
  read(messages: number, flow: Flow) {
    for (let i = 0; i < messages && this.inbox.length > 0; i++) {
      const { data, written } = this.inbox.shift()!;
      flow.take(data);
      this.writableLength -= data.length;
      process.nextTick(written);
    }
    if (this.#needDrain && this.writableLength === 0) {
      this.#needDrain = false;
      process.nextTick(() => this.emit('drain'));
    }
  }
  destroy() {
    if (this.destroyed) return this;
    this.destroyed = true;
    const unwritten = this.inbox.splice(0);
    this.writableLength = 0;
    process.nextTick(() => {
      for (const { written } of unwritten) written(new Error('the socket was destroyed'));
      this.emit('close');
    });
    return this;
  }
  /** The app closes its end: with bytes it never read, its close is a reset, which the listener's socket sees as an error. */
  hangUp() {
    if (this.destroyed) return;
    if (this.inbox.length > 0) process.nextTick(() => this.emit('error', new Error('read ECONNRESET')));
    this.destroy();
  }
}

/**
 * coffre's end, from the design: on Workers it says it paces with a first
 * `0`, sends while less than a window is uncounted and counts back once
 * 128 KiB of what the database took piles up; on Node it sends a byte first
 * and counts nothing. Either way it checks the listener's counts.
 */
class Coffre {
  readonly wire: Frame[] = [];
  readonly paces: boolean;
  readonly up: Flow;
  readonly down: Flow;
  sent = 0;
  counted = 0;
  taken = 0;
  open = true;
  readonly pending: number[] = [];
  readonly held: Buffer[] = [];
  constructor(paces: boolean, up: Flow, down: Flow) {
    this.paces = paces;
    this.up = up;
    this.down = down;
    if (paces) this.wire.push({ kind: 'text', data: '0' });
  }
  write(size: number) {
    this.pending.push(size);
    this.pump();
  }
  pump() {
    while (this.open && this.pending.length > 0 && (!this.paces || this.sent - this.counted < WINDOW)) {
      const size = this.pending.shift()!;
      this.wire.push({ kind: 'binary', data: this.down.write(size) });
      this.sent += size;
    }
  }
  text(data: string) {
    if (this.open) this.wire.push({ kind: 'text', data });
  }
  receive(frame: Frame) {
    if (!this.open) return;
    if (frame.kind === 'text') {
      assert.match(frame.data, COUNT, 'a count is decimal digits');
      assert.ok(Number(frame.data) <= this.sent - this.counted, `the listener counts ${frame.data} bytes of the ${this.sent - this.counted} it holds uncounted`);
      this.counted += Number(frame.data);
      this.pump();
    } else if (frame.kind === 'binary') {
      this.held.push(frame.data);
    } else {
      this.wire.push({ kind: 'close' });
      this.open = false;
    }
  }
  read(messages: number) {
    for (let i = 0; i < messages && this.held.length > 0; i++) {
      const chunk = this.held.shift()!;
      this.up.take(chunk);
      this.taken += chunk.length;
      if (this.paces && this.taken >= COUNT_EVERY) {
        this.text(String(this.taken));
        this.taken = 0;
      }
    }
  }
  close() {
    if (!this.open) return;
    this.wire.push({ kind: 'close' });
    this.open = false;
  }
}

const kinds = ['app-write', 'db-write', 'to-coffre', 'to-listener', 'app-read', 'db-read', 'keepalive'] as const;
const endings = ['app-close', 'coffre-close', 'vanish'] as const;
const cheats = ['bad-count', 'over-count'] as const;
type Kind = typeof kinds[number] | typeof endings[number] | typeof cheats[number];
type Operation = { kind: Kind; size: number; n: number; text: string };
/** A write's size: any, and often the sizes the bounds turn on. */
const size = gs.oneOf(gs.integers({ minValue: 1, maxValue: BIGGEST }), gs.sampledFrom([BIGGEST, 64 * KiB, COUNT_EVERY - 1, COUNT_EVERY, 1]));
/** Text that is no count, eleven digits however small, and now and then a count. */
const badCount = gs.oneOf(
  gs.sampledFrom(['', '-1', '+1', '1.0', ' 1', '1 ', '1e3', '0x10', 'NaN', 'Infinity', '\u0663', '12345678901', '00000000000', '00000000001']),
  gs.fromRegex('[0-9]{1,12}', { fullmatch: true }),
  gs.text({ codec: 'utf-8', maxSize: 4 }),
);
const operation = (from: readonly Kind[]) => gs.record({
  kind: gs.sampledFrom(from),
  size,
  n: gs.integers({ minValue: 1, maxValue: 12 }),
  text: badCount,
});

const settle = () => new Promise<void>((resolve) => setImmediate(resolve));

/** One run: the listener, the app's socket, its WebSocket, and coffre at the other end. */
async function run(t: TestContext, operations: Operation[], { paces, honest }: { paces: boolean; honest: boolean }) {
  const up = new Flow();
  const down = new Flow();
  const app = new AppSocket();
  const ws = new ListenerSocket();
  const coffre = new Coffre(paces, up, down);
  carry(app as unknown as Socket, ws as unknown as WebSocket, KEEPALIVE_MS);
  ws.readyState = OPEN;
  ws.emit('open');

  // What the listener must do, from what it was sent and what it sent: whether coffre paces, by its
  // first frame, and the counts the listener accepted.
  let pacing: boolean | null = null;
  let accepted = 0;
  let countsSent = 0;
  let cheated = false;
  /** Frames delivered, either way. */
  let moved = 0;
  const toCoffre = (n: number) => {
    for (let i = 0; i < n && ws.wire.length > 0; i++) {
      const frame = ws.deliver();
      moved += 1;
      if (frame.kind === 'text') countsSent += Number(frame.data);
      coffre.receive(frame);
    }
  };
  const toListener = (n: number) => {
    for (let i = 0; i < n && coffre.wire.length > 0 && !ws.isPaused; i++) {
      const frame = coffre.wire.shift()!;
      moved += 1;
      if (ws.readyState === CLOSED || frame.kind === 'close') {
        ws.receive(frame);
        continue;
      }
      let refused = false;
      if (frame.kind === 'text') {
        refused = pacing === false || !COUNT.test(frame.data) || Number(frame.data) > app.emitted - accepted;
        if (!refused) accepted += Number(frame.data);
      }
      pacing ??= frame.kind === 'text';
      ws.receive(frame);
      assert.equal(ws.terminated, refused, refused ? `the listener ends a coffre that sent ${pacing === false ? 'a count, not pacing' : `the count ${JSON.stringify(frame.data)}`}` : 'the listener keeps an honest frame');
      cheated ||= refused;
    }
  };

  const check = async (where: string) => {
    await settle();
    // The app's bytes wait in its socket, not in the listener: a window uncounted at most, while coffre paces or has
    // not said, and the WebSocket's buffer at most either way, each plus one write.
    if (pacing !== false) assert.ok(app.emitted - accepted < WINDOW + BIGGEST, `${where}: the listener sent ${app.emitted - accepted} bytes uncounted`);
    const buffered = ws.wire.reduce((sum, { frame }) => sum + (frame.kind === 'binary' ? frame.data.length : 0), 0);
    assert.ok(buffered < HIGH_WATER + BIGGEST, `${where}: ${buffered} bytes wait in the listener's WebSocket`);
    // And coffre's bytes wait on the wire, not the listener: a socket buffer of them for a slow app, and one message.
    assert.ok(app.writableLength < SOCKET_HIGH_WATER + BIGGEST, `${where}: ${app.writableLength} bytes wait in the app's socket`);
    // Credit is conserved: the listener counts back what the app took, never more, and owes less than 128 KiB of it.
    if (!app.destroyed && ws.readyState === OPEN) {
      const owed = down.taken - countsSent - ws.wire.reduce((sum, { frame }) => sum + (frame.kind === 'text' ? Number(frame.data) : 0), 0);
      assert.ok(owed >= 0 && owed < COUNT_EVERY, `${where}: the listener owes coffre a count of ${owed} bytes`);
    }
  };

  const vanish = () => {
    coffre.wire.length = 0;
    coffre.open = false;
    ws.end();
  };
  for (const [i, op] of operations.entries()) {
    switch (op.kind) {
      case 'app-write':
        if (!app.destroyed) for (let k = 0; k < op.n; k++) app.outbox.push(up.write(op.size));
        process.nextTick(() => app.flow());
        break;
      case 'db-write': for (let k = 0; k < op.n; k++) coffre.write(op.size); break;
      case 'to-coffre': toCoffre(op.n); break;
      case 'to-listener': toListener(op.n); break;
      case 'app-read': app.read(op.n, down); break;
      case 'db-read': coffre.read(op.n); break;
      case 'keepalive': t.mock.timers.tick(KEEPALIVE_MS); break;
      case 'app-close': app.hangUp(); break;
      case 'coffre-close': coffre.close(); break;
      case 'vanish': vanish(); break;
      case 'bad-count': coffre.text(op.text); break;
      // A count of what the listener sent and has not had counted, as coffre sends it, give or take a byte.
      case 'over-count': coffre.text(String(Math.max(0, app.emitted - accepted - coffre.wire.reduce((sum, frame) => sum + (frame.kind === 'text' && COUNT.test(frame.data) ? Number(frame.data) : 0), 0) + (op.n % 3) - 1))); break;
    }
    await check(`after operation ${i} (${op.kind})`);
  }

  // Then everyone does everything they can, until nothing moves: whatever is owed must come.
  const drain = async () => {
    for (let rounds = 0; ; rounds++) {
      assert.ok(rounds < 10_000, 'the tunnel keeps moving without end');
      // A coffre on Node says nothing until the database answers the app's first message, as Postgres does its startup.
      if (!paces && coffre.sent === 0 && !app.destroyed) {
        if (up.written === 0) app.outbox.push(up.write(1));
        if (up.taken > 0) coffre.write(1);
        app.flow();
      }
      const state = () => [moved, up.taken, down.taken, app.emitted, coffre.sent, ws.readyState, app.destroyed].join();
      const before = state();
      app.read(Infinity, down);
      coffre.read(Infinity);
      coffre.pump();
      toCoffre(Infinity);
      toListener(Infinity);
      await check('draining');
      if (before !== state()) continue;
      // ws would end it only after its close timeout, 30 seconds.
      assert.notEqual(ws.readyState, CLOSING, "the listener's close waits for an answer it does not read");
      assert.ok(ws.wire.length === 0 && (coffre.wire.length === 0 || ws.readyState === CLOSED), 'frames wait on the wire that nothing will take');
      return;
    }
  };
  await drain();
  if (ws.readyState === OPEN && !app.destroyed) {
    if (honest) {
      // Liveness: both ways, every byte written arrived, once and in order, and nobody waits on credit.
      assert.equal(up.taken, up.written, "coffre's database took every byte the app wrote");
      assert.equal(down.taken, down.written, 'the app took every byte the database wrote');
      assert.ok(coffre.pending.length === 0 && app.outbox.length === 0, 'no write waits on a count');
      // The keepalive counts what the app took since the last count: then the counts are exactly what it took.
      t.mock.timers.tick(KEEPALIVE_MS);
      await settle();
      toCoffre(Infinity);
      assert.equal(countsSent, down.taken, 'the counts sum to what the app took');
    }
    app.hangUp();
    await drain();
  }
  // Both ends finish: the WebSocket and the app's socket close, and the keepalive stops.
  assert.equal(ws.readyState, CLOSED, "the listener's WebSocket closed");
  assert.ok(app.destroyed, "the app's socket closed");
  const { pings } = ws;
  t.mock.timers.tick(3 * KEEPALIVE_MS);
  await settle();
  assert.equal(ws.pings, pings, 'the keepalive stopped');
  if (honest) assert.ok(!cheated, 'an honest coffre is never ended for cheating');
}

const pacedSettings = propertySettings(100);
test(`with a coffre that paces, every byte arrives once and in order both ways, the app's held to a window, and the counts are exactly what the app took, seed ${pacedSettings.seed}`, (t) => {
  t.mock.timers.enable({ apis: ['setInterval'] });
  return hegel.testAsync(async (tc) => {
    const operations = tc.draw(gs.arrays(operation(kinds), { minSize: 1, maxSize: 40 }));
    await run(t, operations, { paces: true, honest: true });
  }, pacedSettings);
});

const nodeSettings = propertySettings(60);
test(`with a coffre on Node, which never paces, the app is held to a window until its first byte, then waits on no count, and the listener counts back all the same, seed ${nodeSettings.seed}`, (t) => {
  t.mock.timers.enable({ apis: ['setInterval'] });
  return hegel.testAsync(async (tc) => {
    const operations = tc.draw(gs.arrays(operation(kinds), { minSize: 1, maxSize: 40 }));
    await run(t, operations, { paces: false, honest: true });
  }, nodeSettings);
});

const endingSettings = propertySettings(80);
test(`a connection ended early by the app, by coffre or by the network ends both sockets, with what arrived in order and the keepalive stopped, seed ${endingSettings.seed}`, (t) => {
  t.mock.timers.enable({ apis: ['setInterval'] });
  return hegel.testAsync(async (tc) => {
    const paces = tc.draw(gs.booleans());
    const operations = tc.draw(gs.arrays(operation(kinds), { minSize: 1, maxSize: 30 }));
    const ending = tc.draw(gs.sampledFrom(endings));
    const at = tc.draw(gs.integers({ minValue: 0, maxValue: operations.length }));
    operations.splice(at, 0, { kind: ending, size: 1, n: 1, text: '' });
    await run(t, operations, { paces, honest: true });
  }, endingSettings);
});

const cheatSettings = propertySettings(150);
test(`a coffre that counts what it was never sent, sends what is no count, or counts after saying it does not pace is ended at that frame, seed ${cheatSettings.seed}`, (t) => {
  t.mock.timers.enable({ apis: ['setInterval'] });
  return hegel.testAsync(async (tc) => {
    const paces = tc.draw(gs.booleans());
    const operations = tc.draw(gs.arrays(operation([...kinds, ...cheats]), { minSize: 1, maxSize: 30 }));
    await run(t, operations, { paces, honest: false });
  }, cheatSettings);
});

test('the listener takes a count of one to ten decimal digits: eleven are refused however small, and ten zeros count nothing', async () => {
  for (const [count, refused] of [['0000000000', false], ['0000000005', false], ['00000000000', true], ['00000000001', true]] as const) {
    const app = new AppSocket();
    const ws = new ListenerSocket();
    carry(app as unknown as Socket, ws as unknown as WebSocket, KEEPALIVE_MS);
    ws.readyState = OPEN;
    ws.emit('open');
    app.outbox.push(Buffer.alloc(5));
    await settle();
    ws.receive({ kind: 'text', data: count });
    assert.equal(ws.terminated, refused, count);
    app.destroy();
    ws.end();
  }
});
