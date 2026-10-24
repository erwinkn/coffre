// The object's end of the Postgres tunnel on Workers (`fromWebSocket`,
// cloudflare-sockets.ts), driven against a client written from the protocol
// (docs/design/credential-proxy.md, "Postgres through a tunnel"), through a
// simulated WebSocket whose schedule Hegel draws: who writes, how much, when
// each frame arrives (in order, each way), when the database reads, and when
// either side closes or the network goes. Text frames are counts of bytes
// taken, binary frames are bytes; each side sends at most a window the other
// has not counted, and the object ends a client that does otherwise with 1008.
// `coffre run`'s end has its own properties (packages/cli/test/tunnel-properties.test.ts).
import assert from 'node:assert/strict';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { propertySettings } from '../../../scripts/property-settings.ts';
import { fromWebSocket, type WorkersWebSocket } from '../src/cloudflare-sockets.ts';

const KiB = 1024;
/** The protocol's numbers, from the design: a window, a count at least this often, and what ends a client. */
const WINDOW = 1024 * KiB;
const COUNT_EVERY = 128 * KiB;
const MOST_HELD = 2 * WINDOW;
/** The largest message either side sends: a database read, or the app's. */
const BIGGEST = 300 * KiB;
const COUNT = /^\d{1,10}$/;

/**
 * Each direction's bytes are a long pseudo-random sequence, so a chunk
 * dropped, repeated or out of order does not line up with what was written
 * at its offset.
 */
const PERIOD = 1_000_003;
/** The longest message, a cheat's that fills the object to its bound. */
const LONGEST = MOST_HELD + 1;
const pattern = (() => {
  const bytes = Buffer.alloc(PERIOD + LONGEST);
  let x = 0x9e3779b9;
  for (let i = 0; i < PERIOD; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    bytes[i] = x & 0xff;
  }
  bytes.copy(bytes, PERIOD, 0, LONGEST);
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
  take(chunk: Uint8Array) {
    assert.ok(chunk.length <= LONGEST && this.taken + chunk.length <= this.written, `${chunk.length} bytes arrived past the ${this.written} written`);
    const expected = pattern.subarray(this.taken % PERIOD, (this.taken % PERIOD) + chunk.length);
    assert.ok(Buffer.from(chunk.buffer, chunk.byteOffset, chunk.length).equals(expected), `the bytes at ${this.taken} are not the ones written there`);
    this.taken += chunk.length;
  }
}

type Frame = { kind: 'binary'; data: Uint8Array } | { kind: 'text'; data: string } | { kind: 'close'; code: number };

/** The object's WebSocket, as workerd gives it: what it sends goes on the wire to the client, in order. */
class ObjectSocket implements WorkersWebSocket {
  // As socketsObject sets it, before the pipe is made.
  binaryType: 'blob' | 'arraybuffer' = 'arraybuffer';
  readonly #onMessage: ((event: { data: ArrayBuffer | string }) => void)[] = [];
  readonly #onEnd = { close: [] as (() => void)[], error: [] as (() => void)[] };
  /** The code the object closed with; whether the client's close, or the network, ended it. */
  closedWith: number | null = null;
  gone = false;
  /** Bytes it sent, and the sum of its counts. */
  sent = 0;
  counted = 0;
  readonly wire: Frame[];
  constructor(wire: Frame[]) {
    this.wire = wire;
  }
  accept() {}
  send(data: Uint8Array | string) {
    if (this.closedWith !== null || this.gone) throw new TypeError('WebSocket send() after close');
    if (typeof data === 'string') {
      this.wire.push({ kind: 'text', data });
      this.counted += Number(data);
    } else {
      this.wire.push({ kind: 'binary', data: Uint8Array.from(data) });
      this.sent += data.length;
    }
  }
  close(code = 1000) {
    if (this.closedWith !== null || this.gone) throw new TypeError('WebSocket already closed');
    this.closedWith = code;
    this.wire.push({ kind: 'close', code });
  }
  addEventListener(type: 'message' | 'close' | 'error', listener: (event: { data: ArrayBuffer | string }) => void) {
    if (type === 'message') this.#onMessage.push(listener);
    else this.#onEnd[type].push(listener as () => void);
  }
  message(data: Uint8Array | string) {
    const event = { data: typeof data === 'string' ? data : data.buffer.slice(data.byteOffset, data.byteOffset + data.length) as ArrayBuffer };
    for (const listener of this.#onMessage) listener(event);
  }
  end(type: 'close' | 'error') {
    this.gone = true;
    for (const listener of this.#onEnd[type]) listener();
  }
}

/**
 * `coffre run`'s listener as the design describes it: it sends the app's
 * bytes while less than a window is uncounted, counts back once 128 KiB of
 * what it took piles up, or on a keepalive, and checks the object's counts.
 */
class Client {
  sent = 0;
  counted = 0;
  taken = 0;
  countedBack = 0;
  received = 0;
  frames = 0;
  open = true;
  readonly pending: number[] = [];
  readonly inbox: Uint8Array[] = [];
  readonly wire: Frame[];
  readonly up: Flow;
  readonly down: Flow;
  constructor(wire: Frame[], up: Flow, down: Flow) {
    this.wire = wire;
    this.up = up;
    this.down = down;
  }
  write(size: number) {
    this.pending.push(size);
    this.pump();
  }
  pump() {
    while (this.open && this.pending.length > 0 && this.sent - this.counted < WINDOW) this.binary(this.pending.shift()!);
  }
  binary(size: number) {
    if (!this.open) return;
    this.wire.push({ kind: 'binary', data: this.up.write(size) });
    this.sent += size;
  }
  text(data: string) {
    if (this.open) this.wire.push({ kind: 'text', data });
  }
  receive(frame: Frame) {
    if (this.frames++ === 0) assert.deepEqual(frame, { kind: 'text', data: '0' }, 'the object says it paces before any byte');
    if (frame.kind === 'text') {
      assert.match(frame.data, COUNT, 'a count is decimal digits');
      assert.ok(Number(frame.data) <= this.sent - this.counted, `the object counts ${frame.data} bytes of the ${this.sent - this.counted} it holds uncounted`);
      this.counted += Number(frame.data);
      this.pump();
    } else if (frame.kind === 'binary') {
      this.inbox.push(frame.data);
      this.received += frame.data.length;
    } else {
      // The object's close, or its answer to ours.
      if (this.open) this.wire.push({ kind: 'close', code: frame.code });
      this.open = false;
    }
  }
  read(messages: number) {
    for (let i = 0; i < messages && this.inbox.length > 0; i++) {
      const chunk = this.inbox.shift()!;
      this.down.take(chunk);
      this.taken += chunk.length;
      if (this.taken >= COUNT_EVERY) this.count();
    }
  }
  count() {
    if (!this.open) return;
    this.text(String(this.taken));
    this.countedBack += this.taken;
    this.taken = 0;
  }
  close() {
    if (!this.open) return;
    this.wire.push({ kind: 'close', code: 1000 });
    this.open = false;
  }
}

const kinds = ['app-write', 'db-write', 'to-object', 'to-client', 'app-read', 'db-read', 'keepalive'] as const;
const endings = ['client-close', 'object-close', 'vanish'] as const;
const cheats = ['bad-count', 'over-count', 'flood', 'fill'] as const;
type Kind = typeof kinds[number] | typeof endings[number] | typeof cheats[number];
type Operation = { kind: Kind; size: number; n: number; text: string };
/** Text that is no count, eleven digits however small, and now and then a count. */
const badCount = gs.oneOf(
  gs.sampledFrom(['', '-1', '+1', '1.0', ' 1', '1 ', '1e3', '0x10', 'NaN', 'Infinity', '\u0663', '12345678901', '00000000000', '00000000001']),
  gs.fromRegex('[0-9]{1,12}', { fullmatch: true }),
  gs.text({ codec: 'utf-8', maxSize: 4 }),
);
/** A write's size: any, and often the sizes the bounds turn on. */
const size = gs.oneOf(gs.integers({ minValue: 0, maxValue: BIGGEST }), gs.sampledFrom([BIGGEST, 64 * KiB, COUNT_EVERY - 1, COUNT_EVERY, 1]));
const operation = (from: readonly Kind[]) => gs.record({
  kind: gs.sampledFrom(from),
  size,
  n: gs.integers({ minValue: 1, maxValue: 12 }),
  text: badCount,
});

const settle = () => new Promise<void>((resolve) => setImmediate(resolve));

/** One run: the object's end, a client, the wires between them, and the database's side of the pipe. */
async function run(operations: Operation[], { honest }: { honest: boolean }) {
  const toClient: Frame[] = [];
  const toObject: Frame[] = [];
  const up = new Flow();
  const down = new Flow();
  const object = new ObjectSocket(toClient);
  const client = new Client(toObject, up, down);
  const pipe = fromWebSocket(object);
  let failure: unknown = null;
  let closed = false;
  void pipe.closed.then(() => (closed = true));

  // The database reads only when the schedule lets it.
  const reader = pipe.readable.getReader();
  let permits = 0;
  let permitted: (() => void) | null = null;
  let readEnded = false;
  void (async () => {
    for (;;) {
      while (permits === 0) await new Promise<void>((resolve) => (permitted = resolve));
      permits -= 1;
      const { value, done } = await reader.read();
      if (done) return void (readEnded = true);
      up.take(value);
    }
  })().catch((error: unknown) => (failure ??= error));
  const allow = (n: number) => {
    permits += n;
    permitted?.();
    permitted = null;
  };

  // The database's answers, one write at a time, as a socket's pump awaits each.
  const writer = pipe.writable.getWriter();
  const answers: number[] = [];
  let writing = false;
  let writeFailed = false;
  const pumpAnswers = () => {
    if (writing || writeFailed || answers.length === 0) return;
    writing = true;
    writer.write(down.write(answers.shift()!)).then(
      () => {
        writing = false;
        pumpAnswers();
      },
      () => {
        writing = false;
        writeFailed = true;
      },
    );
  };

  // What the object must do, from what it was sent and what it sent: the client's bytes it holds (taken
  // and not counted back, or queued) and the counts it accepted.
  let delivered = 0;
  let accepted = 0;
  let cheated = false;
  /** Frames delivered, either way. */
  let moved = 0;
  const done = () => object.closedWith !== null || object.gone;
  const toObjectFrames = (n: number) => {
    for (let i = 0; i < n && toObject.length > 0; i++) {
      const frame = toObject.shift()!;
      moved += 1;
      if (frame.kind === 'close') {
        if (done()) continue;
        object.end('close');
        // workerd answers a client's close itself.
        toClient.push({ kind: 'close', code: 1000 });
        continue;
      }
      if (done()) {
        object.message(frame.data);
        continue;
      }
      let refused = false;
      if (frame.kind === 'text') {
        refused = !COUNT.test(frame.data) || Number(frame.data) > object.sent - accepted;
        if (!refused) accepted += Number(frame.data);
      } else if (frame.data.length > 0) {
        refused = delivered - object.counted + frame.data.length > MOST_HELD;
        if (!refused) delivered += frame.data.length;
      }
      object.message(frame.data);
      assert.equal(object.closedWith, refused ? 1008 : null, refused ? `the object ends a client that sent ${frame.kind === 'text' ? `the count ${JSON.stringify(frame.data)}` : `${frame.data.length} bytes past its window`}` : 'the object keeps an honest frame');
      cheated ||= refused;
    }
  };
  /** What is on its way to the object: the sum of the counts, and the bytes. */
  const counting = () => toObject.reduce((sum, frame) => sum + (frame.kind === 'text' && COUNT.test(frame.data) ? Number(frame.data) : 0), 0);
  const sending = () => toObject.reduce((sum, frame) => sum + (frame.kind === 'binary' ? frame.data.length : 0), 0);
  const toClientFrames = (n: number) => {
    for (let i = 0; i < n && toClient.length > 0; i++, moved++) client.receive(toClient.shift()!);
  };

  const check = async (where: string) => {
    await settle();
    if (failure !== null) throw failure;
    const held = delivered - object.counted;
    assert.ok(held <= MOST_HELD, `${where}: the object holds ${held} bytes of the client's`);
    if (honest) assert.ok(held < WINDOW + BIGGEST, `${where}: the object holds ${held} bytes of an honest client's, more than a window and a message`);
    assert.ok(object.sent - accepted < WINDOW + BIGGEST, `${where}: the object sent ${object.sent - accepted} bytes uncounted, more than a window and one write`);
    // Credit is conserved: the object counts back what the database took, never more, and owes less than 128 KiB of it.
    assert.ok(object.counted <= up.taken, `${where}: the object counted ${object.counted} bytes of the ${up.taken} the database took`);
    if (!done()) assert.ok(up.taken - object.counted < COUNT_EVERY, `${where}: the object owes the client a count of ${up.taken - object.counted} bytes`);
  };

  for (const [i, op] of operations.entries()) {
    switch (op.kind) {
      case 'app-write': for (let k = 0; k < op.n; k++) client.write(op.size); break;
      case 'db-write': for (let k = 0; k < op.n; k++) answers.push(op.size); pumpAnswers(); break;
      case 'to-object': toObjectFrames(op.n); break;
      case 'to-client': toClientFrames(op.n); break;
      case 'app-read': client.read(op.n); break;
      case 'db-read': allow(op.n); break;
      case 'keepalive': client.count(); break;
      case 'client-close': client.close(); break;
      case 'object-close': pipe.close(); break;
      case 'vanish':
        toClient.length = 0;
        toObject.length = 0;
        client.open = false;
        if (!object.gone) object.end('error');
        break;
      case 'bad-count': client.text(op.text); break;
      // A count of what the object sent and has not had counted, by the time it was sent, give or take a byte.
      case 'over-count': client.text(String(Math.max(0, object.sent - accepted - counting() + (op.n % 3) - 1))); break;
      // One message that fills what the object holds of the client's to its bound, give or take a byte.
      case 'fill': client.binary(Math.max(0, MOST_HELD - (delivered - object.counted) - sending() + (op.n % 3) - 1)); break;
      case 'flood': for (let k = 0; k < op.n; k++) client.binary(op.size); break;
    }
    await check(`after operation ${i} (${op.kind})`);
  }

  // Then everyone does everything they can, until nothing moves: whatever is owed must come.
  const drain = async () => {
    allow(Infinity);
    for (let rounds = 0; ; rounds++) {
      assert.ok(rounds < 10_000, 'the tunnel keeps moving without end');
      const state = () => [moved, up.taken, down.taken, client.sent, object.sent, writing].join();
      const before = state();
      client.read(Infinity);
      client.pump();
      pumpAnswers();
      toObjectFrames(Infinity);
      toClientFrames(Infinity);
      await check('draining');
      if (before !== state()) continue;
      assert.ok(toClient.length === 0 && toObject.length === 0, 'frames wait on the wire that nothing will take');
      return;
    }
  };
  await drain();
  // An honest run nobody ended is still open, so that what it owes is checked below, not skipped.
  if (honest && !operations.some((op) => (endings as readonly string[]).includes(op.kind))) assert.ok(!done(), 'an honest tunnel nobody ended has ended');
  if (!done()) {
    if (honest) {
      // Liveness: both ways, every byte written arrived, once and in order, and nobody waits on credit.
      assert.equal(up.taken, up.written, "the database took every byte the app wrote");
      assert.equal(down.taken, down.written, 'the app took every byte the database wrote');
      assert.ok(answers.length === 0 && !writing && client.pending.length === 0, 'no write waits on a count');
    }
    client.close();
    await drain();
  }
  // Both ends finish: the object's pipe ends, the database's read ends, no write is left waiting.
  assert.ok(closed, "the object's pipe ended");
  assert.ok(readEnded, "the database's read ended");
  assert.ok(!writing, 'no write is left waiting');
  // Whatever reached the object before it ended, it gave to the database.
  assert.equal(up.taken, delivered, 'the database took every byte the object accepted');
  if (honest) assert.ok(!cheated && object.closedWith !== 1008, 'an honest client is never ended for cheating');
}

const honestSettings = propertySettings(100);
test(`with an honest client that eventually reads, every byte arrives once and in order both ways, within the window, and counts back exactly what was taken, seed ${honestSettings.seed}`, () => hegel.testAsync(async (tc) => {
  const operations = tc.draw(gs.arrays(operation(kinds), { minSize: 1, maxSize: 40 }));
  await run(operations, { honest: true });
}, honestSettings));

const endingSettings = propertySettings(60);
test(`a connection ended early by either side, or by the network, ends both ends with what arrived delivered in order and nothing left waiting, seed ${endingSettings.seed}`, () => hegel.testAsync(async (tc) => {
  const operations = tc.draw(gs.arrays(operation(kinds), { minSize: 1, maxSize: 30 }));
  const ending = tc.draw(gs.sampledFrom(endings));
  const at = tc.draw(gs.integers({ minValue: 0, maxValue: operations.length }));
  operations.splice(at, 0, { kind: ending, size: 0, n: 1, text: '' });
  await run(operations, { honest: true });
}, endingSettings));

const cheatSettings = propertySettings(150);
test(`a client that counts what it was never sent, sends what is no count, or floods past its window is ended with 1008 at that frame, and the object never holds more than two windows, seed ${cheatSettings.seed}`, () => hegel.testAsync(async (tc) => {
  const operations = tc.draw(gs.arrays(operation([...kinds, ...cheats]), { minSize: 1, maxSize: 30 }));
  await run(operations, { honest: false });
}, cheatSettings));

test('the object takes a count of one to ten decimal digits: eleven are refused however small, and ten zeros count nothing', async () => {
  for (const [count, code] of [['0000000000', null], ['0000000005', null], ['00000000000', 1008], ['00000000001', 1008]] as const) {
    const object = new ObjectSocket([]);
    const writer = fromWebSocket(object).writable.getWriter();
    await writer.write(new Uint8Array(5));
    object.message(count);
    assert.equal(object.closedWith, code, count);
  }
});
