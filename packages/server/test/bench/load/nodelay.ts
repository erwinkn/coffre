// Every TCP socket this process makes or accepts sends at once (TCP_NODELAY).
// Node leaves Nagle's algorithm on, and a proxy that relays a Postgres
// client's small writes with it on waits for the peer's delayed ACK: 40 ms
// on Linux, on about one read in two. Miniflare's local Hyperdrive proxy,
// which this process runs, is one such: patched here before it starts.
import { syncBuiltinESMExports } from 'node:module';
import net from 'node:net';

const connect = net.connect;
const createConnection = net.createConnection;
const createServer = net.createServer;
const fast = <T extends net.Socket>(socket: T): T => socket.setNoDelay(true);
net.connect = ((...args: Parameters<typeof net.connect>) => fast(connect(...args))) as typeof net.connect;
net.createConnection = ((...args: Parameters<typeof net.createConnection>) => fast(createConnection(...args))) as typeof net.createConnection;
net.createServer = ((...args: Parameters<typeof net.createServer>) => createServer(...args).on('connection', (socket: net.Socket) => void socket.setNoDelay(true))) as typeof net.createServer;
// And the named imports of `node:net` elsewhere in the process, which ESM binds apart from its default export.
syncBuiltinESMExports();
