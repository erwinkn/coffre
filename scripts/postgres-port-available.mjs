// Probe before starting Docker: after a failed bind, some daemon versions can
// start the same container without publishing its port. CI reserves the port
// from automatic outgoing allocations; this waits out earlier sockets too.
import { createServer } from 'node:net';

const port = Number(process.argv[2]);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Expected a TCP port');
const probe = createServer();
probe.once('error', (error) => {
    if (error.code === 'EADDRINUSE') process.exitCode = 1;
    else {
        console.error(error);
        process.exitCode = 2;
    }
});
probe.listen({ host: '0.0.0.0', port, exclusive: true }, () => probe.close());
