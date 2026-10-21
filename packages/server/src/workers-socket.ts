// A TCP socket as Workers give one, from `cloudflare:sockets`'s connect()
// or a VPC Network binding's, as a tunnel's `Socket` (plugins.ts). Web
// streams only: Node loads it too, where tests hand it such a socket.
import type { Pipe, Socket } from './plugins.ts';

/** A Workers TCP socket, as far as a tunnel needs it. */
export type WorkersSocket = {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  opened: Promise<unknown>;
  closed: Promise<void>;
  close(): Promise<void>;
  startTls(): WorkersSocket;
};

const pipeOf = (socket: WorkersSocket): Pipe => ({
  readable: socket.readable,
  writable: socket.writable,
  close: () => void socket.close().catch(() => undefined),
  closed: socket.closed.then(
    () => undefined,
    () => undefined,
  ),
});

/**
 * The socket a dial gives, once open, as a tunnel's: `dialled` as the
 * platform hands it, at once (`cloudflare:sockets`) or later (a binding's
 * `connect()`). If `signal` ends the session first, whatever comes is
 * closed and refused, the TLS that `startTls` begins included. `startTls`
 * takes no name: workerd checks the certificate against the host
 * dialled, and refuses one of the caller's (`expectedServerHostname`).
 */
export async function workersSocket(dialled: WorkersSocket | Promise<WorkersSocket>, signal?: AbortSignal): Promise<Socket> {
  const socket = await opened(dialled, signal);
  return {
    ...pipeOf(socket),
    startTls: async () => pipeOf(await opened(socket.startTls(), signal)),
  };
}

/** `dialled`, open; closed as soon as it comes if `signal` has ended the session, which then waits for it no longer. */
function opened(dialled: WorkersSocket | Promise<WorkersSocket>, signal?: AbortSignal): Promise<WorkersSocket> {
  const coming = Promise.resolve(dialled);
  const open = coming.then(async (socket) => {
    await socket.opened;
    return socket;
  });
  if (signal === undefined) return open;
  return new Promise<WorkersSocket>((resolve, reject) => {
    const abort = () => {
      reject(new Error('the session ended'));
      coming.then((socket) => socket.close().catch(() => undefined), () => undefined);
    };
    if (signal.aborted) return abort();
    signal.addEventListener('abort', abort, { once: true });
    open.then(
      (socket) => {
        signal.removeEventListener('abort', abort);
        resolve(socket);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', abort);
        reject(error);
      },
    );
  });
}
