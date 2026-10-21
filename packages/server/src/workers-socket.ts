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
 * `socket` once open, as a tunnel's; closed and refused if `signal` ends
 * the session first. `startTls` takes no name: workerd checks the
 * certificate against the host dialled, and refuses one of the caller's
 * (`expectedServerHostname`).
 */
export async function workersSocket(socket: WorkersSocket, signal?: AbortSignal): Promise<Socket> {
  const abort = () => void socket.close().catch(() => undefined);
  signal?.addEventListener('abort', abort, { once: true });
  try {
    await socket.opened;
  } finally {
    signal?.removeEventListener('abort', abort);
  }
  // Ended while it opened, or before it was handed here: closed either way.
  if (signal?.aborted) {
    abort();
    throw new Error('the session ended');
  }
  return {
    ...pipeOf(socket),
    startTls: async () => {
      const secure = socket.startTls();
      await secure.opened;
      return pipeOf(secure);
    },
  };
}
