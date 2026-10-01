import { KekCancelledError, type KeyOperation } from './types.ts';

export function checkOperation(operation?: KeyOperation, uncertain = false): void {
  if (operation !== undefined && (operation.signal.aborted || Date.now() >= operation.deadline)) {
    throw new KekCancelledError(uncertain);
  }
}

const signals = new WeakMap<KeyOperation, AbortSignal>();

/**
 * Enforce the deadline even when the caller's signal has not fired yet: one
 * signal for every call of an operation, so its deadline cancels them all at
 * once. With a timer per call, one call's could fire first, free its slot,
 * and start a key queued behind it whose own timer had not fired yet.
 */
export function operationSignal(operation?: KeyOperation): AbortSignal | undefined {
  if (operation === undefined) return undefined;
  checkOperation(operation);
  let signal = signals.get(operation);
  if (signal === undefined) {
    signal = AbortSignal.any([operation.signal, AbortSignal.timeout(Math.max(0, operation.deadline - Date.now()))]);
    signals.set(operation, signal);
  }
  return signal;
}

/** Credentials can finish later, but must never send a request after cancellation. */
export function cancellable<T>(work: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return work;
  return new Promise((resolve, reject) => {
    const abort = () => {
      signal.removeEventListener('abort', abort);
      reject(new KekCancelledError());
    };
    if (signal.aborted) abort();
    else signal.addEventListener('abort', abort, { once: true });
    work.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}

export function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const abort = () => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      reject(new KekCancelledError());
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', abort);
      resolve();
    }, ms);
    if (signal?.aborted) abort();
    else signal?.addEventListener('abort', abort, { once: true });
  });
}
