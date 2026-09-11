import { createServerFn } from '@tanstack/react-start';
import { getRequest, setResponseHeader } from '@tanstack/react-start/server';
import { type Command, type RpcResult } from '../../../../packages/contracts/src/index';
export const operate = createServerFn({ method: 'POST', strict: false }).validator((data: unknown) => data).handler(async ({ data }) => {
  setResponseHeader('Cache-Control', 'no-store');
  const { dispatch } = await import('./gateway.server');
  return dispatch(getRequest(), data);
});
export class OperationError extends Error { constructor(public readonly code: string, message: string) { super(message); } }
export async function invoke<T>(command: Command, signal?: AbortSignal, requestId = crypto.randomUUID()): Promise<T> {
  const result: RpcResult = await operate({ data: { requestId, command }, headers: { 'X-Coffre-Request': '1' }, signal });
  if (!result.ok) throw new OperationError(result.error.code, result.error.message);
  return result.data as T;
}
