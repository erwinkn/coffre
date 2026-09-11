import { createFileRoute } from '@tanstack/react-router';
import { limitedJson, failure, rpcResponse } from '../../../../packages/core/src/http';
import { dispatch } from '../lib/gateway.server';
export const Route = createFileRoute('/api/v1/operations')({ server: { handlers: { POST: async ({ request }) => { try { return rpcResponse(await dispatch(request, await limitedJson(request))); } catch (error) { return rpcResponse(failure(error, crypto.randomUUID())); } } } } });
