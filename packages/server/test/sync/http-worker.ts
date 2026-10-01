import { requestJson, type JsonRequest } from '../../src/sync/http.ts';

// Run the same request in workerd, including its native redirect behavior.
export default {
  async fetch(request: Request): Promise<Response> {
    const input = await request.json() as JsonRequest;
    try {
      return Response.json(await requestJson({ token: 'project-token' }, input));
    } catch (error) {
      return Response.json({ error: error instanceof Error ? error.message : String(error) }, { status: 502 });
    }
  },
};
