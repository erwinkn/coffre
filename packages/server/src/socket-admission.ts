// What a plugin's WebSocket passes before it opens, on Node and on Workers
// alike: the migration and key door, as `respond` keeps it for every other request,
// then the plugin under the path, which refuses or hands back its session.
import { UNAVAILABLE_RETRY_AFTER } from './api/errors.ts';
import { keyReady, schemaReady } from './app.ts';
import { pluginSocket, type SocketSession } from './plugins.ts';
import type { CoffreRuntime } from './runtime.ts';

/**
 * How long a plugin has to admit a WebSocket or refuse it. Long enough for
 * a burst of runs at once, each admission writing to the one audit chain:
 * 64 runs together took up to 22 s each to admit on Cloudflare.
 */
const ADMISSION_MS = 45_000;

/**
 * The plugin's refusal or its session; a path no plugin takes for a socket
 * is a 404, and a plugin that has not decided in time has refused (`inTime`).
 */
export async function admitSocket(request: Request, runtime: CoffreRuntime, sourceIp: string | null, hold?: (deciding: Promise<unknown>) => void): Promise<Response | SocketSession> {
  return inTime(
    (async () =>
      !(await schemaReady(runtime))
        ? new Response("coffre's database lacks this version's migrations", { status: 503 })
        : (await keyReady(runtime)) !== null
          ? new Response('coffre is not serving under its app key yet', { status: 503 })
          : ((await pluginSocket(request, runtime, sourceIp)) ?? new Response('no WebSocket here', { status: 404 })))(),
    hold,
  );
}

/**
 * A decision on a WebSocket, if it comes within `ADMISSION_MS`, and a
 * refusal for taking too long otherwise. `hold` is told of the decision
 * itself, which goes on past that refusal: what holds a slot for it (a
 * Durable Object's) holds it until then.
 */
export async function inTime(decided: Promise<Response | SocketSession>, hold?: (deciding: Promise<unknown>) => void): Promise<Response | SocketSession> {
  let late: ReturnType<typeof setTimeout> | undefined;
  try {
    hold?.(decided);
    return await Promise.race([decided, new Promise<Response>((resolve) => (late = setTimeout(() => resolve(new Response('coffre took too long to decide', { status: 503, headers: { 'retry-after': UNAVAILABLE_RETRY_AFTER } })), ADMISSION_MS)))]);
  } catch {
    return new Response('the plugin failed', { status: 500 });
  } finally {
    clearTimeout(late);
  }
}
