import uiWorker, {
  type UiBindings,
  type UiExecutionContext,
} from '@coffre/ui-spike';

type Env = {
  ASSETS: { fetch(request: Request): Promise<Response> };
  UI_DATABASE_URL: string;
  [name: `COFFRE_${string}`]: string | undefined;
};

function uiBindings(env: Env): UiBindings {
  const { ASSETS: _assets, UI_DATABASE_URL, ...coffreBindings } = env;
  return {
    ...coffreBindings,
    HYPERDRIVE: { connectionString: UI_DATABASE_URL },
  };
}

function cspNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...bytes));
}

export default {
  async fetch(request: Request, env: Env, context: UiExecutionContext): Promise<Response> {
    if (new URL(request.url).pathname === '/api/spike') {
      return Response.json({ ok: true, owner: 'consumer', runtime: 'worker' });
    }

    // This is a genuine in-process call into the installed prebuilt package.
    // The fourth argument is forwarded to TanStack Start's handler.fetch.
    const nonce = cspNonce();
    const response = await uiWorker.fetch(request, uiBindings(env), context, {
      context: { cspNonce: nonce },
    });
    const tagged = new Response(response.body, response);
    tagged.headers.set('x-ssr-spike-request-nonce', nonce);
    return tagged;
  },
};
