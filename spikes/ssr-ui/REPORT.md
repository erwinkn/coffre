# Prebuilt TanStack Start UI spike

## Verdict

Yes. A separate Worker can import the current Cloudflare-built TanStack Start
server output, call its `fetch` method in process, and serve the matching client
files from a pnpm-symlinked `node_modules/@coffre/ui-spike/dist/client` directory.
Wrangler 4.118.0 rebundled the prebuilt server successfully. Local static assets
followed the symlink. The login page rendered on the server, hydrated, and loaded
its JavaScript, CSS, and fonts without a 404.

The same server output also imported and ran on Node 24.21.0 behind a 109-line
`node:http` adapter. It rendered and hydrated the same page with the same CSP
nonce behavior. A second Start build is not required by anything observed in
this spike.

There is one important qualification. The artifact tested here is today's whole
`apps/web` Worker, not the desired UI boundary. It exports `fetch` and
`scheduled`, bundles the database and API, reads coffre configuration, and
expects a `HYPERDRIVE`-shaped binding. The packaging mechanism works, but this is
the wrong final API. `@coffre/ui` should build a UI-only Start handler after page
loaders move to `@coffre/client`.

I recommend publishing the prebuilt UI. Do not make each consumer compile its
source.

## Prototype layout

`ui-package/` is a package named `@coffre/ui-spike`. Its `dist/` is a copy of
`apps/web/dist`, and its package export points at `dist/server/index.js`. The
generated chunks and client files are copied without a behavioral change. I
made one small change to the copied entry: its `fetch` accepts an optional fourth
argument and forwards that object to TanStack Start's `handler.fetch`. This was
necessary because the current generated entry hides the Start handler inside
the whole-app Worker. The consumer passes `{ context: { cspNonce } }` there. The
entry retains the current three-argument behavior when no options are supplied.

The copied `dist/` is not checked in here; it is about 72,000 generated lines.
The runnable spike, copy and entry change included, is commit `ac32b3e` on
branch `bb/coffre-spike-prebuilt-ssr-ui-package-thr_5ney5784rk`. To rebuild it
from this tree, run `pnpm --dir apps/web build`, copy `apps/web/dist` to
`ui-package/dist`, and make the entry change above.

`consumer/` is a separate package with its own `wrangler.jsonc`. It depends on
the UI through `workspace:*`; pnpm creates this link:

```text
consumer/node_modules/@coffre/ui-spike -> ../../../ui-package
```

The consumer handles `/api/spike` itself, then calls the imported UI Worker's
`fetch` for every other path. It mints the nonce and passes it into the package's
Start request context. Its static asset directory is exactly:

```text
./node_modules/@coffre/ui-spike/dist/client
```

The Node adapter imports the same package and serves that same directory with a
small static-file handler before calling the UI.

No database was created. Anonymous `/login` does not query Postgres, so a
database would have added setup without testing the packaging boundary.

## What the existing build contains

`pnpm --dir apps/web build` produced:

- `dist/client`: 40 files, 1.4 MiB. It contains hashed JavaScript chunks, one
  stylesheet, and 12 WOFF2 font subsets.
- `dist/server`: 89 files, 3.3 MiB. `index.js` is 592,094 bytes and imports
  relative server chunks.
- `dist/server/wrangler.json`: a generated deployment config with
  `main: "index.js"`, `assets.directory: "../client"`, and `no_bundle: true`.
- `dist/server/index.js`: one default export with `fetch` and `scheduled`.

The TanStack asset manifest is a generated JavaScript chunk imported by the
server. It is not read from the filesystem at request time. Its URLs are rooted
at `/assets/`, and those URLs match the files under `dist/client/assets`.

The emitted server has no `import.meta` references. It imports
`node:async_hooks`, `node:crypto`, `node:stream`, and `node:stream/web`. The
consumer Worker therefore needs `nodejs_compat`, as the current app does. The
bundled `pg` has a conditional dynamic import of `cloudflare:sockets`; `pg`
chooses that implementation only when its runtime check sees Cloudflare and
uses `node:net` on Node.

Application configuration is still present because this is the whole current
Worker. `loadConfig` receives Worker bindings through the current wrapper, while
TanStack and `pg` also contain a few direct `process.env` reads. These are
current-app coupling, not requirements of Start SSR.

The Cron handler is also current-app coupling. It belongs in `@coffre/server`,
not `@coffre/ui`.

## Workers result

I ran the consumer with local Wrangler on port 3061. Wrangler followed the pnpm
symlink and started normally. It rebundled 73 JavaScript files from the prebuilt
package into one 3,078,744-byte development Worker, 586,454 bytes gzipped. The
bundle had one React production copy. The consumer itself has no React
dependency, so there was no second React instance.

Observed behavior:

- `GET /api/spike` returned 200 and
  `{"ok":true,"owner":"consumer","runtime":"worker"}`. This proves the
  outer Worker retained route ownership.
- `GET /login` returned 200 with a complete HTML login form. The heading and
  persona buttons were in the curl response, before a browser ran JavaScript.
- The consumer exposed its request nonce in a spike-only response header. The
  verifier matched that literal value against the CSP and all four SSR script
  tags. This proves the caller-supplied Start context survived the in-process
  package call.
- The repeatable verifier fetched all 13 JS/CSS asset URLs in the HTML and every
  WOFF2 URL in the stylesheet. All returned 200.
- Agent Browser recorded 200 for the document, stylesheet, all JavaScript
  chunks, and the Latin font subset used on the page. It reported no page
  errors or console errors.
- After hydration, `window.$_TSR` had been removed by Start. Clicking the
  React-controlled Dark button changed `data-theme` to `dark` and wrote
  `coffre-theme=dark` to local storage.

This covers the in-process call, Wrangler's second bundling pass, hashed dynamic
chunks, the compiled asset manifest, CSP context propagation, and assets below
a pnpm symlink.

The consumer's own Wrangler config does not use the generated config shipped in
the UI build. The generated file can be omitted from a real package.

## Node result

I ran `consumer/src/node.ts` on port 3062. It uses Node's global `Request` and
`Response`, converts the final response to a Node response, and serves
`dist/client` first.

The adapter buffers each response before writing it and reduces headers to a
plain object. It is evidence for runtime compatibility, not the production Node
adapter. A real `@coffre/server/node` adapter should preserve streaming and
multiple `Set-Cookie` headers.

The same verifier passed unchanged except for the expected runtime label:

```json
{"runtime":"node","apiOwner":"consumer","scriptsWithMatchingNonce":4,"assetsChecked":13}
```

Agent Browser also hydrated the Node response, loaded all required assets, and
handled the theme click with no browser error. Resource transfer sizes were
nonzero, including 303,284 bytes for the entry JavaScript, 56,658 bytes for the
stylesheet, and 73,220 bytes for the font used by the page.

`GET /readyz` reached the database-backed route on both runtimes and returned
the expected 503 because `coffre_spike_ssr` was not created. I did not test a
successful database query under Node. That is not needed for the target UI:
the final UI artifact should contain neither `pg` nor a database binding. Its
SSR reads should go through the injected `@coffre/client`.

The Cloudflare Vite build is not advertised upstream as a general Node target,
so this should remain a smoke-tested property rather than an assumption. With
the current dependency versions, the emitted UI machinery is based on Web
Requests and Responses and works in both places. A separate Node Start build
would add package size and release complexity without solving an observed
problem.

## Recommended `@coffre/ui` boundary

The package should export a UI-only factory, not an `ExportedHandler` copied
from the application Worker:

```ts
type UiRequestContext = {
  cspNonce: string;
  client: CoffreClient;
};

type Ui = {
  fetch(
    request: Request,
    options: { context: UiRequestContext },
  ): Promise<Response>;
};

export function createUi(options?: UiOptions): Ui;
```

`@coffre/server` should own the outer request:

1. Route `/api`, `/auth/*`, `/livez`, and `/readyz` before calling the UI.
2. Mint one nonce.
3. Construct the request-scoped `@coffre/client`.
4. Call `ui.fetch(request, { context: { cspNonce, client } })`.
5. Put the same nonce in the CSP response header.

The prototype and current app both prove the context route. Their outer Workers pass
`{ context: { cspNonce } }` to the Start handler, `router.tsx` reads it with
`getGlobalStartContext()`, and the spike observed the result on every rendered
script. In the final package, the router should obtain the request client from
the same Start context. Neither value should be global or cached between
requests.

The package should also publish `dist/client` and document one stable asset
path for Workers configuration. I would namespace the final URLs, for example
`/_coffre/assets/...`, rather than keep today's generic `/assets/...`. Otherwise
a consumer's own Vite output can collide with coffre's filenames or asset
policy. The emitted client directory must mirror that URL prefix.

The UI package should not export a scheduled handler, read environment
variables, know about Hyperdrive, or apply security headers. Those belong to
the server adapter. Keeping security headers outside the UI also lets the
server add the correct sign-in provider origins to `form-action`.

## SSR transport to `/api`

In the browser, `@coffre/client` should use its normal same-origin HTTP
transport. A call to `client.secrets.list(...)` becomes an HTTP request to
`/api/...`.

During SSR, `@coffre/server` should create a client whose transport resolves the
same `/api/...` URL but invokes the server's API `fetch` in process. It must copy
the page request's cookie into the internal Request so the API authenticates
the same visitor. If Cloudflare Access remains a supported identity mode, the
adapter must also preserve its authenticated request credential or pass the
already-authenticated request context through an internal boundary. It should
not forward arbitrary browser headers.

Conceptually:

```ts
const client = createClient({
  transport: inProcessTransport(async (path, init) => {
    const apiRequest = new Request(new URL(path, pageRequest.url), {
      ...init,
      headers: withVisitorCredential(init?.headers, pageRequest.headers),
    });
    return api.fetch(apiRequest, env, executionContext);
  }),
});

return ui.fetch(pageRequest, { context: { cspNonce: nonce, client } });
```

This preserves one API implementation and one authorization boundary. It also
avoids a loopback network request during SSR. The browser and server transports
must return identical client result types so loaders do not care which one ran.

## Costs and risks

The consumer cost of the recommended prebuilt approach is small: install one
package, add its client directory to `assets.directory`, enable the runtime
compatibility required by the server output, and forward page requests. The
consumer does not need Vite, TanStack Start, the React plugin, route generation,
or matching frontend dependency versions.

The main release risk is that a future Cloudflare Vite or TanStack Start update
changes the emitted runtime assumptions. Keep two package smoke tests: import
and render under local Wrangler, and import and render under Node. Each should
run the nonce and asset verifier from this spike.

Remote asset upload was not tested because the task forbids Cloudflare remote
operations. Local Wrangler did traverse the pnpm symlink. A release smoke test
can run `wrangler deploy --dry-run` in CI if project policy permits it, without
contacting an account.

The source-build fallback was not prototyped because direct import succeeded.
That fallback would be much heavier. Each consumer would inherit Vite,
`@tanstack/react-start`, the React plugin, a runtime adapter plugin, the route
generator, and compatible React versions. It would also rebuild roughly 2,500
server modules and 2,250 client modules instead of installing an already tested
artifact. It is worth keeping only as an escape hatch if future framework
output stops being portable.

## Commands and evidence

Every shell used Node 24.21.0 by prepending its nvm directory to `PATH`.

```sh
pnpm --dir apps/web build
pnpm install
pnpm --filter @coffre/ssr-ui-spike-consumer typecheck
pnpm --filter @coffre/ssr-ui-spike-consumer dev:worker
curl --include http://127.0.0.1:3061/api/spike
curl --include http://127.0.0.1:3061/login
pnpm --filter @coffre/ssr-ui-spike-consumer verify:worker

AGENT_BROWSER_SESSION=ssr-spike-worker agent-browser open http://127.0.0.1:3061/login
# Snapshot, page errors, console, network requests, and a hydrated theme click.

pnpm --filter @coffre/ssr-ui-spike-consumer dev:node
curl --include http://127.0.0.1:3062/api/spike
curl --head http://127.0.0.1:3062/login
pnpm --filter @coffre/ssr-ui-spike-consumer verify:node

AGENT_BROWSER_SESSION=ssr-spike-node agent-browser open http://127.0.0.1:3062/login
# Page errors, resource timing, CSP nonce, and a hydrated theme click.
```

Worker verifier result:

```json
{"runtime":"worker","apiOwner":"consumer","scriptsWithMatchingNonce":4,"assetsChecked":13}
```

Node verifier result:

```json
{"runtime":"node","apiOwner":"consumer","scriptsWithMatchingNonce":4,"assetsChecked":13}
```

I did not start or stop any shared service, did not touch the existing coffre
databases, did not create `coffre_spike_ssr`, and performed no remote
Cloudflare operation.
