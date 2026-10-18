# @coffre/client

coffre's API as typed function calls, generated from the server's routes,
with the API's types: `createClient({ … })`. The `coffre` CLI and the web
pages are built on it.

The published client has no dependency and runs on Node 20 or newer, and in
browsers and other runtimes with `fetch`. It is an ES module: `import` it, or
`require` it from CommonJS on Node 20.19 or newer and 22.12 or newer, where
`require` loads ES modules (before that, load it with `await import(…)`).
Developing coffre from its TypeScript sources requires Node 24.

Part of [coffre](https://github.com/erwinkn/coffre), a secrets manager you
deploy as a small project of your own. Its eight `@coffre/*` packages are
released together, at one version. MIT licensed.
