# @coffre/cli

The `coffre` command: secrets in your shell, and a new deployment.

The published CLI runs on Node 20 or newer. Developing coffre from its
TypeScript sources and running a deployment require Node 24.

```sh
npx @coffre/cli init --workers my-coffre   # or --node
npx @coffre/cli setup                      # its database, keys and, on Workers, Cloudflare
coffre login https://secrets.acme.example
coffre run market/prod -- node server.js
coffre verify                              # the instance from outside, the keys you keep, or the log
```

It bundles everything it runs, so it installs with no dependencies:
`setup` brings its own Postgres driver and coffre's migrations, at the
CLI's version.

Part of [coffre](https://github.com/erwinkn/coffre), a secrets manager you
deploy as a small project of your own. Its eight `@coffre/*` packages are
released together, at one version. MIT licensed.
