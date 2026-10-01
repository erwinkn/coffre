# @coffre/cli

The `coffre` command: secrets in your shell, and a new deployment.

```sh
npx @coffre/cli init --workers my-coffre   # or --node
coffre login https://secrets.acme.example
coffre run market/prod -- node server.js
```

It bundles everything it runs, so it installs with no dependencies.

Part of [coffre](https://github.com/erwinkn/coffre), a secrets manager you
deploy as a small project of your own. Its eight `@coffre/*` packages are
released together, at one version. MIT licensed.
