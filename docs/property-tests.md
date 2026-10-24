# Property tests

`pnpm test` includes the bounded Hegel properties under `node --test`.
`pnpm test:properties` runs just the properties that need no database: core's,
the CLI's and the server's pure ones (about 7 seconds).
`pnpm test:properties --long` runs 100 times as many generated cases (about 6 minutes).
`pnpm test:properties --long --seed=42` explores a different reproducible seed.
`pnpm test:properties:server` runs the database-backed ones (below), and
`pnpm test:properties:long` runs both sets long.

The default seed is 20261003. Each generated property's Node test name prints its seed.
Pass that exact number to `--seed` to replay it. Hegel prints the shrunk draws and
the original assertion on failure. Its example database is disabled, so an
old local failure cannot change what a seeded CI run explores. Budgets count
cases, not elapsed time. Key material is drawn by Hegel where an outcome
depends on it; where it cannot (the RSA and EC keys of the workload-token
properties, a pool made once a run, and `seal`'s data keys and IVs), it comes
from the host, and decides no outcome.

The audit target authenticates mixed-author chains with the real MAC and
hash code, signs and verifies random checkpoints with the real checkpoint
message and signature verifier, edits every stored field, and tests deletion,
duplication, swaps, truncation before a retained checkpoint, and signing with
the wrong author's key. Failure locations name the first broken retained
entry; a gap names the next entry that exposes it. A standalone valid prefix
is valid to core's chain verifier. These properties do not claim freshness
when the log and all its checkpoints are rolled back together.

The access target compares every permission across project and environment
places with an independent table transcribed from the README's role rules:
the instance roles inside their scopes, and the project roles of grants. It
also compares grant management, running the instance and making projects,
and that a scope written another way decides the same. Its boundary is
core's `Holdings`: the vault has already checked membership and filtered
expired grants. Service tokens hold the same grant permissions as people,
and no instance role.

The conversion target holds the vault's replacement of the grants on every
project of 0.4 (`convertEveryProjectGrants`) to an independent model of
what they gave: nobody ends up holding a permission they did not, at any
place, at any time, in a project made later included; and in the projects
there are now, they keep every permission they had, at any time, but what
the conversion names: a role it put on a project's environments instead,
on the project itself, and a role it says is lost.
Credential validity is checked before that boundary, not by core's `allows`.

## The shared domain

`scripts/properties/domain.ts` is Coffre's domain as Hegel generators, for
every package's properties: projects, environments, forks to three deep and
`@me` overlays, keys of each nature, references, a fork's removals, the role
tables as the README has them, a policy an Owner edited (roles, custom roles,
instance roles, protected environments), scopes, grants, personal tokens,
service tokens and trust bindings. It is an independent model, transcribed
from the README and docs/design, and imports nothing of Coffre's, so a test
that compares the two compares two readings of the rules. Ids within a world
never repeat, though Hegel shrinks each towards zeros.
`packages/core/test/domain-properties.test.ts` holds every world it makes to
the database's keys and checks (`packages/db/src/schema.ts`), so a world the
database would refuse fails there first.

## More targets

Each file names its model and its sources in its header.

- **Access rules under any policy** (`access-rules-properties.test.ts`): every
  permission at every place, under edited and custom roles, protected
  environments and credentials of any kept columns, against the model;
  protecting an environment, losing a grant or narrowing a scope never widens
  anything; a personal token never holds more than its person now, nor more
  than they held when they issued it, in the column the place uses now (R15);
  a service token, no more than its account now and its role at issue; a
  person who does not manage access gives a service account nothing they do
  not hold, nor issues a credential reaching past themselves; who owns a
  project, that they hold everything in it, and that only a service
  credential reads sensitive values (R16, R30, R32); role definitions.
- **Envelopes and keys** (`envelope-properties.test.ts`): round trips; any
  change to the IV, tag, ciphertext, wrapped key, its claimed key or version
  fails to open; a value opened under another project, environment, secret,
  owner or sensitivity fails, the ids at the value's own AAD and the owner and
  sensitivity at the wrap's; the AAD is injective; rotation; the KMS
  encryption context; sign-in's sealed values, expiry to the millisecond.
- **Parsers and exports** (`dotenv-properties.test.ts`,
  `packages/cli/test/export-properties.test.ts`): dotenv round trips any
  value; shell exports evaluated by sh, dash, bash and busybox give back each
  value byte for byte and run nothing (sh and bash required, dash and busybox
  where installed); `$GITHUB_ENV` and its masks as the
  runner parses them; a parse problem never carries a value; the key-name
  patterns all agree; `coffre.json` and instance resolution.
- **Workload tokens** (`workload-token-properties.test.ts`): a token is
  accepted exactly when an oracle written from docs/oidc.md and the JOSE RFCs
  accepts it, through alg confusion, kid games, embedded keys, respelled
  signatures and every time bound; uploaded key sets; binding claims; the
  Cloudflare Access verifier on a local JWKS.
- **SigV4 and the credential proxy** (`sigv4-properties.test.ts`,
  `credential-proxy-properties.test.ts`): the proxy's signer and presigner,
  and core's KMS signer, byte for byte against `@smithy/signature-v4`; the
  path an upstream is asked stays under the credential's base and `paths`
  whatever the encoding (`..;`, `%2e`, double encoding); redirects never
  followed or leaked; no CR, LF or NUL in a header; redaction the same
  however the body is split; private addresses in every spelling refused.
- **The Postgres tunnel** (`packages/server/test/tunnel-properties.test.ts`,
  `packages/cli/test/tunnel-properties.test.ts`): each real end, the Durable
  Object's `fromWebSocket` and the listener's `carry`, against a model of
  the other written from the design, over a simulated WebSocket whose
  schedule Hegel draws: every byte once and in order, nothing held past its
  bound, both ends finish, and a cheating peer gets its 1008 at the frame
  that cheats. Two files, as a server test may not import the CLI.
- **The workload gate** (`packages/server/test/gate-properties.test.ts`):
  a workload's gate
  ([workload-access.md](design/workload-access.md#52-the-gate-replay-nonces-live-counters))
  against a reference written from the design: random requests with and
  without a proof or counts, clock steps both ways, restarts, and for a
  Durable Object's gate its writes and evictions; every answer must be the
  reference's. The reference keeps every proof taken across restarts, so a
  gate that took one twice disagrees. A small ceiling lets sequences reach
  `overloaded`. It needs no database, so `pnpm test:properties` runs it.

## Database-backed properties

`pnpm test:properties:server` runs these on one random scratch database,
Postgres unless `COFFRE_TEST_ENGINE=sqlite`; `pnpm test` runs each on its
private clone too.

- **Operation sequences** (`operations-properties.test.ts`): below.
- **Forks** (`forks-properties.test.ts`): random worlds written as rows,
  around the app too (a parent archived or deleted under a live fork, a chain
  that loops or runs past three, a key with neither value nor reference),
  resolve to the same keys by name (`resolveKeys`), row by row
  (`inheritedRows`) and as read (`readableValues`), each from the nearest
  environment that holds or removed it.
- **Audit visibility** (`audit-visibility-properties.test.ts`): the log a
  caller pages through is exactly the entries about the places they read,
  both sides of a reference's, less a protected environment's their role
  leaves out, with no gaps or repeats and the hidden counts right.
- **Natures** (`natures-properties.test.ts`): a random world built through
  the API, then a random list of changes; after each, every session and
  credential reads every environment every way the API offers, and no value
  reaches anyone the rules forbid it to (R8, R15, R16, R20, R23, R24, R30,
  R32). Every value is a unique token, so a scan of each answer finds it
  wherever it is.
- **Request cost** (`request-cost.test.ts`): after any growth Hegel draws
  (writes elsewhere, other projects and forks, members, the reader's role
  flipped, protection, roles, references in, sensitivity, tokens), each hot
  request runs the same statements and reads the same rows. Postgres only.

## Native dependencies

Hegel 0.4.7 is an exact development dependency of core, server, the CLI and the
root, whose `scripts/properties/domain.ts` imports it. Tests load it under
`coffre:source`; shipped source and build entry points never import it.
No Vitest is used and install scripts stay disabled.

On Linux x64, Hegel loads `libhegel-linux-amd64.so` from the optional npm
package `@hegeldev/hegel-linux-x64` 0.4.7. It is libhegel 0.42.4, copied during
upstream packaging from the
[hegel-rust release](https://github.com/hegeldev/hegel-rust/releases/tag/libhegel-v0.42.4).
The installed library matches that release's SHA-256 sidecar:
`60fa1b48f83def125d0d6904bf4351c0022572b52be252ded756aab9e0990682`.

The npm registry publishes SLSA v1 provenance for both the JS package and
its platform package. The
[platform attestation](https://registry.npmjs.org/-/npm/v1/attestations/@hegeldev%2fhegel-linux-x64@0.4.7)
attributes packaging to `hegeldev/hegel-typescript` commit
`37b158df1e8455c8054db108f5c28f87ab827a83`, through its GitHub Actions CI workflow.
This identifies the npm packaging run, not an independent attestation of the
Rust binary's build. We inspected the published attestation payload and
compared the binary checksum; we did not independently verify its signatures
or reproduce the Rust build.

The lockfile resolves Hegel's FFI dependency to Koffi 3.3.1. Koffi declares
an install script, but its optional `@koromix/koffi-linux-x64` package supplies
the prebuilt Node addon. The native tests run with `ignoreScripts: true`,
without running that script or compiling Koffi.

## Server operation sequences

`pnpm test:properties:server` runs the real server properties against its own
random scratch Postgres database: the operation sequences below, then the
other database-backed files above. `pnpm test:properties:server --long --seed=42`
runs 40 generated sequences instead of the normal four, and ten times as many
cases of the others. A normal run takes about a minute on Postgres and half
that on SQLite; a long one, about five minutes and two. Set the existing
`COFFRE_TEST_ENGINE=sqlite` to run that command on SQLite. Normal `pnpm test`
and `pnpm test:sqlite` include the file with their usual private database
clone or copy. The standalone command removes its scratch data on exit.

The operation list is drawn before execution, so Hegel can shrink its length
and parameters: four to fourteen operations. It includes invitations, member
removal, service token issue and revocation, writes and reads, and grants and
revocations on the project and on one environment, and refused on every
project (`*`, and `*` on one slug), which no grant is on now. Places change
too: environments are made, renamed, archived, restored and deleted, and
the project is archived, restored, deleted and made again under its old
slug. `retire-env` and `retire-project` archive and then delete in one
step: a deletion needs both, and two independent draws rarely line up.
The root sets ada's instance role: an Admin, who grants and sees every
member's grants and still reads a secret only with a grant of her own; a
Developer everywhere, or scoped to one environment slug, who reads and writes
it in every project; or a member again. Removed and brought back, she is a
member. A service account is refused any role.
Two fixed scenarios cover every operation, removal followed by
re-admission, a grant on a slug before any environment has it, renames
across slugs, and slugs used again after a deletion.

After every step, the model checks that:

- old credentials stay refused;
- a read is allowed exactly when the model's grants cover the place, with
  an environment's grant following it through a rename and a `*/<slug>`
  grant following the slug;
- a granted reader gets the current value, and an allowed read has exactly
  one audit entry, while a refused read releases nothing and logs none;
- the root's lists show exactly the live project and environments,
  archived ones included, and no tombstone;
- every deleted place stays unreachable: its tombstone's path is refused
  for a grant and a read, and at the vault, a grant on its ids and an
  unwrap of each version it had are refused as `deleted`;
- the real app/vault log verifies.

Read requests use the real sign-in verifier and API, including the
credential's generation.

The model has one person and one service, one project and the environment
slugs `dev`, `prod` and `qa`, with one secret in each environment. Viewer
and developer grants can be at any of the four scopes. This is a bounded
state model, not every API route or every role: core's properties cover
the complete role/permission table. Deployment keys are fixed test keys;
product-generated IDs and data keys do not decide the modeled outcomes.
Clock-sensitive expiry is outside these sequences.

Removing an absent member or revoking a revoked token is refused with 404,
without changing members, grants, credentials or identities, or adding an
allowed audit entry. Declarative `access.set` succeeds when the requested
role is already held, or when clearing an absent grant. That no-op changes
no state and adds no audit entry claiming a grant changed. The model follows
these semantics after PM review of the shrunk repeated-removal case.

Key rotation is omitted because the API fixture offers no rotation
operation: its vault keys are deployment configuration. The existing key
rotation tests remain in the full suite.

## Every night

`.github/workflows/properties.yml` runs `pnpm test:properties --long` and
`pnpm test:properties:server --long`, on Postgres and on SQLite, each night
on a fresh seed, and on demand with a seed to replay (Actions, Nightly
properties, Run workflow). The seed is printed first as a notice, and a
failure ends with an error naming it and the command that replays it
locally; Hegel's shrunk operations are in the step's log.
