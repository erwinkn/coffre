# Rotation (exploration, W109)

A design sketch, not a plan of record. Prototype:
`packages/server/src/rotation/` and `packages/server/test/rotation.test.ts`,
pure code against fakes: no table, no route, nothing wired in.

## Where coffre is today (0.6.0)

- Each value shows its age, and a quiet "Rotate" tag after
  `rotateAfterDays` (one number for the whole instance, in deployment code).
  `coffre list --stale` and `--older-than 90d` filter on it.
- Offboarding already lists the values a person saw that are still current
  ([offboarding.md](../offboarding.md)): a second reason a value is due.
- Writing a new value is the only way to rotate. Nobody is told, and nothing
  records that a write was a rotation.

## Three levels

**(a) Reminders and owners.** A per-key policy, stored as data (keyed by
the secret's ID, so a rename keeps it), set from the UI or the CLI, with the
instance's `rotateAfterDays` as the default:

```
coffre rotation set market/prod/STRIPE_SECRET_KEY --every 90d --owner user:ada@acme.example
```

A value is due when it is older than its policy, or when someone who saw it
left. One "Due" list across the instance shows both reasons. Telling people
is a deployment hook, as config is code:
`createCoffre({ rotation: { notify: async (due) => … } })`, called from the
scheduled job once a day with what became due; the deployment posts it to
Slack or sends mail. The Action can warn on a due key
(`::warning::market/prod/STRIPE_SECRET_KEY is 412 days old`) without failing
the deploy.

**(b) Guided rotation.** A "Rotate" button on the key. Two kinds of key:

- Coffre makes the value (a webhook signing secret between two of your
  services, a session secret, an AES key): the policy remembers the
  generator, so rotating is one click, and coffre runs the overlap below.
- A provider makes it (Stripe, a GitHub App key): coffre shows a checklist,
  with a link to where it is made: make a new one there, paste it here, wait
  for the deploys, revoke the old one there, tick "old one revoked". Stripe
  and GitHub App private keys can only be made in their dashboards, so this
  is as far as coffre can go for them.

Each rotation is a record: who started it, the old and new versions, its
phase, and when it ended. A rollback to a retired value warns first.

**(c) Automatic rotation.** A provider plugin makes the new credential,
coffre stores it, waits for its consumers, then revokes the old one. Of
the examples, three have an API for it:

| Provider | Make | Overlap | Revoke | Notes |
|---|---|---|---|---|
| AWS IAM access key | `CreateAccessKey` | two keys per user | `DeleteAccessKey` | `GetAccessKeyLastUsed` says when the old one is idle |
| Cloudflare API token | create a token | both live | delete it | needs "API Tokens Write"; T91's token lacks it (error 9109). "Roll" kills the old value at once, so coffre would create and delete instead |
| Postgres password | `ALTER ROLE … PASSWORD` | none: one password per login | | two logins taken in turn (`app_a`, `app_b`), as AWS Secrets Manager does |
| Stripe key | dashboard only | Stripe's own, up to its roll window | Stripe's | API only for approved Stripe Apps |
| GitHub App private key | dashboard only | several keys at once | dashboard | the root that installation tokens are minted from |

## Consumers during an overlap

Two kinds of overlap, which look the same from far away:

- **At the provider** (AWS, Cloudflare): both keys work; consumers need
  only the current one. Coffre just waits before revoking the old one.
  `export`, `run` and the Action change nothing.
- **At the consumer** (a webhook secret your service A signs with and B
  verifies): the verifier must accept both. Coffre exports extra names:

```
staged    WEBHOOK_SECRET=v4   WEBHOOK_SECRET_NEXT=v5        verifiers learn v5
promoted  WEBHOOK_SECRET=v5   WEBHOOK_SECRET_PREVIOUS=v4    signers switch
retired   WEBHOOK_SECRET=v5                                 v4 forgotten
```

A signer uses `WEBHOOK_SECRET`; a verifier accepts each of the three that
is set. Three phases, not two: with two, a signer that deploys first signs
with v5 while a verifier not yet deployed knows only v4. The test
"the overlap" checks this. Two phases do when signer and verifier deploy
together, or when the signer is Stripe, which signs with both secrets while
a rolled one expires.

The phases are pointers to versions the secret already has; no value is
copied. A reference reads its source's phase live, as it reads its current
version. The extra names are not keys: `missing` ignores them, and a real
key named `WEBHOOK_SECRET_PREVIOUS` stops a policy with an overlap.

**When have consumers moved?** The log records the version of every read.
Who read v4 in the last 30 days and has not read v5 since is waiting
(`laggards`): "waiting on service:api, last read v4 on Oct 2". Where the
provider says when a key was last used (AWS), coffre also waits for the old
one to go idle. A minimum overlap applies either way.

## Coffre's own keys

| Key | Rotates today | Missing |
|---|---|---|
| Vault key, local | yes: `kek` + `previousKeks`, a `key.rotate` entry ([keys.md](../keys.md)) | rewrap, so the old key stops opening data; and a verify-only form, since the old key stays configured for good to verify the log signed under keys derived from it |
| Vault key, KMS | AWS rotates the material yearly | rewrap, to move to another key |
| Data keys | one per version, so every new value has a fresh one | nothing |
| KMS `signingKey` | no | a key ring, verify-only previous keys |
| App key (`auditChainKey`) | no: it MACs the app's log entries and sign-in rows | the vault's scheme, mirrored: previous keys verify-only, sign-in rows MACed again under the new key, an app `key.rotate` |
| Service tokens | by hand: issue a second, revoke the first; 90 days unless told | a reminder before expiry, and `coffre tokens rotate`, which revokes the old token once its `lastUsedAt` shows it idle |
| Database logins | `coffre setup --reset-passwords` | one password per login, so a brief gap |
| Sign-in client secrets, GitHub App key, KMS credentials | in the platform's secret store, outside coffre | reminders only: coffre cannot hold its own configuration |

## Where the scheduler runs

The scheduled job already runs every five minutes on both platforms
(Workers' Cron trigger, Node's `schedule()`), for the heartbeat. A rotation
is a row it advances a step per beat:

```
issue → overlap → revoke → done
```

No step holds a transaction across a provider or vault call. The new value
lives only in memory between the provider's answer and its store, so making
and storing it is one step. Two halfway cases:

- **The provider made a key, coffre never stored it** (the answer was lost,
  or the write failed): the key is an orphan, its value lost. Each key coffre
  makes is named `coffre/<rotation id>/<attempt>`; the next attempt lists the
  provider's keys under that name and revokes them before making another.
- **The provider revoked the old key, coffre never recorded it**: the next
  beat revokes again, and "already gone" counts as revoked.

The old key is revoked only once the new one is stored as current, so a
read of coffre always returns a working key. Two beats on one row compare
and set it; the loser revokes what it made. The prototype's tests fault
every provider and store call, once at each position and randomly 300
times, and check that every run ends with exactly one live key, the stored
one, and that the consumer never held a dead key.

Providers are code the deployment passes in; policies are data. Neither
needs an environment variable.

## Audit and permissions

- Setting a policy, starting or finishing a rotation by hand: write on the
  environment. A policy that uses a root credential: read on that secret too.
- The scheduled job acts as a service account (`service:rotator`, or one per
  policy), with ordinary grants: write where it rotates, read on the root
  credentials. The vault checks it like anyone else, and offboarding it stops
  rotation.
- Entries: `rotation.policy`, `rotation.start`, the `secret.write` of the
  new value naming the rotation, `credential.issue` and `credential.revoke`
  with the provider's key ID (never a value), `rotation.done`, and
  `rotation.failed` with the step and the provider's error.

## What rotation shares with dynamic secrets

`CredentialProvider` (`packages/server/src/rotation/provider.ts`): `issue`,
`revoke`, `list` by name, `lastUsed`. A dynamic secret calls `issue` per job
with an expiry and `revoke` at its end; rotation calls them for a long-lived
key. Both need a root credential to call the provider with, kept in coffre.
The two meet there: the root itself is a key with a rotation policy (a
Cloudflare token that may create tokens can make its own successor; a GitHub
App private key can only be rotated by hand, guided).
