# Keys

Every value coffre stores is encrypted under a data key of its own, and the
vault wraps each data key with a key-encryption key, the KEK. The database
holds the ciphertext and the wrapped data key, never a key that opens them.
The KEK is one of two things:

| | Where the KEK lives | Who can see a key being used |
| --- | --- | --- |
| A local key | 32 bytes in the vault's configuration (a Worker secret) | the vault's entries in the shared audit log |
| AWS KMS | inside KMS, which it never leaves | vault entries in the shared log, and CloudTrail |

## A local key

The default, and what `coffre init` sets up:

```ts
kek: { id: env.KEK_ID, key: env.KEK },
```

It costs nothing and adds no latency. But whoever holds the Worker secret
and a copy of the database holds every value, and nothing outside coffre
records the use of either. Keep an offline copy
([deploy.md](deploy.md#on-workers)): without it, nothing can be read again.

## AWS KMS

```ts
import { awsKms, postgres, vault } from '@coffre/vault/cloudflare';

export default vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE),
  kek: awsKms({
    keyArn: env.KMS_KEY_ARN, // arn:aws:kms:eu-west-3:123456789012:key/…
    credentials: { accessKeyId: env.AWS_ACCESS_KEY_ID, secretAccessKey: env.AWS_SECRET_ACCESS_KEY },
  }),
  rootAdmins: env.ROOT_ADMINS.split(','),
  signingKey: env.SIGNING_KEY,
}));
```

The vault sends each fresh data key to KMS to be encrypted, and each wrapped
one to be decrypted when someone may read it. Each call carries the secret's
ids as the *encryption context*: KMS binds the ciphertext to them, so a
wrapped key moved to another secret's row does not decrypt, and CloudTrail
records them with every call. A read in coffre then shows up twice, in
places run by different people:

```
vault log    unwrap  allow  user:ada@acme.example  market/prod/DATABASE_URL  secretId 5c0e…
CloudTrail   Decrypt        coffre-vault (IAM user)   encryptionContext { "coffre:project": "8f2a…",
                                                        "coffre:environment": "d41b…",
                                                        "coffre:secret": "5c0e…" }
```

For a key KMS wrapped, one without the other means something read around
coffre, or a log was edited. The vault asks KMS only for a call its rules
allow, so a refused read appears in its log and never in CloudTrail.

**Setting it up.**

1. Create a symmetric key in the region nearest the vault, and turn on
   rotation:
   ```sh
   aws kms create-key --description coffre --query KeyMetadata.Arn
   aws kms enable-key-rotation --key-id <arn>
   ```
2. Create an IAM user for the vault with this policy and nothing else, and
   an access key for it:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": ["kms:Encrypt", "kms:Decrypt"],
       "Resource": "arn:aws:kms:eu-west-3:123456789012:key/…"
     }]
   }
   ```
3. Give the vault Worker the ARN as a var, and the access key as secrets:
   ```sh
   pnpm exec wrangler secret put AWS_ACCESS_KEY_ID -c vault/wrangler.jsonc
   pnpm exec wrangler secret put AWS_SECRET_ACCESS_KEY -c vault/wrangler.jsonc
   ```

The ARN is required: a bare key id does not say which region to call, and
an alias can later name another key while every row records the one it was
wrapped with. On Node, `credentials` may also be a function, asked before
each call. An AWS SDK credential provider is one, e.g.
`fromNodeProviderChain()` from `@aws-sdk/credential-providers` for an
instance role.

**What it changes.** The access key still opens everything, together with a
copy of the database, as a local key would. What you gain: every use is in
CloudTrail, the access key can be revoked in IAM at once without
re-encrypting anything, and the key material itself cannot be copied out.

**Cost and speed.** Each data key opened is one Decrypt, and each value
written one Encrypt. AWS charges about $1 a month per key and $0.03 per
10,000 calls. The vault handles one call at a time and runs up to eight KMS
requests of it at once, so a `coffre run` of 50 secrets is 50 Decrypts in
about seven round trips. On Workers, each is a subrequest: the Free plan
allows 50 per invocation, so an environment larger than that cannot be read
in one call there. The Paid plan allows 10,000.

**When KMS fails.** A throttled, failed or timed-out request (5 seconds)
is retried twice. If it still fails, or KMS refuses coffre's credentials,
or the key is disabled, the call fails: the API answers 500, the server log
names the KMS error, and the vault logs nothing, since nothing was decided.
A wrapped key that KMS will not decrypt for this secret is refused as
`bad_claim`, as with a local key.

**Rotation.** KMS rotates the key material once a year under the same ARN,
and keeps decrypting what older material wrapped. coffre has nothing to do.
To move to another key, make it `kek` and put the old one in `previousKeks`.

## Moving from a local key

```ts
kek: awsKms({ keyArn: env.KMS_KEY_ARN, credentials }),
previousKeks: [{ id: env.KEK_ID, key: env.KEK }],
```

New versions are wrapped by KMS from then on. Versions written before still
open with the local key, which must stay configured and escrowed until a
rewrap moves them to KMS. That command does not exist yet
([roadmap](roadmap.md)). Until then, the local key keeps opening everything
written before the switch, without CloudTrail.

## A KEK service of your own

`kek` takes any `KekProvider`, so another KMS (Google Cloud's, Vault
Transit's) takes about as much code as `aws-kms.ts` in `@coffre/core`:

```ts
import { KekUnavailableError, type KekProvider } from '@coffre/vault/cloudflare';

const transit: KekProvider = {
  provider: 'vault-transit', // with keyId, recorded on every row it wraps
  keyId: 'coffre',
  keyVersion: '1',
  async wrap(dek, ctx) {
    // Encrypt `dek` bound to `ctx`; return { kekProvider, kekId, kekVersion, bytes }.
  },
  async unwrap(wrapped, ctx) {
    // Decrypt `wrapped.bytes` bound to `ctx`; throw new KekUnavailableError(…)
    // when the service cannot answer.
  },
};
```

`ctx` is the secret's `{ projectId, environmentId, secretId }`. Bind it to
the ciphertext, so that a wrapped key presented as another secret's fails to
unwrap. `unwrap` throws `KekUnavailableError` when the service cannot answer,
and any other error when the wrapped key does not open: the vault fails the
call on the first and refuses the second.

Scaleway's Key Manager would fit the same way, but its Audit Trail logs no
Encrypt or Decrypt, only changes to keys, so it would bring no second record.
