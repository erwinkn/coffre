# Architecture and decisions

## Trust boundaries

One installation is one company. Project/environment scopes do not imply SaaS
customer isolation. Cloudflare and privileged vault deployers remain trusted.
The web Worker has only a vault binding. It forwards the original Access JWT or
native bearer credential; an asserted actorId is never accepted as identity.
The vault has the only operational database binding and key-provider configuration.

A standalone key service is optional. Integrated mode is simpler. Separate mode
is useful only with independently controlled deployment credentials and journal
custody. Its journal records DEK releases, not every downstream use of retained
DEKs or plaintext. Same-account service separation is not a guarantee against an
account administrator. The service is not advertised as an HSM.

## Cryptography

Each secret version receives a fresh random 256-bit DEK. AES-256-GCM uses random
96-bit nonces. Both the encrypted payload and its wrapped DEK authenticate stable
instance/project/environment/secret/version identifiers; the wrap additionally
binds its key reference. Renames do not alter cryptographic context.
Root providers are selected explicitly. Historical key references must remain
available. `rewrap` changes root-key protection without changing payload bytes;
it does not rotate an upstream database password. Unknown keys fail closed.
The Scaleway adapter uses Encrypt/Decrypt with associated_data; the ML-KEM Wrap
endpoint is not interchangeable. No external KMS was contacted in local tests.

## Atomic storage contract

Core code evaluates one consistent authorization snapshot and builds a commit plan.
The adapter conditionally advances a global revision/head and commits mutations,
new encrypted versions, audit rows, outbox entries, and a mutation receipt together.
A stale revision aborts the entire transaction; core retries from a fresh snapshot.
Thus permission revocation during a KMS operation invalidates that attempt before
plaintext is returned. KMS calls occur outside the short database transaction.

D1 uses a guarded batch with a named CHECK constraint to turn a failed compare-and-
swap into a real rollback, rather than accepting a zero-row UPDATE. PostgreSQL and
MySQL use interactive transactions. PostgreSQL's restricted runtime role can enforce
append-only audit privileges; D1 cannot. MySQL's capability is conservatively false
until its privilege model has a dedicated certification test.

The initial adapter loads all metadata and grants, but only necessary ciphertext
versions and paginated audit rows. The global head serializes audit-producing
operations. This is an intentional internal-team baseline, not a high-volume
multi-tenant design. Load testing, targeted metadata queries, and segmented journals
are future work, not hidden guarantees of this release.

## Audit semantics

No value response before audit commit. Server-side decrypt may occur before commit;
it must not escape on failure. A read event means authorized release, not proof of
human observation. Copying in a browser cannot be proven from an HTTP response.
Bulk exports create one event per value, linked by requestId (100-value limit).
Denials are recorded for authenticated requests. Invalid authentication is refused
before database operations; operational logs must be monitored separately.

Events are canonicalized and chained with sequence/head state committed atomically.
Sequence rollback does not leave gaps. CLI verification compares the complete chain
to a captured head. Independent retained checkpoints are still necessary to detect
wholesale rewrites or history truncation by a privileged operator.

Archive copies are idempotent, conditionally created, and acknowledged only after
success. An archive outage leaves pending work. It does not undo the already-
committed journal. Archive lag monitoring, object retention, and independent custody
must be configured by the operator; R2 in the same account is not inherently an
independent immutable evidence store.

## Portability

One logical model, adapter-specific migrations. Hyperdrive is a connection source,
not a storage adapter. Disable its query cache. Database switching is an offline
migration preserving IDs, envelope key references and original canonical audit
records; changing STORAGE is not a data migration. No automatic database failover
is implemented.
