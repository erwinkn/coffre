# Passkeys: a second factor at sign-in, and a fresh check for risky acts (T176)

Written on 2026-10-31, phase 1 of T176: the design and a mock of its screens
([passkeys-mock/index.html](passkeys-mock/index.html)). Nothing here is built
yet. The code comes after 0.15 ships, for 0.15.x or 0.16, and waits for the
sign-in work in flight (#436, T171), since it splits the sign-in callback.

Erwin's decisions, from a team request on 2026-10-31:

- Passkeys only: WebAuthn, platform and synced passkeys and security keys. No
  TOTP, no SMS.
- A passkey is a second factor, held by coffre, on top of the sign-in
  provider (GitHub, Google, Entra, any OIDC). Never a sign-in of its own:
  removing someone at the provider still cuts them off.
- The deployment's config sets the policy, `off`, `optional` or `required`,
  and coffre's default is `optional`.
- A fresh check, a passkey touch within the last five minutes, guards risky
  acts: role changes, Owner promotion and demotion, issuing service
  credentials. Reading a value is not one. Reads in a protected environment
  may be, but only with one check covering many reads.
- `coffre login` is approved in a browser, so the terminal inherits that
  browser's factor.

## In one page

| | `off` | `optional` (default) | `required` |
|---|---|---|---|
| Sign-in, no passkey yet | provider only | provider only, then a prompt to add one | provider, then add one before any session exists |
| Sign-in, has a passkey | provider only | provider + passkey | provider + passkey |
| Changing access, issuing service credentials | as today | a touch in the last 5 minutes; no passkey yet: add one first | a touch in the last 5 minutes |
| Approving a terminal or an MCP client, linking an account, managing passkeys | as today | a touch, if you have a passkey | a touch |
| Reading values | as today | as today | as today |
| Reading a protected environment's values, with `protectedReveals` | as today | a touch in the last 5 minutes | a touch in the last 5 minutes |
| `/use`, CI and workload sign-in, services | untouched | untouched | untouched |

The pieces:

- **One new table**, `passkeys`, and two nullable columns on `credentials`
  (`passkey_id`, `confirmed_at`) and one on `device_authorizations`
  (`passkey_id`). All additive: one migration per engine.
- **Two new sign-in routes**, `GET` and `POST /auth/passkey`, between the
  provider's callback and the session. Until the passkey answers, coffre
  writes nothing: what the provider vouched for waits in a sealed cookie,
  as `PendingSignin` does today.
- **Five API routes**: `GET`, `POST`, `PATCH` and `DELETE
  /api/members/:member/passkeys[/:id]`, and `POST /api/passkeys/checks`.
- **A table typed over the route table**, `FRESH_ROUTES`, like
  `PERSONAL_TOKEN_ROUTES`: every route says whether it needs a fresh check,
  so a new route fails the typecheck until it says.
- **The app enforces it, the vault does not** (section 8). The vault could
  verify passkey signatures itself later, for Owner-level acts, which would
  close the gap `architecture.md` names under "What the vault stops".
- **A verifier of our own**, about 300 lines in `@coffre/core/identity`,
  over WebCrypto, rather than `@simplewebauthn/server` (section 9).

## 1. What it stops, and what it does not

The cast for every example below: Ada is an Owner, `admin@acme.example`;
Bob is a Developer, `bob@acme.example`; coffre runs at
`https://secrets.acme.example` and signs people in with GitHub.

**A stolen provider account.** Someone phishes Bob's GitHub password and
session. Today they sign in to coffre as Bob. With a passkey, they pass
GitHub, land on "Confirm it's you", and stop: coffre wrote nothing, and
their browser holds only a sealed cookie that expires in five minutes.

**A real-time phishing proxy.** An attacker's `secrets-acme.example` relays
Bob's GitHub sign-in and asks for Bob's passkey. The browser refuses: a
passkey for `secrets.acme.example` answers only that origin. This is what
TOTP cannot give, and why passkeys only.

**A stolen session cookie.** Malware lifts Ada's cookie and replays it from
elsewhere. It can read what Ada reads, as today. It cannot promote itself
an Owner, issue a service token, approve a terminal or connect an MCP
client, each of which would outlive the cookie: those need a touch within
five minutes, which the thief cannot make.

**What it does not stop:**

- **The first passkey is trust on first use.** Under `required`, whoever
  passes the provider first for Bob adds the passkey. Under `optional`, a
  person who has none yet is as strong as their provider account until they
  add one. The first passkey needs a sign-in from the last ten minutes,
  which narrows a stolen cookie's chance to add one (section 3.3).
- **An app fully taken over.** It can skip its own checks. The vault does
  not see passkeys in this design (section 8).
- **A cookie stolen inside a fresh window.** A thief who takes Ada's cookie
  in the five minutes after Ada's touch gets the rest of that window. The
  window is the price of not touching per act.
- **Reads.** Revealing a value needs no passkey (Erwin's call), unless the
  deployment turns on `protectedReveals` for protected environments.
- **Cloudflare Access.** Behind Access, coffre has no session of its own;
  passkeys are a `signin()` option (section 12).

## 2. The policy

Config is code. Passkeys are an option of `signin()`, beside `providers`:

```ts
auth: signin({
  providers: [github({ app, organization: 'acme' })],
  passkeys: 'required', // 'off' | 'optional' (default) | 'required'
}),
```

or, with the two settings a deployment may need:

```ts
passkeys: {
  policy: 'required',
  // The WebAuthn relying party: publicUrl's host unless set, or a parent of it (section 7.1).
  rpId: 'acme.example',
  // Reading a protected environment's values takes a fresh check too (section 4.3).
  protectedReveals: true,
},
```

### Does "required for Owners" fall out?

Mostly, yes, and I propose no fourth mode. Under `optional`, everything that
changes access or issues a service credential needs a fresh check, and a
fresh check needs a passkey. So the first time Ada changes a role, coffre
asks Ada to add a passkey, then to touch it, in one dialog. From then on Ada
holds a passkey, so Ada's sign-ins need it too. In practice, everyone who
manages access (Owners, project Owners, Access managers) ends up with a
passkey, and people who only read and write secrets never have to.

The gap against a true "Owners must have one" mode: an Owner who never
changed anything since the upgrade has no passkey yet, so an attacker with
that Owner's GitHub account signs in, adds their own passkey at the first
risky act, and proceeds. A `required: 'owners'` mode would close that by
making Owners add one at their next sign-in. It costs a fourth value and a
rule keyed on role at sign-in. Open question 2.

## 3. The flows

### 3.1 Signing in with a passkey

Ada has two passkeys, "YubiKey 5C" and "iCloud Keychain".

1. `/login` → Continue with GitHub → GitHub → `GET /auth/callback/github`,
   as today.
2. The callback verifies GitHub's answer, then reads, in one statement, the
   identity, its member and that member's live passkeys (today's
   `findIdentity`, joined). Ada has passkeys, so no session yet. It clears
   the provider's pending cookie and sets another, `__Host-coffre_passkey`,
   sealed like `PendingSignin` and five minutes long:

   ```ts
   type PendingFactor = {
     purpose: 'signin' | 'enroll';
     account: SignedInAccount;      // what GitHub vouched for: provider, subject, emails, name
     principal: string;             // 'user:admin@acme.example'
     generation: number;
     next: string;                  // where to land
     challenge: string;             // 32 random bytes, base64url
     issuedAt: number;              // ms; also the replay guard (section 7.3)
     allow: { id: string; transports: string[] }[]; // the person's live passkeys, at most 10
   };
   ```

   and redirects to `/auth/passkey`.
3. The page, "Confirm it's you", renders from the cookie (no query), and its
   button calls `navigator.credentials.get` with that challenge, `rpId:
   'secrets.acme.example'`, `allowCredentials` from `allow`, and
   `userVerification: 'required'`. Ada touches the YubiKey.
4. `POST /auth/passkey` with the assertion, a browser post held to the
   same origin as every other. coffre opens the cookie, checks
   the assertion (section 7), moves the passkey's counter and replay mark in
   one conditional statement, and then runs today's `completeSignin` from
   the cookie's `account`, which re-reads and re-checks everything it
   decides on. The session it issues carries `passkey_id` = the YubiKey and
   `confirmed_at` = now. The cookie is cleared, the session cookie set, and
   Ada lands on `next`.

The cookie carries what GitHub vouched for and nothing coffre decided.
Someone who passed GitHub but not the passkey leaves no row behind, and an
unauthenticated visitor makes coffre write nothing, as today.

The page also says what to do without the passkey: "Lost your passkeys? An
Owner can reset them" (section 3.7). There is no fallback that skips it.

### 3.2 The first sign-in under `required`

Bob was invited; this is Bob's first sign-in. The callback finds the invited
member and no passkey, so the cookie's `purpose` is `enroll` and the page
says "Add a passkey to finish signing in". Its button calls
`navigator.credentials.create`:

```ts
{
  rp: { id: 'secrets.acme.example', name: 'Acme secrets' },  // the sign-in page's title
  user: { id: handle, name: 'bob@acme.example', displayName: 'Bob' },
  challenge,
  pubKeyCredParams: [{ type: 'public-key', alg: -8 }, { alg: -7 }, { alg: -257 }], // Ed25519, ES256, RS256
  authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
  attestation: 'none',
  excludeCredentials: [],          // the person's live passkeys, when adding a second one
}
```

`POST /auth/passkey` with the attestation does, in one transaction with
its audit entries: link the GitHub account (today's first-sign-in path),
insert the passkey, issue the session confirmed by it. Entries:
`account.link`, `passkey.add`, `sign_in`.

`user.id` is no secret and no email: 16 bytes of HKDF over the member and
generation, derived each time and never stored. It stays the same across a
person's passkeys, so a keychain that already holds one for Bob replaces it
instead of keeping two.

### 3.3 `optional`: the prompt

Bob has no passkey and the policy is `optional`. Bob signs in with GitHub
alone, as today, and the Projects page shows a notice: "Add a passkey.
Signing in will then take GitHub and a touch of your passkey, so a stolen
GitHub account is not enough." Add passkey, or Not now, which hides it in
this browser for 30 days. Account → Passkeys has the same button.

Adding the first passkey needs a session signed in within the last ten
minutes; otherwise "Sign in again to add your first passkey". A stolen
cookie is rarely that young, and adding a passkey to someone else's account
is the one way a cookie thief could make their access outlive the cookie.

Adding a first passkey changes three things for Bob:

- this session is confirmed by it (`passkey_id`, `confirmed_at`);
- Bob's other browser and CLI sessions, which no passkey confirmed, are
  signed out (one statement, today's revocation by principal and kind), so
  "has a passkey" means every live session of Bob's had one; and
- Bob's next sign-in asks for it.

### 3.4 A fresh check in the browser

Ada promotes Bob to Owner at 10:02. Ada's session was confirmed at 08:15, at
sign-in.

1. Users → Bob → Change global role → Owner → Save. The page knows from
   `GET /api/me` that the session is confirmed until 08:20, so before it
   sends anything, it opens "Confirm it's you" with what Ada is about to
   do: "Make bob@acme.example an Owner".
2. Use passkey → `POST /api/passkeys/checks {}` answers the request options
   and a sealed state bound to the session's credential; Ada touches the YubiKey;
   `POST /api/passkeys/checks { state, assertion }` checks it and sets the
   session's `confirmed_at` to 10:02.
3. The page sends the change, `PATCH /api/access/user:bob@acme.example`. The
   router finds the route in `FRESH_ROUTES`, finds the session confirmed
   within five minutes, and runs it. The `access.set` entry names the
   passkey and when it confirmed.
4. At 10:05 Ada issues a service token for `ci-deploy`. No prompt: still
   inside the window. At 10:09 Ada edits a role: prompt again.

The header shows a quiet "Confirmed · 3 min" chip while a window is open,
so the second act does not surprise anyone.

If the page did not know (the window ended between the check and the
send), the API answers `403 fresh_check_required`, and the page opens the
same dialog and resends once.

If Ada had no passkey under `optional`, step 1's dialog would be "Add a
passkey to change roles": one `create`, which also confirms the session,
then the change goes. The ten-minute rule of section 3.3 holds here too: in
an older session the dialog says "Sign in again to add your first passkey".

### 3.5 The CLI

**Signing in.** `coffre login` stays a device login. The approval page
needs a touch of its own for anyone with a passkey, not the window: the
terminal gets a credential that lasts 30 days, and the touch is the moment
Ada says yes to this terminal and this code. The approval records which
passkey (`device_authorizations.passkey_id`); the CLI session the poll
issues carries it as its `passkey_id`, and the approval's `decided_at` as
its `confirmed_at`. So a terminal starts with a five-minute window too.

**A fresh check.** Ada runs, an hour later:

```console
$ coffre access set bob@acme.example --role owner
This change needs a touch of your passkey. Approve it in your browser:

  https://secrets.acme.example/auth/device?code=QJXM-4WTP

Waiting for approval... approved.
bob@acme.example is now an Owner.
$ coffre tokens issue --service ci-deploy --scope market/prod=viewer --expires-in 30d
coffre_svc_...
```

On `403 fresh_check_required` the CLI starts a device login of its own,
labelled with the command it is running ("coffre CLI: access set
bob@acme.example --role owner"), prints the link, and polls. Ada opens it in
the signed-in browser, sees the command and the code, touches a passkey,
and approves. The poll returns a new CLI session, confirmed now; the CLI
swaps it in, signs the old one out, and retries the command. The second
command runs inside the new window without asking.

This reuses the device flow whole: its table, its page, its rate limits,
its audit entries. Nothing new is stored for a CLI fresh check. The cost is
a new CLI credential per step-up, which is a row and a `sign_in`-like
entry; risky commands are rare.

**What the CLI never needs.** `coffre run`, `export`, `set`, handles and
personal tokens. A personal token made from the CLI needs no check: it holds
at most what the CLI session holds, which a passkey confirmed.

### 3.6 Adding, renaming and removing passkeys

Account → Passkeys lists one's own: name, kind (synced or this device
only, from the authenticator's backup flags), added, last used. Each row has
Rename and Remove.

- **Add another**: a touch of an existing passkey within five minutes, then
  `create` with `excludeCredentials` listing the existing ones. The default
  name comes from the authenticator's AAGUID where it names one ("iCloud
  Keychain", "1Password", "YubiKey 5 Series"), else "Passkey 3".
- **Rename**: no check. A name grants nothing and sits outside every MAC.
- **Remove**: a touch. It also signs out every session that passkey last
  confirmed: "Removing YubiKey 5C signs out 2 sessions it confirmed." Under
  `required`, the last passkey cannot be removed: add another first.
- **At most 10** per person, which keeps the sealed sign-in cookie small.

### 3.7 Recovery

**One of two lost.** Ada signs in with iCloud Keychain and removes the
YubiKey. Its sessions end with it.

**All lost.** Bob asks an Owner. Ada opens Users → Bob → ⋯ → Reset
passkeys..., and the dialog says what happens: "Removes Bob's 2 passkeys
and signs out their 3 browser and CLI sessions. Their personal tokens (1) and
connected apps (0) stay unless you check them." Ada touches a passkey to
confirm. Bob's next sign-in under `required` asks for a new one, as a
first sign-in does; the page says "Ada reset your passkeys on 31 Oct".

Who may reset whose, mirroring R1:

- Only an unscoped Owner resets anyone's passkeys. Passkeys belong to the
  instance, not to a project, so a project's Owner resets nobody's.
- An Owner's passkeys are reset by another unscoped Owner, never by
  themselves through this route (they remove their own, with a touch).
- Owners the deployment names (`owners`, R3) are reset like any Owner.
- Every reset is a fresh check, an audited `passkey.reset` naming the
  passkeys and sessions it ended, and a banner at the target's next
  sign-in.

**The last Owner, every passkey lost.** No one can reset Ada's. Whoever
deploys coffre sets `passkeys: 'off'` and redeploys. Ada signs in with
GitHub alone, removes the lost passkeys (no check under `off`), and the
deployer puts the policy back; under `required` Ada adds a passkey at the
next sign-in. While it is `off`, a provider account is enough for everyone,
so the window should be minutes. A narrower lever is open question 3.

`off` keeps the rows. Passkeys are not deleted when a deployment turns
them off, so turning them back on restores everyone's.

## 4. What needs a fresh check

A fresh check is a touch of one of your passkeys within the last five
minutes, on the session making the request. The rule: **it guards what
widens someone's reach, mints a credential, or cannot be undone.** Removing
access, revoking, freezing and protecting never need one: in an incident
they must be quick.

Three answers per route:

- **always**: the caller touches a passkey. No passkey under `optional`:
  add one first (section 3.4). Under `off`: no check.
- **holder**: a touch if the caller has a passkey; nothing otherwise.
- **never**.

### 4.1 always

| Route | Why |
|---|---|
| `PUT /api/members/:member` | adds or restores a member with a role, scope and grants |
| `DELETE /api/members/:member` | removes a member; removing an Owner is the other way to demote one, and removing every other Owner is a takeover step |
| `PATCH /api/access/:member` | grants, instance role, Owner promotion and demotion |
| `PUT` / `DELETE /api/roles/:role`, `PUT` / `DELETE /api/instance-roles/:role` | what every holder of a role may do |
| `PUT /api/settings` | where people may set up service accounts |
| `POST /api/members/:member/tokens`, for a service | a service token |
| `POST /api/members/:member/bindings`, `POST …/bindings/keys` | a trust binding: GitHub or GitLab OIDC, Kubernetes, AWS, a custom issuer, and its uploaded keys |
| `POST …/bindings/:id/enrollments`, `POST …/enrollments/:enrollment/promote` | an enrollment code, and making one current |
| `POST /api/members/:member/tokens/:id/approve` | a workload's session waiting for a person |
| `DELETE /api/freezes/:target` | lifting a freeze lets its uses through again |
| `PATCH /api/projects/:project/:environment` with `protected: false` | unprotecting |
| `PATCH /api/secrets/…` that loosens a key's nature (sensitive to secret, R30; secret to plain) | a value people could not read becomes readable |
| `DELETE /api/projects/:project`, `DELETE …/:environment`, not `?dryRun` | erasing for good |
| `POST /api/audit/loss` | accepting lost log entries for good |
| `DELETE /api/members/:member/passkeys` | resetting someone's passkeys |

`?dryRun=1` of any of these needs nothing: it changes nothing.

### 4.2 holder

| Route | Why |
|---|---|
| `POST /api/device-logins/:code` with `approve: true` | a 30-day CLI session; a touch of its own, not the window (section 3.5) |
| `POST /api/oauth/authorizations` with `approve: true` | an MCP client's refresh token |
| `POST /api/members/user:<self>/tokens` from a browser session | a personal token outlives a 12-hour browser session; from a CLI session, never |
| `GET /auth/signin/:provider?link=1` | another provider account that signs in as you |
| `POST /api/members/user:<self>/passkeys`, a second one onward | a new factor |
| `DELETE /api/members/user:<self>/passkeys/:id` | removing a factor |

### 4.3 Reads, and `protectedReveals`

`POST /api/reveals` and every other read stay **never**, by default. With
`protectedReveals: true`, a reveal that opens a value of a protected
environment is **always** for a person's browser or CLI session: one touch
covers five minutes of reads, never a prompt per secret.

A personal token or an MCP connection cannot touch a passkey, so under
`protectedReveals` they read no protected environment's values; their
`/use` is untouched. Open question 4.

### 4.4 Who is never asked

- **Services**: service tokens, CI exchanges, workload sessions. They hold
  no passkey. What a service may do was fixed when its token or binding was
  made, and making one is a fresh check.
- **Personal tokens and MCP connections** are not exempt; they have
  nothing to touch. The fixed **always** routes are out of their reach
  already (`PERSONAL_TOKEN_ROUTES`, `ROUTE_SCOPES`). Where a token could
  reach a case that turns **always** by its input (unprotecting, loosening
  a key's nature), it is refused `fresh_check_required`, and its person does
  it signed in. A change an MCP client asks for is approved on
  `/approvals/:id`, and its Approve makes the change in process, in the
  approving browser's request: the check applies to that session. PR 4
  confirms the in-process call carries the approving session's credential
  to the router, and makes it if not.
- **Handles and `/use`**: never.

### 4.5 In code

```ts
// packages/server/src/api/fresh-routes.ts, typed over the route table as PERSONAL_TOKEN_ROUTES is.
type Fresh = 'always' | 'holder' | 'never';
export const FRESH_ROUTES: { [K in RouteKey]: Fresh | ((input: RouteInput<K>, ctx: ApiContext) => Fresh) } = {
  'PATCH /access/:member': 'always',
  'PATCH /projects/:project/:environment': (input) => (input.protected === false ? 'always' : 'never'),
  'POST /members/:member/tokens': (input, ctx) => …, // service: always; personal from a browser: holder; else never
  'POST /reveals': (input, ctx) => …,               // protectedReveals and a protected place: always
  'GET /me': 'never',
  // … every route
};
```

The router checks it after the body parses and before the handler runs,
from the request's credential, which it read already. A refusal is `403
fresh_check_required`, with `{ add: true }` when the caller has no passkey
yet, and is not logged: it is a prompt, not an attempt.

## 5. Storage

### 5.1 `passkeys`

```ts
export const passkeys = pgTable('passkeys', {
  id: uuid().primaryKey(),
  authMac: bytea('auth_mac').notNull(),
  // Whose: the member and the generation it was added in, as identities are bound.
  principal: text().notNull(),
  generation: integer().notNull(),
  // The authenticator's credential ID, raw (WebAuthn caps it at 1023 bytes), unique across the instance.
  credentialId: bytea('credential_id').notNull(),
  // The COSE_Key as registered, and its COSE algorithm: -8 Ed25519, -7 ES256, -257 RS256.
  publicKey: bytea('public_key').notNull(),
  algorithm: integer().notNull(),
  // The authenticator's signature counter; 0 for synced passkeys, which never move it.
  signCount: bigint('sign_count', { mode: 'number' }).notNull().default(0),
  // The newest challenge an assertion of it answered, by when it was issued: the replay guard (section 7.3).
  lastChallengeAt: timestamp('last_challenge_at', { withTimezone: true }),
  // Display only: what the browser said it can reach it by, its model, whether it syncs, and its name.
  transports: text().notNull().default('[]'),   // JSON array
  aaguid: bytea(),
  synced: boolean().notNull(),
  name: text().notNull(),
  createdAt: createdAt(),
  // Who added it: the person, or `system:signin` at a first sign-in.
  createdBy: text('created_by').notNull(),
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
  removedAt: timestamp('removed_at', { withTimezone: true }),
  // Who removed it: the person, or the Owner who reset it.
  removedBy: text('removed_by'),
}, (table) => [
  unique('passkeys_credential_id_key').on(table.credentialId),
  check('passkeys_auth_mac_check', sql`octet_length(${table.authMac}) = 32`),
  check('passkeys_algorithm_check', sql`${table.algorithm} IN (-8, -7, -257)`),
  check('passkeys_principal_check', sql`${table.principal} LIKE 'user:%'`),
  foreignKey({ name: 'passkeys_principal_fkey', columns: [table.principal], foreignColumns: [vaultMembers.principal] }).onDelete('restrict'),
  // A person's live passkeys: the sign-in's read and the Passkeys tab.
  index('passkeys_live_idx').on(table.principal, table.generation).where(sql`${table.removedAt} IS NULL`),
]);
```

The MAC is the sign-in rows' (`architecture.md`, "Sign-in rows"): a new
`passkeys` entry in `auth-rows.ts` over id, principal, generation,
credential ID, public key, algorithm and removed at. A database writer
cannot add a passkey or swap one's key. The counter, the replay mark, the
name, transports and last use are bookkeeping, outside the MAC as last-use
telemetry is elsewhere. A writer who lowers the counter or the replay mark
could let a captured assertion through again; under R64 that is a state
forged by a direct write, and it reveals nothing such a writer cannot
already read. A removed row put back with its old MAC is the same case.

Rows are never deleted: a removed passkey keeps its row, so a session can
still name the passkey that confirmed it, and the log's entries keep
resolving to a name.

A member's removal moves their generation past their passkeys, as it does
their identities: someone removed and added back starts with none.

`APP_KEY` rotation (R41) re-signs these rows with the others.

### 5.2 `credentials` and `device_authorizations`

```ts
// credentials: the passkey that last confirmed this session, and when. Null on every other kind.
passkeyId: uuid('passkey_id'),          // FK passkeys(id)
confirmedAt: timestamp('confirmed_at', { withTimezone: true }),

// device_authorizations: the passkey that approved this terminal; its decided_at is when.
passkeyId: uuid('passkey_id'),          // FK passkeys(id)
```

The credential's tuple gains a kind that covers both fields when
`passkey_id` is set, as a scope or a handle's places make a kind of their
own today. Rows without one keep the tuple they were signed with, so the
migration re-signs nothing. A device authorization does the same with
`passkey_id`.

What a session's row says, for Ada at 10:03:

| Session | `kind` | `passkey_id` | `confirmed_at` | Fresh? |
|---|---|---|---|---|
| Firefox, laptop | browser | YubiKey 5C | 10:02 | yes, until 10:07 |
| Safari, phone | browser | iCloud Keychain | 07:40 | no; confirmed at sign-in |
| CLI, laptop | cli | YubiKey 5C | 09:15 | no |
| Chrome, before the upgrade | browser | null | null | under `required`: refused until a passkey touch |

Fresh is derived, never stored: `confirmed_at > now - 5 minutes`. Removing
a passkey signs out the sessions whose `passkey_id` names it.

### 5.3 Migrations

One per engine (`packages/db/src/migrations/postgres`, `…/sqlite`), the
next in each sequence, additive only, as AGENTS.md's expand and contract
asks: a table, three nullable columns, two foreign keys on columns that are
null everywhere, and grants: `SELECT, INSERT, UPDATE` on `passkeys` to
`coffre_app`, `SELECT` to `coffre_backup` (or `pnpm test:schema` fails),
nothing to the vault's logins. The previous release ignores all of it and
keeps working while the migration runs ahead of the deploy.

`pnpm test:compat` keeps the newest release conformant on this schema.

## 6. The session model

Two facts, both on the credential, both read in the statement that already
reads it on every request, so no request reads anything more:

- **Signed in with a passkey**: `passkey_id` is set. A browser session gets
  it at sign-in, or at a step-up; a CLI session from the approval that made
  it.
- **Fresh**: `confirmed_at` within five minutes. Set at sign-in, at each
  fresh check, at a step-up, and from the device approval for a terminal.

Under `required`, a browser or CLI session with no `passkey_id` reaches only
`GET /api/me`, the passkey routes and sign-out. A page redirects to
`/auth/passkey?step-up=1`, which confirms the existing session (no new
one); the CLI is told to `coffre login` again. That covers sessions issued
before the deployment turned `required` on: they are asked once, not ended.

Under `optional`, the check is not needed per request: a person with a
passkey has no live session without one, because their sign-ins ask for it
and adding the first one signs out the rest (section 3.3).

`GET /api/me` answers `passkeys: { policy, enrolled, confirmedUntil }`, which
the pages read to decide when to open the dialog before sending.

A cookie-only window (a sealed `coffre_fresh` cookie bound to the session)
would need no write per check. It was the first design. It does not reach
the CLI, so the CLI would need a mechanism of its own, and it cannot
answer "which passkey confirmed this session", which removal needs. One
column read with the credential does all three.

## 7. The ceremony, checked

### 7.1 Relying party and origin

- `rpId` is `publicUrl`'s host, `secrets.acme.example`, unless the config
  names a parent of it, `acme.example`. Checked at startup: the host itself
  or a suffix on a label boundary with at least two labels. Browsers apply
  the public suffix list themselves.
- The origin in `clientDataJSON` must equal `publicUrl`'s origin exactly,
  whatever `rpId` is. So with `rpId: 'acme.example'`, a passkey works for
  `secrets.acme.example` alone, and an assertion phished by
  `evil.acme.example` fails. `crossOrigin` must be false or absent, and
  `topOrigin` absent.
- **Moving coffre to another host orphans its passkeys** unless `rpId` was
  a parent that covers both from the start. Under `required` that locks
  everyone out; the way back is `off`, then everyone re-adds. The config
  docs say so where `rpId` is described, and a deployment planning a move
  sets `rpId` first.
- **Custom domains on Workers**: `publicUrl` is the one origin coffre
  answers to, as for its cookies; a request through `*.workers.dev` fails
  the origin check as it fails sign-in today.
- **The dev stack**: `127.0.0.1` is not a valid RP ID; browsers refuse
  WebAuthn there. `dev/start.sh` would print `http://localhost:<port>`
  (a secure context, and a valid RP ID) when passkeys are on, and the
  dev deployment keeps `optional`, so the seed's personas sign in without
  any. Through a tunnel (`COFFRE_DEV_PUBLIC_URL`), the RP ID is the
  tunnel's host: a passkey added there does not work on `localhost`, and
  the reverse. Dev passkeys are throwaway; Chrome's DevTools virtual
  authenticator is enough for manual tests.

### 7.2 What each assertion must hold

In order, any failure refusing:

1. The sealed state opens, is unexpired, and is for this purpose (`signin`,
   `enroll`, `check`) and, for a check, this credential. Each purpose has
   its own HKDF key, so a sign-in's state never opens as a check's.
2. `clientDataJSON.type` is `webauthn.get` (`webauthn.create` to add);
   `challenge` equals the state's; origin as above.
3. `authenticatorData.rpIdHash` is SHA-256 of the `rpId`; flags: UP set, UV
   set, and BE/BS read for `synced`.
4. The credential ID is a live passkey of this principal and generation:
   another member's passkey is unknown here.
5. The signature verifies over `authenticatorData ‖ SHA-256(clientDataJSON)`
   with the stored key and algorithm. ES256 signatures arrive DER-encoded
   and are turned into the raw form WebCrypto takes.
6. The counter: if the stored one or the new one is non-zero, the new must
   be larger; otherwise refused and logged as a possible clone.
7. The replay mark moves (7.3).

To add one: steps 1 to 3 on the attestation's client data and
authenticator data, attested credential data present, algorithm one of the
three, credential ID unused across the instance. Attestation is `none`: the
attestation statement is ignored, whatever its format. Coffre trusts the
browser for which key was made, as every relying party that does not
restrict authenticator models does.

### 7.3 Challenges and replay

Challenges are 32 random bytes in a sealed value: a cookie at sign-in, where
there is no session yet, and a field of the JSON for an API check, bound to
the session's credential ID. Nothing is stored for a challenge.

Stateless challenges can be answered twice within their five minutes, so
the passkey's row holds the issue time of the newest challenge it answered,
and an assertion is taken only by moving it forward:

```sql
UPDATE passkeys
   SET last_challenge_at = $issued, sign_count = $count, last_used_at = now()
 WHERE id = $id AND removed_at IS NULL
   AND (last_challenge_at IS NULL OR last_challenge_at < $issued)
```

No row: replayed, or overtaken by a newer challenge, and refused. Two tabs
asking at once: the older one's touch is refused and it asks again. The
statement is the write the counter needs anyway, so replay costs nothing
extra.

### 7.4 User verification

`userVerification: 'required'`: the touch is a fingerprint, a face or the
device's PIN, never presence alone. Every platform passkey does it; a
security key without a PIN is asked to set one. Presence alone would let
anyone at an unlocked laptop with a plugged-in key confirm an Owner change.
Open question 5.

## 8. The app authenticates, the vault authorizes: where the check lives

`architecture.md`: "The app decides who someone is. The vault decides what
they may decrypt." A passkey is about who, so it is the app's. The question
is whether the vault should also refuse a role change or a credential issue
that no fresh passkey confirmed. Three options:

**A. App only (proposed).** The router enforces `FRESH_ROUTES`; the vault is
unchanged. The audit entries of every guarded act name the passkey and the
time it confirmed.

- Catches: stolen provider accounts, phishing, stolen cookies (section 1).
- Misses: an app that forgets the check. `FRESH_ROUTES` is typed over the
  route table, so a new route cannot forget silently; conformance checks
  each **always** route without a confirmation.
- Misses: an app taken over. It can skip the check.

**B. The app's claim, sealed for the vault.** The credential's
`confirmed_at` becomes part of its sealed object, written through a vault
change, and the vault refuses `setAccess`, issues and role changes without
it.

- Catches: an app bug that skips the router's check, as the vault catches
  permission bugs today.
- Misses: an app taken over, which writes the vault change "confirmed now"
  itself. The vault cannot tell a touch happened.
- Costs: a vault change per fresh check, waiting on the checkpoint (R51),
  the credential's sealed object and the TLA+ and Lean models grow (R45),
  and a second copy of the rule.

**C. The vault verifies the passkey.** Passkey public keys become part of
the member's sealed object, added through vault changes. A guarded act
carries an assertion whose challenge is the digest of the exact change
("promote bob@acme.example to Owner, basis 9f3c…"), and the vault verifies
it before it decides. The vault needs no network for this, so R63 holds.

- Catches: an app taken over, for those acts. It cannot promote anyone
  without an Owner's touch on that exact change. This is the "requests
  signed by keys the principals hold themselves" that `architecture.md`
  names as what would close that gap.
- Costs: a touch per act, never a window (a window is a time grant the app
  could replay); the first passkey is still trust on first use through the
  app; the reset path becomes vault changes; WebAuthn parsing in the vault;
  a model of its own in TLA+.

**Recommendation: A now, C later for the few acts that make Owners and
change what roles mean.** B buys little: it guards against a bug that the
typed table already makes hard, and not against the attacker the vault
exists for. C is the real step and should be designed with the vault's
next model, not bolted on here. A builds everything C needs: the table, the
verifier in `@coffre/core`, passkeys bound to members and generations.

## 9. The verifier: our own, not `@simplewebauthn/server`

`@simplewebauthn/server` 14.0.3 (published 2026-09-25, past the 7-day
release age) is the usual choice and runs on Workers: it uses WebCrypto.
Measured on this machine, esbuild bundling only `verifyRegistrationResponse`
and `verifyAuthenticationResponse` for a neutral platform, minified: **312 KB,
88 KB gzipped**, from 10 direct dependencies (`@peculiar/x509`,
`@peculiar/asn1-*` including post-quantum, `reflect-metadata`, `tsyringe`
through x509, `@levischuck/tiny-cbor`, `@hexagon/base64`). Nearly all of it
verifies attestation certificate chains, which coffre never asks for.
`reflect-metadata` patches a global. Each would be one more exact pin under
the release-age rule, and the bundle is parsed in every cold isolate,
which R27 counts.

What coffre needs fits in about 300 lines in `@coffre/core/identity`:

- a CBOR decoder for the subset WebAuthn uses (unsigned and negative
  integers, byte and text strings, arrays, maps; definite lengths only;
  anything else refused);
- `authenticatorData` and `clientDataJSON` parsing, and the checks of 7.2;
- COSE keys to WebCrypto: EC2 P-256, OKP Ed25519, RSA; and ES256's DER
  signatures to raw;
- `crypto.subtle.verify`, which both runtimes have; core already verifies
  DPoP proofs this way.

It is held by: the W3C spec's examples and SimpleWebAuthn's own test
fixtures, copied as data; a software authenticator (P-256 and Ed25519, in
the test helpers and in `@coffre/conformance`) that makes real
registrations and assertions; and property tests where a flipped bit in any
signed byte, a changed origin or a changed RP ID must fail.

The browser side needs no library:
`PublicKeyCredential.parseRequestOptionsFromJSON`, `parseCreationOptionsFromJSON`
and `credential.toJSON()` where the browser has them, and a base64url
helper of a dozen lines where it does not.

## 10. Cost

Measured against R42 (a handful of queries, no chain of round trips), R27
(well under 10 ms CPU at p50) and R44/R58 (the hot paths).

| Flow | Queries | CPU added | Round trips added |
|---|---|---|---|
| Sign-in callback | 1: identity, member and passkeys in one statement; the session's writes move to the passkey POST | one seal | none |
| `GET /auth/passkey` | 0: renders from the cookie | one unseal | the page, one |
| `POST /auth/passkey` | 1 for the passkey (7.3), then today's `completeSignin` | one signature check, CBOR parsing | one |
| Fresh check | options: 1 (the person's passkeys); verify: one transaction, the passkey's statement, the credential's update and its entry | one signature check | two requests, plus the touch |
| Every other request | 0: two more columns of the row already read | a comparison | none |
| `/use`, CI and workload sign-in | 0: never consulted | none | none |

A P-256 or Ed25519 verification costs well under a millisecond of WebCrypto
in either runtime; the first PR measures it with `pnpm bench:workers`
before merging. A sign-in with a passkey is two more browser round trips
than today, one of them the person's touch.

## 11. Audit

New actions, in the shared log as `account.link` and `device.approve` are:

| Action | When | Metadata |
|---|---|---|
| `passkey.add` | a passkey is added: at a first sign-in, from Account | passkey ID, name, AAGUID, synced, sessions signed out (first one) |
| `passkey.remove` | its person removes one | passkey ID, sessions signed out |
| `passkey.reset` | an Owner resets someone's | target, passkey IDs, sessions signed out, tokens and apps revoked |
| `passkey.check` | a fresh check, allowed or denied | passkey ID, purpose; on deny, the reason: `origin`, `rp_id`, `challenge`, `replay`, `unknown_credential`, `signature`, `counter`, `user_verification` |

Changed:

- `sign_in` entries name the passkey that confirmed them, and a denied
  `sign_in` gains the reasons above as `passkey_<reason>`.
- `device.approve` names the passkey that approved.
- Every **always** act names, in its own entry, the passkey and time that
  confirmed the session (`confirmedBy`, `confirmedAt`).

A `403 fresh_check_required` is not logged.

## 12. Behind Cloudflare Access

With `cloudflareAccess()`, Access keeps the browser's session and
`cloudflared` the CLI's; coffre has no credential row to mark. Passkeys are
an option of `signin()` only, so such a deployment cannot turn them on,
and its typecheck says so. Access has its own policies, MFA among them,
for the sign-in half. A fresh check behind Access would need a cookie of
coffre's bound to the Access identity, and the CLI would need something
else again. Open question 6.

## 13. Conformance

`@coffre/conformance` holds every deployment to what it must never do. It
gains a software authenticator and these checks, each against a deployment
running `passkeys: 'required'`:

1. An assertion whose `clientDataJSON.origin` is another origin is refused.
2. An assertion whose `rpIdHash` is another RP ID's is refused.
3. The same assertion, sent twice with its sealed state, signs in once.
4. An assertion by another member's passkey, for this member's pending
   sign-in or fresh check, is refused.
5. A sign-in state cannot complete a fresh check, nor the reverse.
6. An assertion without UV is refused.
7. A provider sign-in that stops before the passkey sets no session cookie,
   and the next request with what it did set is `401`.
8. A browser session with no passkey reaches nothing but `GET /api/me`, the
   passkey routes and sign-out.
9. Every **always** route answers `403 fresh_check_required` to a session
   confirmed more than five minutes ago, and none of them changes anything.
10. A removed passkey signs nobody in, and the sessions it confirmed are
    `401`.
11. `/use` and `POST /api/auth/workload` answer as they did, with no
    passkey anywhere.

## 14. Build plan (phase 2, after 0.15)

1. **The verifier**, in `@coffre/core/identity`, with its vectors, the
   software authenticator and property tests. No wiring.
2. **Storage**: the migrations, the schema, the MAC kinds, `pnpm
   test:schema` and the backup grant.
3. **Sign-in**: `signin({ passkeys })`, the callback's split, `/auth/passkey`
   and its page, enrolling under `required`, the step-up. Waits for #436 and
   T171, which touch the callback.
4. **Fresh checks**: `FRESH_ROUTES`, `POST /api/passkeys/checks`, the
   dialog, the CLI's step-up through the device flow.
5. **Management**: Account → Passkeys, the Owner reset, the prompt under
   `optional`, `protectedReveals`.
6. **Conformance** checks of section 13, and docs: `docs/deployment-auth.md`
   (the policy, `rpId`, recovery) and `docs/offboarding.md`.

Each PR leaves `main` shippable: until PR 3, nothing is reachable.

## 15. Open questions for Erwin

1. **A per-act touch or a five-minute window?** Proposed: the window, as you
   asked, with one exception: approving a terminal takes a touch of its own
   (section 3.5). Option: a touch per act for Owner promotion and role
   edits only, which is what option C in section 8 would need anyway.
2. **`required: 'owners'`?** Under `optional`, anyone who changes access
   has to add a passkey at their first risky act (section 2), so I propose
   no fourth mode. A fourth mode would also make Owners add one at their
   next sign-in, closing the window before their first risky act. Proposed:
   no fourth mode now; it can be added later without migration.
3. **Recovering the last Owner: `off` for everyone, or a named exemption?**
   `off` is what you described; it opens every account to its provider
   alone while it lasts. Option: `passkeys: { policy: 'required', recover:
   ['admin@acme.example'] }`, which lets only the people named sign in
   without one and makes them add a new one. Proposed: `off`, documented,
   for its simplicity; the exemption if you would rather not drop the
   factor for everyone.
4. **`protectedReveals` and tokens.** Under it, personal tokens and MCP
   connections read no protected environment's values (they cannot touch a
   passkey); their `/use` is untouched. Option: let a personal token made
   inside a fresh window read them until it expires. Proposed: refuse, and
   leave `protectedReveals` off by default.
5. **User verification: `required` or `preferred`?** Proposed `required`:
   a touch then means the person, not someone at their unlocked laptop.
   `preferred` would let PIN-less security keys work without setup.
6. **Fresh checks behind Cloudflare Access?** Proposed: not in phase 2;
   Access deployments use Access's own MFA policies. Option: a sealed
   cookie bound to the Access identity for the browser, and browser-only
   for risky acts.
7. **Does an Owner reset also revoke the person's personal tokens and
   connected apps?** Proposed: the dialog offers both, unchecked; sessions
   always end. Option: always revoke all of it, as an offboarding does
   short of removal.
8. **The vault (section 8).** Proposed: A now, C designed with the vault's
   next model for Owner-level acts. Option: C in phase 2 for promotion to
   Owner only.
