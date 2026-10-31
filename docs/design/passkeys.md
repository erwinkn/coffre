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
| Connecting an MCP client, linking an account, managing passkeys | as today | a touch in the last 5 minutes, if you have a passkey | a touch in the last 5 minutes |
| Approving a terminal | as today | a touch for that terminal, if you have a passkey | a touch for that terminal |
| Reading values | as today | as today | as today |
| Reading a protected environment's values, with `protectedReveals` | as today | a touch in the last 5 minutes | a touch in the last 5 minutes |
| `/use`, CI and workload sign-in, services | untouched | untouched | untouched |

Three rules carry it:

1. **A touch issues a new session.** Every passkey touch in a browser (at
   sign-in, at a fresh check, at a step-up, approving a terminal) issues a new session to the
   browser that touched, and ends the one it came in on. A copy of the old
   cookie, wherever it went, stops working.
2. **Changes to a person's passkeys end credentials by revoking them,
   under one per-person lock that every issue takes too** (section 6). A
   first passkey ends what no passkey confirmed; removing or resetting one
   signs the person out everywhere else. Nothing is inferred from
   timestamps, so nothing revoked comes back.
3. **The app enforces it; the vault does not** (section 8). The vault could
   verify passkey signatures itself later, for Owner-level acts.

The pieces:

- **One new table**, `passkeys`, and nullable columns: `passkey_id` and
  `confirmed_at` on `credentials`, `passkey_id` on `device_authorizations`
  and `mcp_connections`. All additive: one migration per engine.
- **Sign-in routes**: `GET` and `POST /auth/passkey`, between the provider's
  callback and the session. Until the passkey answers, coffre writes
  nothing: what the provider vouched for waits in a small sealed cookie,
  as `PendingSignin` does today.
- **API routes**: `POST /api/passkeys/challenges`, `POST
  /api/passkeys/checks`, and `GET`, `POST`, `PATCH` and `DELETE
  /api/members/:member/passkeys[/:id]`.
- **A table typed over the route table**, `FRESH_ROUTES`, like
  `PERSONAL_TOKEN_ROUTES`: every route says whether it needs a fresh check,
  so a new route fails the typecheck until it says. The sign-in routes
  outside the table check for themselves (section 4.5).
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

**A stolen session cookie.** Malware lifts Ada's cookie at 09:00 and replays
it from elsewhere. It can read what Ada reads, as today. It cannot promote
anyone, issue a service token, approve a terminal or connect an MCP client:
those need a session touched in the last five minutes. And when Ada next
touches a passkey, at 10:02, that browser gets a new session and the
stolen one ends (rule 1): the thief cannot ride Ada's touch.

**What it does not stop:**

- **The first passkey is trust on first use.** Under `required`, whoever
  passes the provider first for Bob adds the passkey. Under `optional`, a
  person who has none yet is as strong as their provider account until they
  add one. The first passkey needs a sign-in from the last ten minutes,
  which narrows a stolen cookie's chance to add one (section 3.3).
- **An app fully taken over.** It can skip its own checks. The vault does
  not see passkeys in this design (section 8).
- **A cookie stolen after the touch.** A thief who copies Ada's new cookie
  in the five minutes after Ada's touch gets the rest of that window. The
  window is the price of not touching per act.
- **Malware that stays.** Software on Ada's machine that reads every new
  cookie gets every new session. A passkey proves a touch, not a clean
  device.
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
   identity, its member, and whether that member has a live passkey
   (today's `findIdentity`, joined). Ada has one, so no session yet. The
   callback clears the provider's pending cookie and sets another,
   `__Host-coffre_passkey`, sealed like `PendingSignin`, five minutes long,
   and small:

   ```ts
   type PendingFactor = {
     purpose: 'signin' | 'enroll';
     // What GitHub vouched for: the account, and for a first sign-in the one verified email that
     // matched an invitation. Never the whole list: the cookie stays under 1 KB sealed.
     account: { provider: string; subject: string; email: string | null; name: string | null }; // name cut to 100 characters
     principal: string;             // 'user:admin@acme.example'
     generation: number;
     next: string;                  // where to land, a path of at most 512 characters, or '/projects'
     challenge: string;             // 32 random bytes, base64url
     issuedAt: number;              // ms; also the replay guard (section 7.3)
   };
   ```

   and redirects to `/auth/passkey`. Sealing refuses a value over 3 KB, so
   no input can make a cookie a browser drops.
3. The page, "Confirm it's you", reads the cookie and Ada's live passkeys in
   its render (one query: IDs and transports), and its button calls
   `navigator.credentials.get` with that challenge, `rpId:
   'secrets.acme.example'`, those passkeys as `allowCredentials`, and
   `userVerification: 'required'`. Ada touches the YubiKey.
4. `POST /auth/passkey` with the assertion, a browser post held to the
   same origin as every other. coffre opens the cookie, reads the passkey
   the assertion names (its key and counter), checks the assertion (section
   7), and runs today's `completeSignin` from the cookie's `account`, which
   re-reads and re-checks everything it decides on. Inside its transaction,
   before the session is written, it moves the passkey's counter and replay
   mark (section 7.3), conditional on the passkey still being live and
   still Ada's, at the generation `completeSignin` resolved. The session
   carries `passkey_id` = the YubiKey and `confirmed_at` = now. The cookie
   is cleared, the session cookie set, and Ada lands on `next`.

The cookie carries what GitHub vouched for and nothing coffre decided.
Someone who passed GitHub but not the passkey leaves no row behind, and an
unauthenticated visitor makes coffre write nothing, as today.

**The callback writes nothing, the vault included.** Today a first sign-in
can admit a member: `#principalForEmails` asks `vault.access`, which makes
an Owner the deployment names (`owners`, R3) a member when they are none
yet, on an empty instance too. Under passkeys the callback only reads: it
matches the email against the members' rows and the deployment's `owners`.
Not through `vault.about()`, which settles a cold vault first and can
write (keys, members, the configured Owners, the bulk policy): through a
new read-only `vault.configuredOwners()`, which answers from the vault's
configuration alone. An Owner named in config with no
member row yet gets an `enroll` cookie with `generation: null`; the `POST`
admits them through `vault.access`, as today, once the attestation has
verified, then enrolls at the generation that answered. Conformance runs
`required` on an empty database and on a cold vault (section 13).

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

**An `enroll` state adds a first passkey only.** The transaction, under the
audit head that already serializes bindings to one person, checks that the
person has no live passkey, and refuses otherwise ("You already have a
passkey: sign in with it"). So a second use of the same sealed state, or two
tabs racing, adds one passkey at most, and nobody adds a second key through
the door meant for the first.

`user.id` is 16 random bytes, made at a person's first passkey and kept on
each of their passkey rows (`passkeys.user_handle`), copied from the
others when they add one. WebAuthn asks that it reveal nothing about the
person, and a hash of the email, even keyed, can be tested against
guesses by anyone who learns the key; random bytes cannot, and survive an
`APP_KEY` rotation. It stays the same across a person's passkeys, so a
keychain that already holds one for Bob replaces it instead of keeping two,
and the `userHandle` an assertion returns is checked against the row of the
passkey it names (7.2). A configured Owner not yet admitted gets one at
registration, as anyone does; nothing about it depends on the generation.

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
It takes the same "still first" check as section 3.2.

Adding a first passkey changes three things for Bob:

- this browser gets a new session confirmed by it (rule 1);
- Bob's other credentials, which no passkey confirmed, end, and stay ended
  whatever happens to the passkey later (section 6): another browser is
  asked to sign in again, a terminal to `coffre login` again, a personal
  token, handle or MCP client is made again; and
- Bob's next sign-in asks for it.

### 3.4 A fresh check in the browser

Ada promotes Bob to Owner at 10:02. Ada's session was confirmed at 08:15, at
sign-in.

1. Users → Bob → Change global role → Owner → Save. The page knows from
   `GET /api/me` that the session was confirmed until 08:20, so before it
   sends anything, it opens "Confirm it's you" with what Ada is about to
   do: "Make bob@acme.example an Owner".
2. Use passkey → `POST /api/passkeys/challenges { purpose: 'check' }`
   answers the request options and a sealed state bound to the session's
   credential; Ada touches the YubiKey; `POST /api/passkeys/checks { state,
   assertion }` checks it and, in one transaction, moves the passkey's
   replay mark, issues a new session (`passkey_id` = YubiKey, `confirmed_at`
   = 10:02) and ends the old one. The response sets the new cookie.
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
passkey to change roles": one `create`, which also issues a confirmed
session, then the change goes. The ten-minute rule of section 3.3 holds
here too: in an older session the dialog says "Sign in again to add your
first passkey".

A fresh check is a session issue, so it costs what a sign-in's issue costs
(section 10). Risky acts are rare; a window means one per five minutes at
most.

### 3.5 The CLI

**Approving a terminal.** `coffre login` stays a device login. Approving it
takes a touch for that terminal, not the browser's window: the terminal gets
a credential that lasts 30 days, and the touch is the moment Ada says yes to
this code. So the approval page asks `POST /api/passkeys/challenges {
purpose: 'device', code: 'QJXM-4WTP' }`, whose sealed state names that
device authorization and the approving session, and Approve sends `POST
/api/device-logins/QJXM-4WTP { approve: true, state, assertion }`. The
decision's transaction checks the assertion, moves the replay mark, records
the passkey (`device_authorizations.passkey_id`) with the decision, and, as
every touch in a browser does, replaces the approving browser's session
(rule 1) and sets its new cookie. A fresh browser session alone approves
nothing; one touch approves one code.

The poll that redeems the code issues the CLI session with that
`passkey_id`, and the approval's `decided_at` as its `confirmed_at`. Its
transaction takes the person's lock (section 6) and checks under it that
the approval still stands and its passkey is still live, so a passkey
removed, or a first one added, between approval and poll redeems nothing. A terminal starts with a five-minute window too.

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
and approves. The poll returns a new CLI session, confirmed then; the CLI
swaps it in, signs the old one out, and retries the command. The second
command runs inside the new window without asking.

This reuses the device flow whole: its table, its page, its rate limits,
its audit entries. The cost is a new CLI credential per step-up, which is a
row and a `sign_in`-like entry; risky commands are rare.

**What the CLI never needs.** `coffre run`, `export`, `set`, handles and
personal tokens. A personal token made from the CLI needs no check: it holds
at most what the CLI session holds, which a passkey confirmed, and it names
that passkey (section 6).

### 3.6 Adding, renaming and removing passkeys

Account → Passkeys lists one's own: name, kind (synced or this device
only, from the authenticator's backup flags), added, last used. Each row has
Rename and Remove.

- **Add another**: a session confirmed in the last five minutes, then
  `create` with `excludeCredentials` listing the existing ones. The default
  name comes from the authenticator's AAGUID where it names one ("iCloud
  Keychain", "1Password", "YubiKey 5 Series"), else "Passkey 3".
- **Rename**: no check. A name grants nothing and sits outside every MAC.
- **Remove**: a touch of a passkey the person keeps, in the remove dialog
  itself, so the new session this browser gets names a passkey that is
  still live and was just touched. It signs the person out everywhere else:
  every other session, terminal, personal token, handle and MCP client
  ends (section 6.1). The dialog says how many: "Removing YubiKey 5C signs
  you out of 3 other sessions and ends 1 personal token." Under `required`,
  the last passkey cannot be removed: add another first. Under `optional`,
  removing the last one takes a touch of that one, and the new session
  names no passkey and is not fresh: the person is back to signing in with
  the provider alone.
- **At most 10** per person: a list a person can still read.

### 3.7 Recovery

**One of two lost.** Ada signs in with iCloud Keychain and removes the
YubiKey. Every other session of Ada's ends with it.

**All lost.** Bob asks an Owner. Ada opens Users → Bob → ⋯ → Reset
passkeys..., and the dialog says what happens: "Removes Bob's 2 passkeys.
Everything Bob is signed in with ends: 3 sessions, 1 personal token, 2
handles and 1 connected app." Ada touches a passkey to confirm. Bob's
next sign-in under `required` asks for a new one, as a first sign-in does;
under `optional`, GitHub alone signs Bob in again. Either way the page says
"Ada reset your passkeys on 31 Oct".

Who may reset whose, mirroring R1:

- Only an unscoped Owner resets anyone's passkeys. Passkeys belong to the
  instance, not to a project, so a project's Owner resets nobody's.
- An Owner's passkeys are reset by another unscoped Owner, never by
  themselves through this route (they remove their own, with a touch).
- Owners the deployment names (`owners`, R3) are reset like any Owner.
- Every reset is a fresh check, an audited `passkey.reset` naming the
  passkeys and what ended with them, and a banner at the target's next
  sign-in.

**The last Owner, every passkey lost.** No one can reset Ada's. Whoever
deploys coffre sets `passkeys: 'off'` and redeploys. Ada signs in with
GitHub alone, removes the lost passkeys (no check under `off`), and the
deployer puts the policy back; under `required` Ada adds a passkey at the
next sign-in. While it is `off`, a provider account is enough for everyone,
so the window should be minutes. A narrower lever is open question 3.

What `off` leaves behind when it ends: sessions, terminals, personal
tokens and MCP clients made while it lasted name no passkey, so for anyone
who has a passkey they are refused at their next request once the policy is
back, and revoked by that person's next removal or reset (section 6);
handles made meanwhile live out their lifetime unless revoked. What `off` cannot undo by itself is what such a session did:
service tokens issued, bindings made, access changed. The recovery steps in
`docs/deployment-auth.md` end with reading the log for the `off` window.

`off` keeps the rows. Passkeys are not deleted when a deployment turns
them off, so turning them back on restores everyone's.

## 4. What needs a fresh check

A fresh check means the session making the request was confirmed by a
passkey touch in the last five minutes: `confirmed_at` within five minutes,
on a session that rule 1 issued at that touch. The rule for what needs one:
**it guards what widens someone's reach, mints a credential, or cannot be
undone.** Removing access, revoking, freezing and protecting never need one:
in an incident they must be quick.

Four answers per route:

- **always**: a fresh session. No passkey under `optional`: add one first
  (section 3.4). Under `off`: no check.
- **holder**: a fresh session if the caller has a passkey; nothing
  otherwise.
- **ceremony**: the request carries its own assertion, for that request's
  target alone (section 3.5); a fresh session is not enough. Nothing for a
  caller without a passkey under `optional`.
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

`?dryRun=1` needs no check only on the routes that take it, those whose
`query` is `dryRunFlag` or extends it (issuing tokens, bindings and their
keys, erasing for good, role edits, secret writes), and only when the
parsed query says so: the route's `FRESH_ROUTES` entry is a function of its
input and query. A route that takes no `dryRun` is checked whatever its
query string says; `PATCH /api/access/:member?dryRun=1`, which changes
access today, needs a fresh session like any other.

### 4.2 holder and ceremony

| Route | Answer | Why |
|---|---|---|
| `POST /api/device-logins/:code` with `approve: true` | ceremony | a 30-day CLI session (section 3.5) |
| `POST /api/oauth/authorizations` with `approve: true` | holder | an MCP client's refresh token |
| `POST /api/members/user:<self>/tokens` from a browser session | holder | a personal token outlives a 12-hour browser session; from a CLI session, never |
| `GET /auth/signin/:provider?link=1`, and its callback | holder | another provider account that signs in as you (section 4.5) |
| `POST /api/members/user:<self>/passkeys`, a second one onward | holder | a new factor |
| `DELETE /api/members/user:<self>/passkeys/:id` | ceremony | removing a factor: a touch of a passkey kept, or of the last one (section 3.6) |

### 4.3 Reads, and `protectedReveals`

`POST /api/reveals` and every other read stay **never**, by default. With
`protectedReveals: true`, a reveal that opens a value of a protected
environment needs a fresh session, for a person's browser or CLI session:
one touch covers five minutes of reads, never a prompt per secret. The
vault checks it, not the router (below).

A personal token or an MCP connection cannot touch a passkey, so under
`protectedReveals` they read no protected environment's values; their
`/use` is untouched. Open question 4.

**The vault decides it, on every reveal path.** Whether an environment is
protected is the vault's to say: it reads the place under its own lock, and
the policy can change while a read runs (another Owner protects `prod` while
a stale session's `coffre export` is opening it). A check in the router, or
in the app before the vault's call, decides on a protection the vault may
no longer hold by the time it releases the values. So the router does not
check reveals at all. **Every vault call that releases a value carries
whether the caller's session is fresh**, `fresh: boolean`, beside what the
call carries today, whichever route or path reaches it. Today those calls
are `useNamed` (one key, by name; `fresh` goes in its `accepts`), `use` and
`useMany` (0.15's reads, which `openValues` sends through `useValues`), and
`unwrap` (0.14's); a new one joins the list in the `Vault` interface's own
type, which makes `fresh` a required field of every call that returns a
value. `fresh` is true for anything but a person's credential (browser,
CLI, personal token, MCP connection): a service's read and a handle's `/use`
never wait on a touch.
The vault refuses a protected environment to a caller who is not fresh
where it refuses a caller without standing, under the same fence that
holds the policy for that decision, and so with the same answer as any
refusal there: the named path's one `404 not_available`, the unwrap's
`vault_refused`. A protection that lands while the read runs is the
vault's own read, fenced like any other change of the policy.
`Probing.tla`'s `AcceptedFirst` and `NoKeyBeforeStanding` take the new
input, the use matrices gain its cases, and the unwrap's policy fence holds
on all-encrypted reads too, on each of those calls.

**Asking before reading.** A refusal that looks like any other cannot ask
for a touch, so the clients ask first, from what is no secret: `GET
/api/me` lists the environments the caller reaches, each with whether it is
protected, and says `confirmedUntil`. Before a read of a protected
environment from a session that is not fresh, the page opens the confirm
dialog, and the CLI starts its step-up (section 3.5), then reads. A
protection that lands in between gets the plain refusal; the client reads
`/api/me` again, sees it, confirms and retries once.

`protectedReveals` ships in a PR of its own, after the rest (section 14).

### 4.4 Who is never asked, and who cannot be

- **Services**: service tokens, CI exchanges, workload sessions. They hold
  no passkey. What a service may do was fixed when its token or binding was
  made, and making one is a fresh check.
- **Personal tokens and MCP connections** are not exempt; they have
  nothing to touch. The fixed **always** routes are out of their reach
  already (`PERSONAL_TOKEN_ROUTES`, `ROUTE_SCOPES`). Where a token could
  reach a case that turns **always** by its input (unprotecting, loosening
  a key's nature), it is refused `fresh_check_required`, and its person does
  it signed in.
- **An MCP client's change** is approved on `/approvals/:id`, and its
  Approve makes the change in process, in the approving browser's request,
  so the router's check applies to that session. Today's `#decide` commits
  the approval before it makes the change and records `failed` if the
  change throws, which would spend the approval on a mere prompt. So
  Approve asks `FRESH_ROUTES` about the change's own route first, and
  answers `403 fresh_check_required` with the approval still pending; the
  page confirms and approves again. The inner check stays.
- **Handles and `/use`**: never.

### 4.5 In code, and the routes outside the table

```ts
// packages/server/src/api/fresh-routes.ts, typed over the route table as PERSONAL_TOKEN_ROUTES is.
type Fresh = 'always' | 'holder' | 'ceremony' | 'never';
export const FRESH_ROUTES: { [K in RouteKey]: Fresh | ((input: RouteInput<K>, ctx: ApiContext) => Fresh) } = {
  'PATCH /access/:member': 'always',
  'PATCH /projects/:project/:environment': (input) => (input.protected === false ? 'always' : 'never'),
  'POST /members/:member/tokens': (input, ctx) => …, // service: always; personal from a browser: holder; else never
  'POST /device-logins/:code': (input) => (input.approve ? 'ceremony' : 'never'),
  'POST /reveals': 'never',                         // protectedReveals is the vault's to decide (section 4.3)
  'GET /me': 'never',
  // … every route
};
```

The router checks it after the body parses and before the handler runs,
from the request's credential, which it read already. A **ceremony** route
checks its assertion in its own handler, inside the transaction that makes
its change. A refusal is `403 fresh_check_required`, with `{ add: true }`
when the caller has no passkey yet, and is not logged: it is a prompt, not
an attempt.

The sign-in routes are protocols beside the table (`auth-routes.ts`), so
they check for themselves:

| Route | Check |
|---|---|
| `GET /auth/signin/:provider?link=1` | holder, at the start, before leaving for the provider |
| `GET /auth/callback/:provider` for a link | holder again, before `linkIdentity` commits: the browser's session must still be the one the link started from and still fresh; if the window ran out at the provider, "Confirm again and link" |
| `POST /api/auth/device/token` (the poll) | the approving passkey still live, inside the issuing transaction (section 3.5) |
| `POST /api/oauth/token` (an MCP refresh) | the connection's passkey still live (section 6) |
| `POST /auth/signout`, `POST /api/auth/logout` | never |
| `POST /api/auth/oidc`, `POST /api/auth/workload` | never: services |

Conformance checks the link and the poll (section 13), since no type holds
them.

## 5. Storage

### 5.1 `passkeys`

```ts
export const passkeys = pgTable('passkeys', {
  id: uuid().primaryKey(),
  authMac: bytea('auth_mac').notNull(),
  // Whose: the member and the generation it was added in, as identities are bound.
  principal: text().notNull(),
  generation: integer().notNull(),
  // The WebAuthn user handle: 16 random bytes, the same on every passkey of the person's (section 3.2).
  userHandle: bytea('user_handle').notNull(),
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
  check('passkeys_credential_id_check', sql`octet_length(${table.credentialId}) BETWEEN 16 AND 1023`),
  check('passkeys_principal_check', sql`${table.principal} LIKE 'user:%'`),
  foreignKey({ name: 'passkeys_principal_fkey', columns: [table.principal], foreignColumns: [vaultMembers.principal] }).onDelete('restrict'),
  // A person's live passkeys: the per-request check, the sign-in's read and the Passkeys tab.
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

Rows are never deleted: a removed passkey keeps its row, so a credential can
still name the passkey that confirmed it, and the log's entries keep
resolving to a name.

A member's removal moves their generation past their passkeys, as it does
their identities: someone removed and added back starts with none.

`APP_KEY` rotation (R41) re-signs these rows with the others.

### 5.2 The columns that name a passkey

```ts
// credentials: the passkey that confirmed this credential, and when it was touched.
// Set on browser and CLI sessions, and copied onto what they make: personal tokens and handles (no confirmed_at).
passkeyId: uuid('passkey_id'),          // FK passkeys(id)
confirmedAt: timestamp('confirmed_at', { withTimezone: true }),

// device_authorizations: the passkey that approved this terminal; its decided_at is when.
passkeyId: uuid('passkey_id'),          // FK passkeys(id)

// mcp_connections: the passkey that confirmed the session that connected it.
passkeyId: uuid('passkey_id'),          // FK passkeys(id)
```

Each row's MAC tuple gains a kind that covers these fields when
`passkey_id` is set, as a scope or a handle's places make a kind of their
own today. Rows without one keep the tuple they were signed with, so the
migration re-signs nothing. The fields are written once, when the row is
made: rule 1 means a touch issues a new credential, never updates one, so
no MAC is re-signed on a check.

What Ada's credentials say at 10:03:

| Credential | `kind` | `passkey_id` | `confirmed_at` | Fresh? |
|---|---|---|---|---|
| Firefox, laptop, issued at the 10:02 check | browser | YubiKey 5C | 10:02 | yes, until 10:07 |
| Firefox, laptop, the one before it | browser | YubiKey 5C | 08:15 | ended at 10:02 |
| Safari, phone | browser | iCloud Keychain | 07:40 | no |
| CLI, laptop | cli | YubiKey 5C | 09:15 | no |
| `cursor-agent` personal token | personal | YubiKey 5C | null | never needs to be |
| Chrome, made before the upgrade | browser | null | null | refused: asks for a touch (section 6) |

Fresh is derived, never stored: `confirmed_at > now - 5 minutes`.

### 5.3 Migrations

One per engine (`packages/db/src/migrations/postgres`, `…/sqlite`), the
next in each sequence, additive only, as AGENTS.md's expand and contract
asks: a table, four nullable columns, four foreign keys on columns that are
null everywhere, and grants: `SELECT, INSERT, UPDATE` on `passkeys` to
`coffre_app`, `SELECT` to `coffre_backup` (or `pnpm test:schema` fails),
nothing to the vault's logins. The previous release ignores all of it and
keeps working while the migration runs ahead of the deploy.

`pnpm test:compat` keeps the newest release conformant on this schema.

## 6. The session model

### 6.1 One lock, and revocation, not derived history

Three review rounds found holes wherever the design inferred, from
timestamps or from what a passkey had confirmed, whether a credential
should still work. So it no longer infers. It writes the answer down, under
one lock:

**The person's factor lock.** A transaction-scoped lock per person:
`pg_advisory_xact_lock` on a hash of the principal, which any login can take
inside its transaction, and on SQLite the database's one writer. Every
transaction that issues a credential of a person's (a browser session, a
CLI session at its poll, a personal token, a handle, an MCP connection) or
decides a device login takes it, and so does every change to the person's
passkeys. Under it, every issue re-checks what it is issued from and what
it names:

- **its source is still live**: the session or token the request came in
  on (a personal token's, a handle's, an MCP consent's, a fresh check's, a
  removal's), the pending sign-in's member and generation, or the device
  approval a poll redeems. A change that ended the source before the lock
  was taken leaves the issue nothing to issue from;
- **its passkey**: a credential no passkey confirms is refused when the
  person has a live passkey (unless the policy is `off`), and one that
  names a passkey no longer live is refused.

Today, MCP consent (`McpService.decide`) re-checks only membership, and a
handle's issue only the person; both gain the source check.

**Changes end credentials by revoking them**, in the same transaction:

| Change | Ends |
|---|---|
| A first passkey added (a person with none live) | every credential of the person's that names no passkey, and every pending device approval that names none |
| A passkey removed by its person | every credential and pending device approval of the person's, but the new session issued to the browser that removed it (rule 1): "Removing a passkey signs you out everywhere else" |
| An Owner's reset | every credential and pending device approval of the person's |

Removing a passkey ends everything, not only what that passkey confirmed:
any session could have been confirmed by any of the person's passkeys at
some point, and "everywhere else" is a rule a person can predict.

That leaves no way back for a credential no passkey stands behind. Bob's
terminal from before the first passkey was revoked when Bob added it, and
stays revoked when an Owner later resets Bob's passkeys. A device code Bob
approved without a passkey is denied when Bob adds one, so its poll redeems
nothing. A session made while the policy was `off` is refused while its
person has a live passkey (below), and revoked by the next removal or
reset, which is the only way to stop having one.

### 6.2 The check at every request

Every credential of a person's that the API or MCP takes (a browser or CLI
session, a personal token, an MCP connection) passes one check, in the
statement that already reads it, with a primary-key join on the passkey it
names and an indexed `EXISTS` on the person's live passkeys:

| Policy | It names a passkey | It names none |
|---|---|---|
| `off` | taken | taken |
| `optional` | taken if that passkey is live | taken if the person has no live passkey |
| `required` | taken if that passkey is live | refused |

A credential refused so gets `401 passkey_required`. A browser page goes to
`/auth/passkey?step-up=1`, where a touch issues a new, confirmed session
(rule 1); the CLI says to `coffre login` again; a personal token or an MCP
client is made again by its person.

With 6.1, the check refuses what the revocations have already ended; it is
there for what no change marks: sessions made before the deployment turned
`required` on, and sessions made while `off` for a person who has a passkey.

### 6.3 Handles

Handles are the one kind not checked per request: they reach `/use` only,
which R44 and R58 keep to one statement. So the revocations of 6.1 carry
them, which needs every handle issue under the person's lock. Today a
handle is issued by the vault's own statement (`vault.issueToken`, with
the app's audited transaction as the fallback) and records only its person,
in `created_by`; signing out does not end it. The vault's issue contract
grows: it takes the person's lock, checks under it that the session or
personal token issuing the handle is still unrevoked (6.1 revokes those
first), and copies that credential's `passkey_id` onto the handle. Its
statement and its model change with it (R45). A handle is then either ended
by a change or made after it, from a credential the change left alive.

What escapes: a handle made while the policy was `off` lives out its
lifetime, 12 hours unless asked and a week at most, unless a removal or a
reset ends it.

### 6.4 Named reveals

A reveal of one key (`POST /api/reveals` with one key, a plugin's read)
goes to the vault first, by name, and checks its credential on the rows the
vault answers (`useByName`, `packages/server/src/named-use.ts`). That path
holds that whatever the app refuses of a credential, the vault refuses
first, before anything that hangs on the key, and its one answer for every
refusal (D153, `formal/Probing.tla`). The ordinary path does not: it
resolves the key before it decides on the caller.

So the named path stays, for people too, and the passkey check goes before
it: for a person's credential, while passkeys are not `off`, the app runs
the check of 6.2 in one statement before the vault call. The statement
reads the credential and the person's passkeys, nothing about the key, so
a refusal says nothing about the key and costs the same whatever was
asked. A passkey removed between that statement and the vault's call
revoked the credential (6.1), which the vault checks itself
(`credentialStill`). The cost is one statement before a person's one-key
reveal; the later way to save it is to teach the vault's named statement
the check, through `accepts`, as `named-use.ts` asks of any new check, with
`Probing.tla`'s `AcceptedFirst`.

### 6.5 Fresh, and replacing a session

**Fresh** is `confirmed_at` within five minutes. Only a touch sets it, on a
credential that touch issued: a browser session at sign-in, at a step-up, a
fresh check or a device approval; a CLI session from its device approval.

**A touch replaces the session it came in on, once.** The transaction that
issues the new session first ends the old one, conditionally (`revoked_at
IS NULL`), and aborts if that changes no row. Two tabs that both touch on
the same session: one replaces it, the other aborts and answers `401`, and
its page reloads with the jar's new cookie and asks again if it still needs
to. A request in flight with the old cookie gets `401` and the page retries
once with the new one.

**The new session keeps the old one's sign-in.** It carries the old
session's `identity_id` and `expires_at`: the browser's absolute lifetime
runs from the provider sign-in that started the chain, and only another
provider sign-in starts a new one. Touching a passkey every few minutes
never puts off signing in to GitHub again.

`GET /api/me` answers `passkeys: { policy, enrolled, confirmedUntil }`, which
the pages read to decide when to open the dialog before sending.

**Why a new session per touch, not a column updated in place.** Updating
the session's `confirmed_at` would refresh every copy of its token: a
cookie stolen at 09:00 would wait for Ada's touch at 10:02 and promote
someone at 10:03. A new token, set only in the response to the browser that
touched, leaves the copy behind, ended. It also keeps every MAC written
once.

**Why not a separate "fresh" cookie** (a sealed `coffre_fresh` cookie bound
to the session): it would need no new credential per check, but it does
not reach the CLI, and it cannot answer "which passkey confirmed this
credential", which the check above needs.

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
  (a secure context, and a valid RP ID) for a person's browser. Through a
  tunnel (`COFFRE_DEV_PUBLIC_URL`), the RP ID is the tunnel's host: a
  passkey added there does not work on `localhost`, and the reverse. Dev
  passkeys are throwaway; Chrome's DevTools virtual authenticator is
  enough for manual tests.
- **The seed** (`dev/seed.mjs`) adds members, changes access and issues a
  service token, all **always**, so under the dev deployment's `optional` it
  needs a passkey too. `dev/browser.mjs`, which the seed and the restore
  drill share, gains the software authenticator of section 9: each persona
  it signs in adds a passkey at its first risky act, and touches it at
  each check. The dev stack keeps the policy people will run, and the seed
  exercises the passkey path every time it runs.

### 7.2 What each response must hold

The W3C's relying-party algorithms, [Registering a new
credential](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential)
and [Verifying an authentication
assertion](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion),
are the checklist. Each of their steps maps to a line of the verifier and a
negative fixture that fails it. What applies here, in order, any failure
refusing:

For an assertion:

1. The sealed state opens, is unexpired, and is for this purpose (`signin`,
   `check`, `device`) and, for `check` and `device`, this credential, and for
   `device` this device authorization. Each purpose has its own HKDF key,
   so one purpose's state never opens as another's.
2. The response is well formed: `type` is `public-key`, `id` is the
   base64url of `rawId`, every field decodes, nothing trails.
3. The credential ID is a live passkey of this principal and generation,
   read now: another member's passkey, or one removed since the options
   were sent, is unknown here.
4. `userHandle`, when the authenticator returns one, equals the passkey
   row's `user_handle`.
5. `clientDataJSON.type` is `webauthn.get`; `challenge` equals the
   state's; origin and `crossOrigin` as in 7.1.
6. `authenticatorData` is at least 37 bytes; `rpIdHash` is SHA-256 of the
   `rpId`; flags: UP set, UV set, BS set only with BE set; AT clear; ED, if
   set, followed by well-formed CBOR, whose extensions are ignored.
7. The signature verifies over `authenticatorData ‖ SHA-256(clientDataJSON)`
   with the stored key and algorithm. ES256 signatures arrive DER-encoded
   and are turned into the raw form WebCrypto takes.
8. The counter and the replay mark move, in one statement (7.3).

For a registration, steps 1, 2 and 5 (with `webauthn.create`), then:
`authenticatorData` with AT set, UP and UV set, BS only with BE; the
attested credential ID 16 to 1023 bytes and unused across the instance and
by this person (`excludeCredentials` is the browser's courtesy, not a
check); the COSE key one of the three algorithms asked for, with valid
parameters (EC2 on P-256, OKP Ed25519, RSA of at least 2048 bits), its
`alg` matching; and the `enroll` or add rules of sections 3.2 and 3.6.
Attestation is `none`: the attestation statement is ignored, whatever its
format. Coffre trusts the browser for which key was made, as every relying
party that does not restrict authenticator models does.

### 7.3 Challenges and replay

Challenges are 32 random bytes in a sealed value: a cookie at sign-in, where
there is no session yet, and a field of the JSON for a check or a device
approval, bound to the session's credential ID. Nothing is stored for a
challenge.

Stateless challenges can be answered twice within their five minutes, so
the passkey's row holds the issue time of the newest challenge it answered,
and an assertion is taken only by moving it forward, with the counter, in
one statement inside the transaction that makes what the touch is for:

```sql
UPDATE passkeys
   SET last_challenge_at = $issued, sign_count = $count, last_used_at = now()
 WHERE id = $id AND principal = $principal AND generation = $generation AND removed_at IS NULL
   AND (last_challenge_at IS NULL OR last_challenge_at < $issued)
   AND (sign_count < $count OR ($count = 0 AND sign_count = 0))
```

No row: replayed, overtaken by a newer challenge, a counter that did not
move (a possible clone, logged as such), or a passkey removed meanwhile; all
refused. Two tabs asking at once: the older one's touch is refused and it
asks again. The statement is the write the counter needs anyway, so replay
costs nothing extra. A use and a removal of the same passkey both hold the
person's lock (section 6.1): either the removal comes first and the use
matches no row, or the use comes first and the removal ends what it made.

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
  each **always** route without a confirmation, and the sign-in routes the
  table does not cover.
- Misses: an app taken over. It can skip the check.

**B. The app's claim, sealed for the vault.** The credential's
`confirmed_at` becomes part of its sealed object (in 0.15, credentials are
sealed objects of the log already), and the vault refuses `setAccess`,
issues and role changes without it.

- Catches: an app bug that skips the router's check, as the vault catches
  permission bugs today.
- Misses: an app taken over, which issues itself a credential "confirmed
  now". The vault cannot tell a touch happened.
- Costs: the vault's decisions read one more field, the TLA+ and Lean
  models grow (R45), and the rule lives in two places.

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
verifier in `@coffre/core`, passkeys bound to members and generations, and
the device ceremony's shape (an assertion bound to one target).

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
- `authenticatorData` and `clientDataJSON` parsing, and the checks of 7.2,
  step by step against the W3C's algorithms;
- COSE keys to WebCrypto: EC2 P-256, OKP Ed25519, RSA; and ES256's DER
  signatures to raw;
- `crypto.subtle.verify`, which both runtimes have; core already verifies
  DPoP proofs this way.

It is held by: the W3C spec's examples and SimpleWebAuthn's own test
fixtures, copied as data; one negative fixture per step of 7.2; a software
authenticator (P-256 and Ed25519, in the test helpers, `dev/browser.mjs`
and `@coffre/conformance`) that makes real registrations and assertions; and
property tests where a flipped bit in any signed byte, a changed origin or
a changed RP ID must fail. The choice is worth revisiting if that checklist
grows past what 300 lines hold; the library stays the fallback.

The browser side needs no library:
`PublicKeyCredential.parseRequestOptionsFromJSON`, `parseCreationOptionsFromJSON`
and `credential.toJSON()` where the browser has them, and a base64url
helper of a dozen lines where it does not.

## 10. Cost

Against R42 (a handful of queries, no chain of round trips), R27 (well under
10 ms CPU at p50) and R44/R58 (the hot paths). These are counts from the
design and estimates, not measurements: PR 3 measures sign-in and a check
with `pnpm bench:workers` before it merges.

**Signing in with a passkey**, against today's sign-in:

| Step | Queries | CPU |
|---|---|---|
| Callback | 1: identity, member and "has a live passkey", one statement. Today's `completeSignin` no longer runs here. | one seal |
| `/auth/passkey` page | 1: the person's live passkeys (IDs, transports), in the render | one unseal |
| `POST /auth/passkey` | 1: the passkey the assertion names (key, counter); then today's `completeSignin` (its reads, the vault's `access`, its prepared change, its transaction), with the replay statement inside that transaction | one signature check, CBOR parsing, one unseal |

So two statements and one read more than today, none of them chained to
another but the passkey read before the signature check, plus two more
browser round trips (the page and its post), one of them the person's touch.

**A fresh check**: `POST /api/passkeys/challenges` reads the person's live
passkeys (1 query); `POST /api/passkeys/checks` reads the passkey (1), checks
the signature, then issues the new session as a sign-in does (the vault's
prepared change for the new credential and the old one's end, and one
transaction: the conditional end of the old session, the replay statement,
the insert, the entries). About a sign-in's issue; at most once per five minutes per
person.

**Every other request**: no query more. The statement that reads the
credential gains a primary-key join on `passkeys` and an indexed `NOT
EXISTS`, for the four kinds of section 6 only; the decision is a
comparison. The exception: a person's one-key reveal runs that check as a
statement of its own before its named vault call (section 6.4). Issues take
the person's lock, an advisory lock no other request waits on.

**`/use`, CI and workload sign-in**: nothing. Their statements do not
change.

A P-256 or Ed25519 verification should cost well under a millisecond of
WebCrypto in either runtime; that is the number to measure.

## 11. Audit

New actions, in the shared log as `account.link` and `device.approve` are:

| Action | When | Metadata |
|---|---|---|
| `passkey.add` | a passkey is added: at a first sign-in, from Account | passkey ID, name, AAGUID, synced |
| `passkey.remove` | its person removes one | passkey ID, credentials and apps ended |
| `passkey.reset` | an Owner resets someone's | target, passkey IDs, credentials and apps ended |
| `passkey.check` | a fresh check or a step-up, allowed or denied | passkey ID, purpose, the session ended and the one issued; on deny, the reason: `origin`, `rp_id`, `challenge`, `replay`, `unknown_credential`, `user_handle`, `signature`, `counter`, `user_verification`, `malformed` |

Changed:

- `sign_in` entries name the passkey that confirmed them. A passkey that
  fails at sign-in writes no entry: whoever answered passed the provider
  but not the factor, and section 3.1 promises such a visitor writes
  nothing. The reason goes to the process log (`console.warn`, with the
  principal and the reason above), as a provider's failures do today.
  `passkey.check` denials are entries: they come from a session.
- `device.approve` names the passkey that approved.
- Every **always** act names, in its own entry, the passkey and time that
  confirmed the session (`confirmedBy`, `confirmedAt`).

A `403 fresh_check_required` or `401 passkey_required` is not logged.

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
5. One purpose's state completes no other: a sign-in's no check, a check's
   no device approval, a device approval's no other code.
6. An assertion without UV, or with BS set and BE clear, is refused.
7. A provider sign-in that stops before the passkey sets no session cookie,
   and the next request with what it did set is `401`.
8. A browser session with no passkey reaches nothing but `GET /api/me`, the
   passkey routes and sign-out.
9. Every **always** route answers `403 fresh_check_required` to a session
   confirmed more than five minutes ago, and none of them changes anything.
10. After a fresh check, the session it came in on is `401`.
11. A fresh session approves no device code without that code's own
    assertion.
12. A device code approved with a passkey, then the passkey removed, redeems
    nothing.
13. A second `enroll` with the same sealed state adds nothing.
14. Linking another provider account from a session not confirmed in the
    last five minutes is refused, at the start and at the callback.
15. A removed passkey signs nobody in, and every credential it confirmed is
    `401`.
16. `/use` and `POST /api/auth/workload` answer as they did, with no
    passkey anywhere.
17. A CLI session made before a first passkey stays `401` after that
    passkey is reset.
18. A handle made by a session no passkey confirmed is `401` at `/use`
    once its person adds a first passkey; every handle of a person's is,
    once they remove a passkey.
19. A one-key reveal by a credential the passkey check refuses gets the
    same `401` whether the key exists, is sensitive or was never made, and
    the log holds no use of it.
20. Two fresh checks on one session: one new session, one `401`.
21. A session made at a fresh check expires when the one before it would
    have.
22. Under `required`, on an empty database and on a cold vault, the Owner
    the config names signs in, adds a passkey and lands; a provider sign-in
    that stops at the passkey admits no one and writes nothing.
23. A device code approved without a passkey redeems nothing once its
    person adds a first passkey, whatever happens to that passkey after.
24. `?dryRun=1` on a route that takes none, from a session not confirmed in
    the last five minutes, is `403 fresh_check_required` and changes
    nothing.
25. An MCP consent whose session a removal ended meanwhile connects
    nothing.
26. Under `protectedReveals`, a stale session's one-key reveal in a
    protected environment answers as for a key it cannot see, whether the
    key exists or not, and the log holds no use of it; the same for a
    several-key reveal (`POST /api/reveals` with `keys`) and an
    environment's, by a stale session, a personal token or an MCP client;
    a reveal that starts before the environment is protected and releases
    after releases nothing, on each path.
27. The configured Owner of check 22 signs in again with the passkey added
    there.

## 14. Build plan (phase 2, after 0.15)

1. **The verifier**, in `@coffre/core/identity`, with its vectors, a
   negative fixture per step of 7.2, the software authenticator and
   property tests. No wiring.
2. **Storage**: the migrations, the schema, the MAC kinds, `pnpm
   test:schema` and the backup grant.
3. **Sign-in**: `signin({ passkeys })`, the callback's split, `/auth/passkey`
   and its page, enrolling under `required`, the configured Owner's first
   sign-in and `vault.configuredOwners()`, the person's lock and the
   revocations of section 6.1, the per-request check, the vault's handle
   issue under the lock (and its model), the check before named reveals,
   the step-up, the seed's authenticator. Waits for #436 and
   T171, which touch the callback.
4. **Fresh checks**: `FRESH_ROUTES`, the challenges and checks routes, the
   dialog, the device ceremony, the CLI's step-up through the device flow,
   the link checks, MCP approvals that stay pending.
5. **Management**: Account → Passkeys, the Owner reset, the prompt under
   `optional`.
6. **`protectedReveals`**: `fresh`, required on every value-releasing call
   of the `Vault` interface (`useNamed`, `use`, `useMany`, `unwrap`),
   decided under the policy fence, `Probing.tla` and the use matrices, the
   clients asking first from `GET /api/me`.
7. **Conformance** checks of section 13, and docs: `docs/deployment-auth.md`
   (the policy, `rpId`, recovery and its log review) and
   `docs/offboarding.md`.

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
7. **How much do passkey changes sign out?** Proposed (section 6.1):
   adding a first passkey ends everything no passkey confirmed, and
   removing one signs the person out everywhere else. Bob's terminals log
   in again and Bob's tokens are made again; in exchange nothing a stolen
   GitHub account made earlier survives, and no rule has to work out what a
   removed passkey once confirmed. Option: end only what the removed
   passkey confirmed, which needs that lineage tracked exactly, the source
   of three rounds of review findings.
8. **The vault (section 8).** Proposed: A now, C designed with the vault's
   next model for Owner-level acts. Option: C in phase 2 for promotion to
   Owner only.
