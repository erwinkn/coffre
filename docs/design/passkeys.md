# Passkeys: a second factor at sign-in, and a fresh check for risky acts

A passkey (WebAuthn: platform and synced passkeys, security keys) is a second
factor that coffre holds, on top of the sign-in provider (GitHub, Google,
Entra, any OIDC). It never signs anyone in alone, so removing someone at the
provider still cuts them off. There is no TOTP and no SMS. The deployment's
config sets the policy, `off`, `optional` (the default) or `required`. A
fresh check, a passkey touch within the last five minutes, guards risky acts.

## In one page

| | `off` | `optional` (default) | `required` |
|---|---|---|---|
| Sign-in, no passkey yet | provider only | provider only (Owners add one first, section 2) | provider, then add one before any session exists |
| Sign-in, has a passkey | provider only | provider + passkey | provider + passkey |
| Changing access, issuing service credentials | no check | a touch in the last 5 minutes; no passkey yet: add one first | a touch in the last 5 minutes |
| Approving a terminal, connecting an MCP client, approving its change | no check | a touch for that act, if you have a passkey | a touch for that act |
| Reading values | no check | no check | no check |
| `/use`, CI and workload sign-in, services | untouched | untouched | untouched |

Three rules carry it:

1. **A touch that opens a window issues a new session.** A touch at sign-in,
   at a step-up or at a fresh check issues a new session to the browser that
   touched and ends the one it came in on, so a copy of the old cookie stops
   working. A touch for one act (approving a terminal, connecting an MCP
   client, approving its change) approves that act alone: it opens no window
   and leaves the session as it was.
2. **Changes to a person's passkeys end credentials by revoking them**, under
   one per-person lock that the vault's issue takes too, and every request
   checks that a live passkey still stands behind its credential (section 6).
   Nothing is inferred from timestamps, so nothing revoked comes back.
3. **The app decides; the vault carries the passkey on what it issues**
   (section 8).

The pieces: one table, `passkeys`, and nullable columns that name a passkey
on `credentials`, `device_logins` and `mcp_connections` (section 5); the
passkey page, `/auth/passkey`, and its API, `GET` and `POST
/api/auth/passkey`, for the sign-in's second step, the step-up and a
removal; `GET`, `POST`, `PATCH` and `DELETE /api/members/:member/passkeys[/:id]`;
`FRESH_ROUTES`, typed over the route table, so a new route fails the
typecheck until it says whether it needs a fresh check (section 4.5); and a
verifier of coffre's own over WebCrypto (section 9).

## 1. What it stops, and what it does not

The cast: Ada is an Owner, `admin@acme.example`; Bob is a Developer,
`bob@acme.example`; coffre runs at `https://secrets.acme.example` and signs
people in with GitHub.

- **A stolen provider account.** Someone phishes Bob's GitHub. They pass
  GitHub, land on "Confirm it's you", and stop: coffre wrote nothing, and
  their browser holds a sealed cookie that expires in five minutes.
- **A real-time phishing proxy.** `secrets-acme.example` relays Bob's sign-in
  and asks for his passkey. The browser refuses: a passkey for
  `secrets.acme.example` answers only that origin. TOTP cannot give this.
- **A stolen session cookie.** Malware lifts Ada's cookie at 09:00. It reads
  what Ada reads, but cannot promote anyone, issue a service token, approve
  a terminal or connect an MCP client. When Ada next touches a passkey, her
  browser gets a new session and the stolen one ends (rule 1).

What it does not stop:

- **The first passkey is trust on first use.** Whoever passes the provider
  first, when a passkey must be added, adds it. A first passkey is only
  added in a sign-in, right after the provider vouched (section 3.4), so a
  stolen cookie alone cannot add one.
- **A stolen provider account before its person has a passkey.** Under
  `optional`, an attacker with Bob's GitHub signs in and adds a passkey. That
  ends Bob's sessions, terminals and tokens (section 6.1), and Bob is locked
  out until an Owner resets. It is loud (a `passkey.add`, Bob locked out);
  `docs/deployment-auth.md` says what to do. Owners add one at their next
  sign-in (section 2), which shortens this window but does not close it.
- **An app fully taken over** can skip its own checks. The vault does not
  verify passkeys (section 8).
- **A cookie stolen right after a touch** gets the rest of that five-minute
  window: the price of not touching per act.
- **Device-code phishing.** A code phished from Ada and approved in her
  browser gives the attacker a 30-day CLI session. The touch binds approval
  to a code, not to a terminal.
- **Malware that stays** reads every new cookie. A passkey proves a touch,
  not a clean device.
- **Reads**, in a protected environment too (section 4.3), and deployments
  behind **Cloudflare Access** (section 12).

## 2. The policy

Passkeys are an option of `signin()`, beside `providers`:

```ts
auth: signin({
  providers: [github({ app, organization: 'acme' })],
  passkeys: 'required', // 'off' | 'optional' (default) | 'required'
  // or { policy: 'required', rpId: 'acme.example' }, to name a parent of the host (section 7.1)
}),
```

`coffre init` writes the policy read from the app's `PASSKEYS` variable
(`app/wrangler.jsonc`, `.env`), so turning passkeys off for recovery (section
3.7) is a variable and a deploy.

### Does "required for Owners" fall out?

There is no fourth mode. Under `optional`, every act that changes access or
issues a service credential needs a fresh check, which needs a passkey, so
whoever manages access ends up with one. That would leave an Owner who has
changed nothing since unprotected. So under `optional`, **an unscoped Owner,
and an Owner the deployment names, sign in as under `required`**: they add a
passkey at their next sign-in (`#afterProvider`,
`packages/server/src/api/signin.ts`).

## 3. The flows

### 3.1 Signing in with a passkey

Ada has two passkeys, "YubiKey 5C" and "iCloud Keychain".

1. `/login` → Continue with GitHub → `GET /auth/callback/github`.
2. The callback verifies GitHub's answer and reads, in one round trip, the
   identity (`findIdentity`), the members the account may be
   (`signinMembers`: status, generation, passkeys ever and live) and the
   Owners the deployment names (`deploymentOwners`). Ada holds a live
   passkey, so no session yet: the callback sets a sealed five-minute cookie,
   `__Host-coffre_passkey`, and redirects to `/auth/passkey`:

   ```ts
   type PendingFactor = {            // packages/server/src/api/ceremony.ts
     purpose: 'signin' | 'enroll';
     account: { provider: string; issuerHash: string; subject: string; email: string | null; name: string | null };
     principal: string;              // 'user:admin@acme.example'
     generation: number;             // the membership the step is for
     next: string;                   // where to land
     challenge: string;              // 32 random bytes, base64url
     issuedAt: number;               // ms; the replay mark (section 7.3)
     passkeysEver: number | null;    // enroll: how many passkey rows the person ever had (section 3.2)
   };
   ```

3. The page asks `GET /api/auth/passkey` for the options (the challenge, the
   RP ID, Ada's live passkeys, `userVerification: 'required'`), and its button
   calls `navigator.credentials.get` at once, since a touch must follow the
   click.
4. `POST /api/auth/passkey` with the assertion checks it (section 7) and runs
   `completeSignin` from the cookie's account, which re-reads everything it
   decides on. Inside its transaction it moves the passkey's replay mark
   (section 7.3), on a passkey still live and Ada's at that generation, ends
   any session cookie of Ada's the browser came in with, and issues a session
   with `passkey_id` = the YubiKey and `confirmed_at` = now.

Rules the cookie keeps:

- **It holds only what the provider vouched for.** Someone who passed GitHub
  but not the passkey leaves no row behind. The callback writes nothing, the
  vault included: an Owner the deployment names with no member row yet gets
  an `enroll` cookie at `generation: 0`, and is admitted at the `POST`, once
  the passkey has verified.
- **The issuer is sealed** (`issuerHash`). If the deployment replaced the
  issuer behind the same provider ID within those five minutes, the sign-in
  is refused (`state_mismatch`); otherwise one issuer's proof would be bound
  as the other's.
- **It names one membership.** A person removed and readmitted within the
  five minutes has another generation, and the cookie is refused.
- **It fits.** A profile whose sealed cookie would pass the 4,096 bytes a
  browser must keep (`COOKIE_BYTES`) ends the sign-in with
  `profile_too_long`, rather than set a cookie the browser drops silently.

**A lost answer is sent again, never made again.** An answer with no clear
refusal (no response, a 5xx, a 408 or 429, a `409 changed`, a body cut off)
clears nothing: the page sends the same answer again (`passkeyAnswer`,
`packages/ui/src/lib/passkey-answer.ts`). It never calls `create()` or
`get()` twice for one set of options. Why: an authenticator keeps one
discoverable credential per RP ID and user handle, so a second `create()`
can replace the passkey coffre just stored with one it never saw. The page
also keeps the step's five-minute deadline itself (`withinDeadline`), since
browsers treat `timeout` as a hint.

**Bounds.** The body is read to `SIGN_IN_BODY_BYTES` (413 past it). CBOR is
decoded with an explicit stack, so nesting costs no call stack, and every
decoded item counts toward `MAX_BODY_NODES`, the count the API holds a JSON
body to. Without that count, a megabyte of nested one-byte maps decoded to
more memory than a Worker's isolate has.

There is no fallback that skips the passkey: the page says "Lost your
passkeys? An Owner can reset them" (section 3.7).

### 3.2 The first sign-in under `required`

Bob was invited and signs in for the first time. The callback finds his
member row and no passkey, so the cookie's `purpose` is `enroll` and the page
says "Add a passkey to finish signing in". Its button calls
`navigator.credentials.create` with Ed25519, ES256 and RS256 (`-8`, `-7`,
`-257`), `residentKey: 'preferred'`, `userVerification: 'required'`,
`attestation: 'none'`, and the person's live passkeys excluded.

`POST /api/auth/passkey` then, in one transaction, takes the person's factor
lock (`lockFactor`) and the log's head, links the GitHub account, adds the
passkey, ends what no passkey stands behind (section 6.1) and issues the
session; entries `account.link`, `passkey.add`, `sign_in`.

**An `enroll` state adds a first passkey only, and only once.** Under the
lock it reads every passkey row of the person's, removed ones included,
holds each to its MAC, and requires that none is live and that their count
still equals the sealed `passkeysEver` (`passkeyHistory`). Example: an
attacker saves Bob's `enroll` cookie and registers a key; an Owner resets
it; within five minutes the attacker uses the cookie again. "No live
passkey" alone would let that through; the count, which only grows since
rows are never deleted, does not. It reads rows rather than a count so that
a removal forged in the database refuses the sign-in (`tampered`) instead of
letting another passkey be "first".

**The user handle** (`user.id`) is 16 random bytes, drawn for each GET of
the options, sealed in the step's state (`CreateState`) and stored on the
row (`passkeys.user_handle`). Random bytes reveal nothing about the person,
as WebAuthn asks, and survive an `APP_KEY` rotation. A fresh one per
`create()` means two tabs or a reload never replace each other's passkey. An
interrupted attempt can leave a passkey on the device that coffre never
stored; coffre never offers it (`allowCredentials` names only the passkeys
it holds), so nobody is locked out.

A credential ID some passkey already has is refused `passkey_failed`; the
unique index decides it.

### 3.3 `optional`: the prompt

Bob, with no passkey under `optional`, signs in with GitHub alone. Projects
shows "Add a passkey. Signing in will then take GitHub and a touch of your
passkey, so a stolen GitHub account is not enough." Not now hides it in this
browser for 30 days (`coffre-passkey-later`). Adding a first passkey (by
signing in again, section 3.4) gives this browser a new confirmed session,
ends Bob's other credentials for good (section 6.1), and makes his next
sign-in ask for it.

### 3.4 A fresh check in the browser

Ada promotes Bob to Owner at 10:02; her session was confirmed at 08:15.

1. Save sends `PATCH /api/access/user:bob@acme.example`. The route is
   **always**, the session is past its window: `403 fresh_check_required`,
   nothing written.
2. The browser's API client hears it for every page at once
   (`freshTransport`, `packages/ui/src/lib/fresh.ts`) and opens "Confirm
   it's you" (`FreshCheck`), which fetches the step-up's options as it opens.
3. Ada touches the YubiKey. `POST /api/auth/passkey` ends the old session,
   moves the replay mark and issues a new one confirmed at 10:02.
4. The act goes again, once, with one more header: the refusal named its
   caller, and the retry says it (`coffre-caller`). A retry naming another
   caller is refused `409 conflict`, `reason: 'caller_changed'`. Example:
   another tab signs in as Bob meanwhile, and the dialog's touch confirms
   Bob's session; Ada's change, sent again on Bob's cookie, is refused rather
   than made as Bob.
5. At 10:05 Ada issues a service token: no prompt. At 10:09: prompted again.

Acts refused together share one dialog and one touch.

**No passkey yet, under `optional`.** The refusal carries `reason:
'add_passkey'`; the dialog offers to sign in again with `?passkey=add`
(`/auth/signin/<provider>?passkey=add&next=<page>`), whose sign-in enrolls as
an Owner's does (`PendingState.addPasskey`). A first passkey is never added
from an existing session, Account → Passkeys included: the provider has
always vouched for the person a moment before, and one code path adds a
first passkey.

`GET /api/me` answers `passkeys: { policy, enrolled, confirmedUntil }`.

### 3.5 The CLI

**Approving a terminal.** `coffre login` is a device login. Approve, `POST
/api/device-logins/:code { approve: true }`, is a **ceremony** (section
4.2): one touch approves one code, recorded as `device_logins.passkey_id`,
and the browser's session stays as it was. The poll (`POST
/api/auth/device/token`) issues the CLI session with that passkey and the
approval's `decided_at` as its `confirmed_at`, so a new terminal starts
inside a five-minute window. Under the log's head the poll checks that the
approval stands and its passkey is live: a passkey removed, or a first one
added, between approval and poll redeems nothing. The CLI session lasts its
own 30 days: a terminal has no provider sign-in to inherit a lifetime from.

**A fresh check.**

```console
$ coffre access set bob@acme.example --role owner
This change needs a touch of your passkey. Approve it in your browser:

  https://secrets.acme.example/auth/device?code=QJXM-4WTP

Waiting for approval... approved.
bob@acme.example is now an Owner.
```

On `403 fresh_check_required`, a session `coffre login` saved starts a
device login labelled `coffre CLI: <the command>` (a secret is never an
argument, so the label holds none), waits for the touch, swaps in the new
session, signs the old one out and retries (`steppingUp`,
`packages/cli/src/main.ts`). It first asks whose the saved session is
(`whoseSession`), and replaces it only if it is still the session the command
started on. With `reason: 'add_passkey'` it says to add one in the browser.
A token or a CI run's credential answers the refusal as any other.

`coffre run`, `export`, `set`, handles and personal tokens never need a
check. A personal token made from the CLI holds at most what its session
holds, and names its passkey.

### 3.6 Adding, renaming and removing passkeys

Account → Passkeys (`/account/passkeys`) lists one's own: name, provider,
whether it syncs, added, last used.

- **List**, `GET /api/members/:member/passkeys`: one's own, or anyone's for
  an unscoped Owner: `{ passkeys, ends, reset, max }`, `ends` counting what a
  removal or a reset would end. A row failing its MAC refuses the read
  (`409 tampered`) rather than list fewer.
- **Add another**, **always**: `POST …/passkeys/options`, then `POST
  …/passkeys { state, response }`, which under the factor lock and the head
  requires that the session still stands and the person's passkeys are as
  they were when the options were asked. It ends nothing: every credential of
  theirs names a passkey already. Browser sessions only, never under `off`.
  The options last no longer than the session stays fresh. An add whose
  answer was lost, sent again, answers `409 passkey_exists`, which the dialog
  takes as done.
- **At most 10** per person (`MAX_PASSKEYS`).
- **Rename**, `PATCH …/passkeys/:id { name }`: 1 to 64 characters, no check
  (a name grants nothing and is outside every MAC).
- **Remove** replaces the browser's session (rule 1), so it goes through the
  passkey page: `GET /api/auth/passkey?remove=<id>` asks a touch of another
  live passkey, or of this one if it is the last under `optional`, or none
  under `off`; under `required` the last one answers `409 last_passkey`.
  `POST /api/auth/passkey`, under the factor lock and the head, ends the
  session it came in on first (of two removals on one session, one goes),
  removes the passkey, ends every other credential, connection and approved
  terminal code of theirs, and issues the new session. The dialog says what
  ends: "Removing YubiKey 5C signs you out of 3 other sessions and ends 1
  personal token."
- **Names**: the provider's, from the AAGUIDs passkey providers publish
  (`packages/server/src/passkey-names.ts`), else "Passkey <n>", `n` one more
  than every passkey row the person has had. Security keys publish theirs in
  FIDO's metadata service, which coffre does not read, so a YubiKey is
  "Passkey <n>" until renamed.

### 3.7 Recovery

**One of two lost.** Ada signs in with iCloud Keychain and removes the
YubiKey, which ends her other sessions.

**All lost.** Bob asks an Owner, who opens Users → Bob → ⋯ → Reset
passkeys… The reset, `DELETE /api/members/:member/passkeys`, is **always**:

- Only an unscoped Owner resets, signed in as themselves (not through a
  token or an MCP connection), only someone else, and only someone who holds
  a live passkey (`409 no_passkeys`). A project's Owner resets nobody:
  passkeys belong to the instance.
- Under the target's factor lock and the head it removes every live passkey
  (`removed_by` = the Owner), ends everything they are signed in with, and
  writes `passkey.reset`. It costs the same round trips for one passkey as
  for ten (`change-cost.test.ts`).
- The Owner is held, under the head, to the vault's answer when the reset
  started (`issuerNow`, `issuerStill`; `formal/Issuing.tla`'s
  `IssuerFence`): demoted meanwhile, they reset no one (`409
  access_changed`).

Bob's next sign-in asks for a new passkey under `required`; under `optional`
GitHub alone signs him in. Either way he sees "Ada reset your passkeys on 31
Oct". That notice is read from the rows (the newest removal by someone else,
while he holds none). `removed_by` is outside the row's MAC, so a database
writer could fake or hide it: the notice informs, the log's `passkey.reset`
is the record.

**The last Owner, every passkey lost.** Keep two unscoped Owners. With no
other, the deployer sets `passkeys: 'off'` and redeploys; Ada signs in with
GitHub alone, removes the lost passkeys (no touch under `off`), and the
deployer puts the policy back. There is no reset command and no exemption:
recovery adds no concept of its own. While `off` lasts, a provider account is
enough for everyone, so it should last minutes. Credentials made meanwhile
name no passkey: once the policy is back they are refused for anyone who has
a passkey (section 6.2), and their next removal or reset revokes them;
handles made meanwhile live out their lifetime. What such a session did
stays, so `docs/deployment-auth.md`'s recovery ends with reading the log for
the `off` window. `off` deletes no rows.

## 4. What needs a fresh check

A fresh check means the session was confirmed by a touch in the last five
minutes (`FRESH_MS`). The rule: **it guards what widens someone's reach,
mints a credential, or cannot be undone.** Removing access, revoking,
freezing and protecting never need one: in an incident they must be quick.

Five answers (`Fresh`, `packages/server/src/api/fresh-routes.ts`):

- **always**: a fresh session; no passkey under `optional`: add one first.
- **holder**: a fresh session if the caller has a passkey; nothing otherwise.
- **ceremony**: a touch of its own, for that act alone (section 4.2).
- **handler**: the handler decides, from what it reads anyway, before it writes.
- **never**.

Under `off`, and for a service, nothing is asked. Only a browser or CLI
session is ever fresh, never a personal token or an MCP connection.

### 4.1 always

| Route | Why |
|---|---|
| `PUT` / `DELETE /api/members/:member` | adds a member with a role and grants; removing an Owner is the other way to demote one |
| `PATCH /api/access/:member` | grants, instance role, Owner promotion and demotion |
| `PUT` / `DELETE /api/roles/:role`, `/api/instance-roles/:role` | what every holder of a role may do |
| `PUT /api/settings` | where people may set up service accounts |
| `POST /api/members/:member/tokens`, for a service | a service token |
| `POST …/bindings`, `POST …/bindings/keys`, `POST …/enrollments`, `…/promote` | what a CI run or a workload signs in with |
| `POST /api/members/:member/tokens/:id/approve` | a workload's session waiting for a person |
| `DELETE /api/freezes/:target` | lifting a freeze lets its uses through again |
| `PATCH /api/projects/:project/:environment` with `protected: false` | unprotecting |
| `DELETE /api/projects/:project`, `DELETE …/:environment` | erasing for good (not one's own personal config) |
| `POST /api/audit/loss` | accepting lost log entries for good |
| `POST …/passkeys/options`, `POST …/passkeys`, `DELETE …/passkeys` | another passkey; resetting someone's |
| `PATCH /api/secrets/…` that marks a sensitive value a secret | **handler**: below |

`?dryRun=1` skips the check only on the routes that take it, when the
parsed query says so. `PATCH /api/access/:member` takes none: a `?dryRun=1`
there is ignored and the change made, so it is checked as usual.

**Loosening a key.** Marking a sensitive value a secret in place makes a
value people could not read readable. The write's handler reads each key's
level (`marking`) and refuses before writing. A new value with a looser level
needs nothing: it is new, and older versions keep their level.

### 4.2 holder and ceremony

| Route | Answer | Why |
|---|---|---|
| `POST /api/device-logins/:code` with `approve: true` | ceremony | a 30-day CLI session (section 3.5) |
| `POST /api/oauth/authorizations` with `approve: true` | ceremony | an MCP client's refresh token |
| `POST /api/approvals/:id` with `approve: true` | ceremony | a change an MCP client asked for (4.4) |
| `POST /api/members/user:<self>/tokens` from a browser session | holder | a personal token outlives the browser session; from a CLI session, never |
| `GET /auth/signin/:provider?link=1`, and its callback | holder | another account that signs in as you (section 4.5) |

**A ceremony asks for its touch in its own refusal**, so no page needs to
know beforehand who holds a passkey. Ada presses Approve: the route answers
`403 touch_required` with `touch: { options, state }`, the state sealed under
a key of its own (`passkey-state/act/v1`) naming the act (that code), her
session and her generation. The page asks the authenticator and sends
Approve again with `touch: { state, response }` (`pressTouch`). The route
verifies the assertion before any transaction (`SigninService.touchFor`); a
failure is `403 touch_failed` with a denied `passkey.check`. The act's own
transaction moves the replay mark and writes `passkey.check` with the act's
entry; a mark that does not move (the same answer again, the passkey removed
meanwhile) rolls the act back. A caller with no passkey under `optional` is
asked nothing. An MCP change binds its touch to what the page showed (the
change's digest, basis and a digest of the value); a connection, to the
request and the scopes chosen.

Why it replaces no session: the act cannot be approved twice, so a copy of
the cookie has nothing to ride. The cost: a copy of Ada's cookie taken at
12:00 still reads after her 12:01 touch, as it could at 11:59.

### 4.3 Reads

`POST /api/reveals` and every other read are **never**. Protected
environments keep their rule: a role that may use or write a key but not
read it cannot reveal it, by any credential. Passkeys add nothing to reads.

### 4.4 Who is never asked, and who cannot be

- **Services** (service tokens, CI exchanges, workload sessions) hold no
  passkey. What a service may do was fixed when its token or binding was
  made, which is a fresh check.
- **Personal tokens and MCP connections** have nothing to touch. The fixed
  **always** routes are out of their reach (`PERSONAL_TOKEN_ROUTES`,
  `ROUTE_SCOPES`); one that turns **always** by its input is refused
  `fresh_check_required`, and the person does it signed in.
- **An MCP client's change** is approved in the person's browser. A
  five-minute window would not stop an agent driving that browser right after
  the person's own touch, so Approve is a **ceremony** for anyone with a
  passkey, for every change. Each change says what its route answers
  (`Change.fresh`), and `#decide` holds the person to it first: with no
  passkey under `optional`, an **always** change is refused `add_passkey` and
  stays pending. The change then runs through the router as the approving
  session, which takes the approval's touch for the window
  (`McpVia.touched`); one approved with no touch is checked as the session
  is, so a wrong `Change.fresh` fails closed.
- **Handles and `/use`**: never.

### 4.5 In code, and the routes outside the table

```ts
// packages/server/src/api/fresh-routes.ts
export const FRESH_ROUTES: { [K in RouteKey]: Answer<K> } = {
  'PATCH /access/:member': 'always',
  'PATCH /projects/:project/:environment': ({ input }) => (input.protected === false ? 'always' : 'never'),
  'POST /device-logins/:code': ({ input }) => (input.approve ? 'ceremony' : 'never'),
  'PATCH /secrets/:project/:environment': 'handler',
  // … every route
};
```

An answer is a constant, or a function of the parsed `params`, `input`,
`query` and the session. The router asks it after the route's own `needs`
and before the handler (`requireFresh`); MCP approvals ask it of the change
they would make. A route whose handler checks permissions itself prompts
first: a Developer who may not add members is asked to touch, then refused.
A refusal writes no audit entry (it is a prompt, and a script on a stolen
cookie meets one every try): one process-log line with the principal, the
route and the credential.

The sign-in routes (`auth-routes.ts`) check for themselves:

| Route | Check |
|---|---|
| `GET /auth/signin/:provider?link=1` | holder: outside the window, the step-up first, which comes back here (`stepUpNext`) |
| `GET /auth/callback/:provider` for a link | holder again: still the same person, still fresh; else nothing linked, `/account?error=link_stale` |
| `POST /api/auth/device/token` (the poll) | the approving passkey still live, in the issuing transaction (section 3.5) |
| `POST /api/oauth/token` (an MCP refresh) | the connection's passkey still live (section 6.2) |
| `POST /auth/signout`, `POST /api/auth/logout`, `POST /api/auth/oidc`, `POST /api/auth/workload` | never |

No type holds these, so conformance checks the link and the poll (section 13).

## 5. Storage

### 5.1 `passkeys`

| Column | What |
|---|---|
| `id`, `auth_mac` | the row and its MAC |
| `principal`, `generation` | whose, and the membership it was added in (FK `principals`) |
| `user_handle` | 16 random bytes, per `create()` (section 3.2) |
| `credential_id` | raw, 16 to 1023 bytes, unique across the instance |
| `public_key`, `algorithm` | the COSE key; -8 Ed25519, -7 ES256, -257 RS256 |
| `sign_count` | the authenticator's counter, a uint32; 0 for synced passkeys |
| `last_challenge_at` | the replay mark (section 7.3) |
| `transports`, `aaguid`, `synced`, `name` | display only; name 1 to 64 characters |
| `created_at`, `created_by` | the person, or `system:signin` at a first sign-in |
| `last_used_at` | |
| `removed_at`, `removed_by` | both or neither: the person, or the Owner who reset it |

Indexes: `passkeys_live_idx` (principal, generation, live only), for the
per-request check, the sign-in and the Passkeys tab; `passkeys_principal_idx`,
every passkey a person has had, for `passkeyHistory`.

**What is signed.** The MAC (`passkeys` in `packages/server/src/auth-rows.ts`)
covers id, principal, generation, user handle, credential ID, public key,
algorithm and `removed_at`. So a database writer cannot add a passkey, swap a
key or forge a removal. The counter, replay mark, name, transports and last
use are outside it. A writer who lowers the counter or the replay mark could
let a captured assertion through again, but that writer can already read all
it would reveal.

**Rows are never deleted.** `coffre_app` has no `DELETE` on `passkeys`, and
updates only the counter, replay mark, name, last use, removal and MAC; never
whose it is, its handle, credential or key
(`packages/db/test/schema-guarantees.sql`, check 22). A removed passkey keeps
its row, so credentials and log entries can still name it. A member's
removal moves their generation past their passkeys: someone removed and added
back starts with none. `APP_KEY` rotation re-signs these rows.

### 5.2 The columns that name a passkey

| Table | Columns | Set on |
|---|---|---|
| `credentials` | `passkey_id`, `confirmed_at` | browser and CLI sessions get both; what they make (personal tokens, service tokens, handles) copies `passkey_id` alone |
| `device_logins` | `passkey_id` | an approval only; its `decided_at` is when |
| `mcp_connections` | `passkey_id` | the passkey touched to connect it; under `off`, the session's own |

A row that names a passkey is signed with the kind `confirmed_<table>`, which
covers these fields, so a writer can neither vouch a passkey for an old
session nor swap one. They are written once, when the row is made: a touch
issues a new credential, never updates one, so no MAC is re-signed on a
check. The MAC's row type requires `passkeyId` (and `confirmedAt` on
credentials), so an issue site that forgets one does not compile.

Ada's credentials at 10:03:

| Credential | `kind` | `passkey_id` | `confirmed_at` | Fresh? |
|---|---|---|---|---|
| Firefox, issued at the 10:02 check | browser | YubiKey 5C | 10:02 | yes, until 10:07 |
| Firefox, the one before it | browser | YubiKey 5C | 08:15 | ended at 10:02 |
| Safari, phone | browser | iCloud Keychain | 07:40 | no |
| CLI, laptop | cli | YubiKey 5C | 09:15 | no |
| `cursor-agent` personal token | personal | YubiKey 5C | null | never |
| Chrome, from before `required` was turned on | browser | null | null | refused (section 6.2) |

Fresh is derived, never stored.

### 5.3 Migrations

`0063_passkeys` adds the table, the columns and their checks: `confirmed_at`
only with a passkey and only on a browser or CLI session; a device login's
passkey only on an approval (`decision IS NOT NULL`, since a pending row's
NULL would otherwise pass), so such a login ends by `consumed_at`, never by
turning `denied`. Grants: `SELECT, INSERT` and the column `UPDATE`s of 5.1
to `coffre_app`, `UPDATE (passkey_id)` on `device_logins`, `SELECT` to
`coffre_backup`, nothing to the vault's logins. `0072_passkeys_principal`
adds `passkeys_principal_idx`; `0073_passkeys_in_vault` lets the vault's
named use read passkeys (section 6.4).

## 6. The session model

### 6.1 One lock, and revocation, not derived history

**The person's factor lock** is `pg_advisory_xact_lock(1717658484,
hashtext(<principal>))`. A change to a person's passkeys takes it first
(`audited`'s `factor`), then the log's head, then the rows. The vault's
`issue_token`, which issues personal tokens, handles and service tokens,
takes it first too (section 6.3). Why a lock beyond the head: the vault's
issue takes no head, and without the lock a removal could read the person's
credentials, then wait while a handle commits from a source it is about to
revoke, and miss it (`formal/Factor.tla`).

**The app's own issues take the head** (a sign-in, a poll, an MCP consent, a
token on the app's path), and a change takes it right after the factor lock,
so one commits before the other reads. Without that, a sign-in committing
between a change's read and its commit is missed (`Factor.tla`'s `FactorApp`
scenario, `ChangeEndsAll`). Under the head each issue checks (`sourceStands`,
`AppIssueChecks`) that its source (the credential it came in on, the pending
sign-in's member, the approval a poll redeems) is still live, and the passkey
rule: a credential no passkey confirms is refused while the person has a live
one (unless `off`), and one naming a removed passkey is refused.

**Changes end credentials by revoking them**, in the same transaction:

| Change | Ends |
|---|---|
| A first passkey added | every credential of the person's that names no passkey, and approved, unredeemed device codes that name none |
| A passkey removed by its person | every credential, connection and approved device code of theirs but the new session of the browser that removed it |
| An Owner's reset | every credential, connection and approved device code of theirs |

Removing one passkey ends everything, not only what it confirmed: any session
could have been confirmed by any passkey, and "everywhere else" is a rule a
person can predict.

The app revokes the rows itself (`revokeCredentialsWhere`). The vault's log
entries for them are prepared before the transaction (`AppChanges.prepare`),
since no app transaction stays open across a vault call; the transaction
re-reads under the lock what to end, and retries if it differs.

So nothing comes back. Bob's terminal from before his first passkey stays
revoked after a reset. A device code he approved without a passkey is denied
when he adds one. A session made while `off` is refused while he holds a
passkey, and revoked by his next removal or reset.

### 6.2 The check at every request

Every browser or CLI session, personal token and MCP connection of a
person's passes one check (`passkeyStands`,
`packages/server/src/passkey-check.ts`):

| Policy | It names a passkey | It names none |
|---|---|---|
| `off` | taken | taken |
| `optional` | taken if that passkey is live | taken if the person has no live passkey |
| `required` | taken if that passkey is live | refused |

Live: not removed, still its holder's at the credential's generation, its MAC
intact. Refused: `401 passkey_required` and a process-log line; a browser
goes to the step-up, the CLI says to `coffre login` again, a token or MCP
client is made again. The revocations of 6.1 end what a change marks; this
check is for what none marks: sessions from before `required`, or from an
`off` window (`Factor.tla`'s `RequestChecks`; without it `ServedBacked`
fails). A passkey row that fails its MAC is no step-up: it throws
`AuthRowTampered`, refused as any tampered auth row. Handles, services'
credentials and workload sessions are not checked (`passkeyChecked`).

**It costs no statement, but in one case.** The statement that reads the
credential (`credentialRow`) joins the passkey it names by primary key and
asks the two indexes whether the person holds a live passkey, rows but none
live, or none ever. "Rows but none live", for a credential naming none, reads the rows in
one statement more (`passkeyHistory`) and holds each to its MAC, so a removal
forged in the database does not pass a session made while the passkey was
live. That statement is paid on each request of a person readmitted after
holding passkeys and holding none since. An MCP connection's read
(`findConnection`) does the same on every call and refresh.

A use by name (`useByName`, `useManyByName`), a key write (`writeAhead`) and
a member's add (`admitAhead`) read their credential in the vault's call,
which reads the same passkey rows in the same statement (`passkeyOf`), so
they keep their round trips (`change-cost.test.ts`,
`proxy-use-cost.test.ts`):

- **A use by name** releases values, so the vault decides first: the app's
  policy goes in `NamedUseInput.accepts.passkeys`, and the statement holds the
  credential to the table above, without the MACs, before reading anything
  of the key (`formal/Probing.tla`'s `AcceptedFirst`). Refused, the request
  falls to the ordinary path, which answers `401 passkey_required` (6.4).
- **A key write and an add** commit nothing without the app's transaction.
  The app's check on the rows the vault answered (`write_request`,
  `admit_read`) refuses before that transaction, and what the vault prepared
  is dropped (`passkey-check.test.ts`).

What a request issues names its credential's passkey, never a touch
(`confirmed_at` null). What an MCP connection issues names the connection's
passkey and goes the app's way, where `sourceStands` checks the connection.

What no MAC answers: a passkey row deleted or moved to another principal.
`coffre_app` cannot make either write; a login above it that does makes the
person read as one who never had a passkey.

### 6.3 Handles

Handles are not checked per request: they reach `/use` only, which stays one
statement. So the revocations of 6.1 carry them, which needs every handle
issue under the factor lock. The vault's `issue_token` takes the lock first,
before the members' rows; checks the issuing credential (`via`) against its
seal, unrevoked, unexpired, of the person's generation; and checks that `via`
names exactly the passkey the issue carries (`p_passkey`), live and the
issuer's. Otherwise it answers `ended` and writes nothing. The vault never
copies the passkey from `via` itself: the row's MAC is the app's, made before
the call. Signing out does not end the handles a session made; a handle made
while `off` lives out its lifetime unless a removal or reset ends it.

### 6.4 Named reveals

A one-key reveal (`POST /api/reveals`, a plugin's read) goes to the vault
first, by name (`useByName`, `packages/server/src/named-use.ts`). That path
holds that whatever the app refuses of a credential, the vault refuses first,
before anything that depends on the key, with one answer for every refusal
(`formal/Probing.tla`). So the passkey check goes first in it: the vault reads
the credential and the person's passkeys before the key, and a refusal says
nothing about the key and costs the same whatever was asked. Taken, the use
answers the passkey rows, which the app holds to their MACs. A passkey change
that leaves none behind the credential revokes it (6.1), and the vault checks
revocation itself (`credentialStill`).

### 6.5 Fresh, and replacing a session

**Fresh** is `confirmed_at` within five minutes. Only a touch sets it, on a
credential that touch issued: a browser session at sign-in or step-up, or a
CLI session from its device approval.

**The step-up.** A page whose `GET /api/me` answers `401 passkey_required`,
or a fresh check (3.4), uses `/auth/passkey?step-up=1&next=…`. `GET
/api/auth/passkey?step-up=1` answers a touch of the person's live passkeys
with a state bound to the session (`StepUpState`), or 404 with none live.
`POST /api/auth/passkey` checks the touch (`SigninService.stepUp`), then in
one transaction ends the old session, moves the replay mark and issues the
new one, with `passkey.check` entries.

**Once per session.** The old session is ended conditionally (`revoked_at IS
NULL`) and the transaction aborts if that changes no row. Two tabs touching on
one session: one replaces it, the other gets `401` and reloads with the new
cookie. A touch whose challenge can no longer move the replay mark ends the
step-up (`state_mismatch`), rolled back, the old session standing.

**The new session keeps the old one's sign-in**: identity and `expires_at`.
The browser's lifetime runs from the provider sign-in, so touching a passkey
never puts off signing in to GitHub again.

**Why a new session per touch, not `confirmed_at` updated in place:** an
update would refresh every copy of the token, so a cookie stolen at 09:00
would wait for Ada's 10:02 touch and promote someone at 10:03. A new token,
set only for the browser that touched, leaves the copy behind, ended, and
keeps every MAC written once.

## 7. The ceremony, checked

### 7.1 Relying party and origin

- `rpId` is `publicUrl`'s host unless the config names a parent of it.
  Startup checks it is the host or a suffix on a label boundary with at least
  two labels. coffre does not ship the public suffix list (it changes weekly,
  costs 130 KB per isolate, and a copy out of step with the browser's
  disagrees with it), so `workers.dev` passes startup and the browser refuses
  it at the first passkey; the page says `passkeys.rpId` must be the host or a
  registrable parent. A `publicUrl` on an IP address with a policy other than
  `off` fails at startup: no browser would make a passkey there.
- The origin in `clientDataJSON` must equal `publicUrl`'s origin exactly,
  whatever `rpId` is: with `rpId: 'acme.example'`, an assertion phished by
  `evil.acme.example` fails. `crossOrigin` false or absent, `topOrigin`
  absent.
- **Moving coffre to another host, or changing `rpId`, orphans its
  passkeys**, unless `rpId` was a parent covering both from the start. Under
  `required` the way back is `off`, then everyone re-adds.
- **The dev stack** serves browsers at `http://localhost:<port>`
  (`dev/start.sh`), a valid RP ID where `127.0.0.1` is not.
  `COFFRE_DEV_PASSKEYS` sets the policy (`optional` unless said). The Owner
  adds a passkey at the seed's sign-in; `dev/browser.mjs` keeps the keys in the
  stack's state, and `node dev/passkey.mjs <DevTools WebSocket URL>` lends the
  Owner's to a Chrome, writing its counter back after each touch so no count
  goes backwards (7.3). Through a tunnel (`COFFRE_DEV_PUBLIC_URL`) the RP ID is
  the tunnel's host.

### 7.2 What each response must hold

The W3C's relying-party algorithms, [Registering a new
credential](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential)
and [Verifying an authentication
assertion](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion), are
the checklist; each step has a line of the verifier and a negative fixture.
For an assertion, in order, any failure refusing:

1. The sealed state opens, is unexpired, is for this purpose and, for a
   step-up or an act, this session and act. Each purpose has its own key
   (`CeremonyStates`).
2. The response is well formed: `type` `public-key`, `id` the base64url of
   `rawId`, every field decodes, nothing trails.
3. The credential ID is a live passkey of this principal and generation, read
   now.
4. `userHandle`, when present, equals the row's; an empty one is refused.
5. `clientDataJSON.type` is `webauthn.get`, `challenge` the state's, origin as
   in 7.1.
6. `authenticatorData` is at least 37 bytes; `rpIdHash` is SHA-256 of the
   `rpId`; UP and UV set, BS only with BE, AT clear; ED, if set, followed by
   well-formed CBOR.
7. The signature verifies over `authenticatorData ‖ SHA-256(clientDataJSON)`
   (ES256's DER signatures turned raw for WebCrypto).
8. The counter and replay mark move (7.3). If not, no touch can answer this
   challenge again, so the sign-in ends (`state_mismatch`) rather than ask
   for touches that cannot pass.

For a registration: 1, 2 and 5 (with `webauthn.create`), then AT, UP and UV
set, BS only with BE; the credential ID 16 to 1023 bytes and unused
(`excludeCredentials` is the browser's courtesy, not a check); the COSE key
one of the three algorithms with valid parameters (P-256, Ed25519, RSA of
2048 to 4096 bits: a larger modulus would spend a Worker's CPU on one
verify); and sections 3.2 and 3.6. Attestation is `none` and its statement
ignored: coffre trusts the browser for which key was made.

### 7.3 Challenges and replay

A challenge is 32 random bytes in a sealed value (the cookie at sign-in, a
JSON field otherwise); nothing is stored per challenge. So the same answer
could be sent twice within five minutes. The passkey's row holds the issue
time of the newest challenge it answered, and an assertion counts only by
moving it forward, with the counter, in one statement inside the transaction
that makes what the touch is for (`touchPasskey`,
`packages/server/src/db/queries.ts`):

```sql
UPDATE passkeys
   SET last_challenge_at = $issued, sign_count = $count, last_used_at = now()
 WHERE id = $id AND principal = $principal AND generation = $generation AND removed_at IS NULL
   AND (last_challenge_at IS NULL OR last_challenge_at < $issued)
   AND (sign_count < $count OR ($count = 0 AND sign_count = 0))
```

No row: replayed, overtaken by a newer challenge, a counter that did not move
(a possible clone), or a passkey removed meanwhile. Of two tabs asking at
once, the older one's touch is refused and it asks again. The counter needs
this write anyway, so replay protection costs nothing.

### 7.4 User verification

`userVerification: 'required'`: a fingerprint, face or PIN, never presence
alone, which would let anyone at an unlocked laptop with a plugged-in key
confirm an Owner change. Not a setting: `USER_VERIFICATION` in
`@coffre/core/identity` is the one place it is spelled. The verifier checks
it last (the order is in the header of `packages/core/src/identity/webauthn.ts`),
so a `user_verification` refusal means every other check passed.

## 8. The app authenticates, the vault authorizes: where the check lives

`architecture.md`: "The app decides who someone is. The vault decides what
they may decrypt." A passkey is about who, so the app decides: the router
enforces `FRESH_ROUTES`, and the vault does not verify passkeys. The vault
carries them: `issue_token` copies the issuing credential's passkey onto what
it issues, under the factor lock (6.3), and the named use applies the app's
rule where the app's own check would come too late (6.2). `FRESH_ROUTES` is
typed over the route table and conformance checks every **always** route, so
the app cannot forget the check silently. An app taken over can skip it;
sealing the app's "confirmed" claim for the vault would not help, since that
app would issue itself a credential "confirmed now". Only a vault that
verifies an assertion over the exact change would stop it, and coffre has
none.

## 9. The verifier: our own, not `@simplewebauthn/server`

`@simplewebauthn/server` bundles to 312 KB (88 KB gzipped) for its two verify
functions, from 10 dependencies, nearly all for attestation certificate
chains coffre never asks for; `reflect-metadata` patches a global. Each is a
pin under the release-age rule, and the bundle is parsed in every cold
isolate.

coffre's is `packages/core/src/identity/webauthn.ts` (`verifyRegistration`,
`verifyAssertion`): a CBOR decoder for WebAuthn's subset (definite lengths
only), `authenticatorData` and `clientDataJSON` parsing and the checks of 7.2,
COSE keys to WebCrypto, and `crypto.subtle.verify`. It is held by the W3C's
examples and SimpleWebAuthn's fixtures as data
(`packages/core/test/vectors/webauthn.json`), one negative fixture per step
of 7.2 (`packages/core/test/webauthn.test.ts`), property tests where a flipped
signed bit, origin or RP ID must fail
(`packages/core/test/webauthn-properties.test.ts`), and a software
authenticator, `@coffre/conformance/authenticator`, which makes real Ed25519,
P-256 and RSA registrations for the tests, the dev seed and conformance.
Measured on Node 24: one assertion costs 0.25 to 0.3 ms of CPU.

A refusal names the check that failed: `malformed`, `type`, `challenge`,
`origin`, `rp_id`, `user_presence`, `user_verification`, `backup_state`,
`credential`, `user_handle`, `algorithm`, `key`, `signature`; the caller adds
`unknown_credential`, `replay` and `counter`. The browser side needs no
library (`PublicKeyCredential.parseRequestOptionsFromJSON` and its kin).

## 10. Cost

- **Sign-in with a passkey**: the callback's one round trip of reads (3.1),
  the page's read of live passkeys, and the `POST`'s read of the passkey
  before `completeSignin`, the replay statement inside its transaction
  (`signin-cost.test.ts`). Two more browser round trips, one the touch.
- **A fresh check** is a step-up, about a sign-in's issue, at most once per
  five minutes per person.
- **Every other request**: no statement more, but for the one case of 6.2.
  Issues take the person's lock, which no other request waits on.
- **`/use`, CI and workload sign-in**: unchanged.

## 11. Audit

| Action | When | Metadata |
|---|---|---|
| `passkey.add` | at a sign-in, or from Account | passkey ID, name, AAGUID, synced |
| `passkey.remove` | its person removes one | passkey ID, what ended |
| `passkey.reset` | an Owner resets someone's | target, passkey IDs, what ended |
| `passkey.rename` | its person renames one | passkey ID, name |
| `passkey.check` | a step-up or an act's touch, allowed or denied; a removal's touch, denied | passkey ID, purpose, sessions ended and issued; on deny, the reason (section 9) |

`sign_in` and `device.approve` name the passkey. A passkey failing at
sign-in writes no entry (that visitor passed only the provider, and writes
nothing): the reason goes to the process log. A request let through on a
touch records what confirmed it, `ApiContext.confirmed`, a `Confirmation` `{
by, at }` (for an MCP change, the approval's touch, `McpVia.touched`). The
app's entries carry it beside `credentialId`; every vault call carries it in
its correlation, which the vault copies into its entries; a first add's change
and a token's issue keep it in their payloads under the vault's MAC. It is
recorded, never weighed. `403 fresh_check_required` and `401
passkey_required` write no entry (section 4.5).

## 12. Behind Cloudflare Access

With `cloudflareAccess()`, Access keeps the browser's session and
`cloudflared` the CLI's; coffre has no credential row to mark. Passkeys are an
option of `signin()` only, so there are none, and no fresh checks, behind
Access. Access's own policies, MFA among them, cover sign-in.

## 13. Conformance

`packages/conformance/src/checks/passkeys.ts` holds every deployment to
these, and cites them by number. The deployment boots under `optional`, as
`coffre init` writes it; the harness restarts it with another `PASSKEYS`,
`PUBLIC_URL` or issuer where a check needs one. 22, 7 and 27 run under
`required` from cold; 8, 16 and 19 under `required`; the rest under
`optional`.

1. An assertion for another origin is refused.
2. An assertion whose `rpIdHash` is another RP ID's is refused.
3. One assertion sent twice with its state signs in once.
4. Another member's passkey answers no sign-in or check of this member's.
5. One purpose's state completes no other: a sign-in's no check, a check's no device approval, a device approval's no other code.
6. An assertion without UV, or with BS set and BE clear, is refused.
7. A sign-in that stops before the passkey sets no session; what it did set is `401`.
8. Under `required`, a session with no passkey gets `401 passkey_required` on every API call, `/api/me` included; signing out works.
9. Every **always** route refuses a session confirmed over five minutes ago, `403 fresh_check_required`, changing nothing.
10. After a step-up, the session it came in on is `401`.
11. A fresh session approves no device code without that code's own touch.
12. A device code approved with a passkey, then the passkey removed, redeems nothing.
13. A second `enroll` with the same state adds nothing.
14. Linking an account from a session not fresh is refused, at the start and at the callback.
15. A removed passkey signs nobody in, and every credential it confirmed is `401`.
16. `/use` answers as before through handles, one from a person with no passkey under `optional` included; services and workload sign-in work under `required`.
17. A CLI session made before a first passkey stays `401` after that passkey is reset.
18. A handle no passkey confirmed is `401` once its person adds a first passkey; every handle of a person's is, once they remove one.
19. A one-key reveal by a refused credential gets the same `401` whether the key exists, is sensitive or never was, and logs no use.
20. Two step-ups on one session: one new session, one `401`.
21. A session from a step-up expires when the one before it would have.
22. Under `required`, on an empty database and a cold vault, the configured Owner signs in, adds a passkey and lands; a sign-in that stops at the passkey leaves no session, identity, passkey or member of its own.
23. A device code approved without a passkey redeems nothing once its person adds a first passkey, whatever happens to it after.
24. `?dryRun=1` on a route that takes none, from a session not fresh, is `403 fresh_check_required` and changes nothing.
25. An MCP consent whose session a removal ended meanwhile connects nothing.
26. A role that may use a protected key but not read it reveals nothing, from a fresh session as from a token or an MCP client.
27. The configured Owner of 22 signs in again with that passkey.
28. A pending sign-in or enrollment whose issuer was replaced under the same provider ID completes nothing.
29. An `enroll` state used once, its passkey reset, used again within five minutes, enrolls nothing.
30. Under `optional`, an unscoped Owner without a passkey adds one at sign-in; a Developer does not.
31. An MCP approval or consent from a fresh session, without its own touch, decides nothing; the approval stays pending.
32. Marking a sensitive value a secret from a session not fresh is `403 fresh_check_required` and writes nothing; keeping the level goes.
33. A `publicUrl` on an IP address, passkeys not `off`, does not start.
34. An MCP-approved service token issues with its approval's touch, and that touch approves nothing after.
35. Handles issued while removals of their person's passkey run are revoked or refused, never live after.
