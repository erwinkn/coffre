# Passkeys: a second factor at sign-in, and a fresh check for risky acts (T176)

Written on 2026-10-31, phase 1 of T176: the design and a mock of its screens
([passkeys-mock/index.html](passkeys-mock/index.html)). Erwin approved
building it for 0.16 on 2026-11-03; section 14's PRs land in order, and
he answered section 15's questions on 2026-11-03 (D170), which this
document now follows. Built so far: the verifier (PR 1, section 9), the
storage (PR 2, section 5), the vault's issue under the factor lock
(PR 3, section 6.3), what holds a credential to its passkey, at every
request and every issue (PR 4a, sections 6.1, 6.2 and 6.4), the sign-in
(PR 4b), the fresh checks (PR 5), and managing passkeys, the API's side
(PR 6a, sections 3.6 and 3.7).

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
  credentials. Reading a value is not one, in a protected environment or
  any other (D170 dropped `protectedReveals`, section 4.3).
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
| `/use`, CI and workload sign-in, services | untouched | untouched | untouched |

Three rules carry it:

1. **A touch that opens a window issues a new session.** A passkey touch
   in a browser at sign-in, at a step-up or at a fresh check issues a new
   session to the browser that touched, and ends the one it came in on. A
   copy of the old cookie, wherever it went, stops working. A touch for
   one act (approving a terminal, connecting an MCP client, approving its
   change) approves that act alone and opens no window, so it leaves the
   session as it was: nothing it made is there for a copy to ride (as
   built in PR 5a, section 4.2). Nor does it refresh the browser's own
   window: approving a terminal at 12:01 leaves a window that closed at
   12:00 closed, and the next risky act asks a touch of its own (PR 5b).
2. **Changes to a person's passkeys end credentials by revoking them,
   under one per-person lock that every issue takes too, and every request
   checks that its credential still has a live passkey behind it** (section
   6). A first passkey ends what no passkey confirmed; removing or
   resetting one signs the person out everywhere else. Nothing is inferred
   from timestamps, so nothing revoked comes back.
3. **The app decides; the vault only carries the passkey on what it
   issues** (section 8). The vault could verify passkey signatures itself
   later, for Owner-level acts.

The pieces:

- **One new table**, `passkeys`, and nullable columns: `passkey_id` and
  `confirmed_at` on `credentials`, `passkey_id` on `device_logins`
  and `mcp_connections`. All additive: one migration per engine.
- **Sign-in routes**: `GET` and `POST /auth/passkey`, between the provider's
  callback and the session. Until the passkey answers, coffre writes
  nothing: what the provider vouched for waits in a small sealed cookie,
  as `PendingSignin` does today.
- **API routes**: `GET`, `POST`, `PATCH` and `DELETE
  /api/members/:member/passkeys[/:id]`. A touch for one act rides the
  act's own route (`403 touch_required`, section 4.2), and a fresh check
  is the step-up's door (section 6.5), so neither has a route of its own.
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
- **A stolen provider account, before its person has a passkey.** Under
  `optional`, an attacker with Bob's GitHub signs in and adds a passkey at
  once; that ends Bob's own sessions, terminals and tokens (section 6.1),
  and Bob's next sign-in asks for a passkey Bob does not have. Today the
  attacker would share Bob's access; here they hold it alone until an
  Owner resets. It is loud (a `passkey.add`, Bob locked out), and
  `docs/deployment-auth.md` says what to do: confirm with Bob out of band,
  reset, read the log since the `passkey.add`. Owners add one at their next
  sign-in (section 2), which brings their protection forward but does not
  remove the risk: whoever passes an Owner's provider first after the
  upgrade adds that passkey.
- **Device-code phishing.** The touch binds approval to a code, not to a
  terminal: a code phished from Ada, approved in Ada's browser, yields the
  attacker a 30-day CLI session, as today. The page shows where the
  request came from; it cannot know whose terminal it is.
- **Malware that stays.** Software on Ada's machine that reads every new
  cookie gets every new session. A passkey proves a touch, not a clean
  device.
- **Reads.** Revealing a value needs no passkey (Erwin's call), in a
  protected environment too (section 4.3).
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

One gap remains, on the accounts that matter most: an Owner who has changed
nothing since the upgrade has no passkey yet, so an attacker with that
Owner's GitHub account signs in, adds their own passkey at the first risky
act, and proceeds. So under `optional`, **an unscoped Owner, and an Owner
the deployment names, sign in as under `required`**: they add a passkey at
their next sign-in. It costs one column of the row the callback already
reads (the instance role), not a fourth mode. Open question 2.

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
     account: { provider: string; issuerHash: string; subject: string; email: string | null; name: string | null }; // name cut to 100 characters
     principal: string;             // 'user:admin@acme.example'
     generation: number;
     next: string;                  // where to land, a path of at most 512 characters, or '/projects'
     challenge: string;             // 32 random bytes, base64url
     issuedAt: number;              // ms; also the replay guard (section 7.3)
     passkeysEver: number | null;   // enroll: how many passkey rows the person had, removed ones included (section 3.2)
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
   re-reads and re-checks everything it decides on. The account's
   `issuerHash` is the issuer that verified it, sealed at the callback:
   `completeSignin` would otherwise take the issuer from the configuration
   as it is now, so a deployment that replaced the issuer behind the same
   provider ID within those five minutes would have one issuer's proof
   bound as the other's. A sealed hash that no longer matches the
   configured provider's refuses the sign-in (`state_mismatch`), and the
   person starts again. Inside its transaction,
   before the session is written, it moves the passkey's counter and replay
   mark (section 7.3), conditional on the passkey still being live and
   still Ada's, at the generation `completeSignin` resolved. The session
   carries `passkey_id` = the YubiKey and `confirmed_at` = now. The cookie
   is cleared, the session cookie set, and Ada lands on `next`.

The cookie carries what GitHub vouched for and nothing coffre decided.
Someone who passed GitHub but not the passkey leaves no row behind, and an
unauthenticated visitor makes coffre write nothing, as today. Precisely:
nothing a visitor sends is written. A cold deployment's first request of
any kind, a visitor's included, still runs what every request's door runs
before any route (`cutoverReady`, which may settle the vault through
`vault.about()`): the cutover, the vault's own settling, and the admission
of the Owners the config names. That writes only what the deployment's
code and data already decide, the same whoever asks, and is outside this
design.

**The callback writes nothing, the vault included.** Today a first sign-in
can admit a member: `#principalForEmails` asks `vault.access`, which makes
an Owner the deployment names (`owners`, R3) a member when they are none
yet, on an empty instance too. Under passkeys the callback only reads: it
matches the email against the members' rows and the deployment's `owners`
(`vault.about().owners`; the settling `about()` can do on a cold vault is
the door's, which ran before the callback, below). An Owner named in config with no
member row yet gets an `enroll` cookie with `generation: 0`, a first
admission's; the `POST` admits them through `vault.access`, as today, once
the attestation has verified, and enrolls only if the vault answered that
generation. A cookie names a membership, never "whichever comes": one
whose person the vault admitted, removed and admitted again within its
five minutes is at generation 1 by then (a removal moves the generation, a
readmission keeps it), and refuses, `state_mismatch` (review r3 of #500). Conformance runs
`required` on an empty database and on a cold vault (section 13).

The page also says what to do without the passkey: "Lost your passkeys? An
Owner can reset them" (section 3.7). There is no fallback that skips it.

**As built (PR 4b).** The page is `/auth/passkey`, a page of the
deployment's Start app (`@coffre/ui/pages/passkey`), so what it asks and
its answer are `GET` and `POST /api/auth/passkey` (`passkeyStep` in
`packages/server/src/auth-routes.ts`): the page reads the question in the
browser, which alone can answer it, and its button asks the browser at
once, as a touch must follow the click. The answer sets the session
cookie and says where to go (`{ next }`); a passkey that did not answer
leaves the sign-in to try again, with another passkey too, and any other
refusal clears the cookie. An answer that is no refusal (no response, a
5xx such as `503 unavailable` or `migrating`, a 408 or 429, a body that
does not parse, or a `409 changed`, another change having come between
each of the transaction's tries, review r6; a 401 or 409 whose body did not
arrive whole, as those are the statuses whose refusals may keep the step,
review r7) clears nothing, so the page says coffre did not answer and
asks again rather than send the person back to their provider
(`passkeyAnswer`, `packages/ui/src/lib/passkey-answer.ts`). Asking again
sends the same answer, never a second `create()` or `get()` from the same
page (`sendPasskey`, review r7): the page's options name one user handle,
and a second `create()` with it can replace, on a discoverable
authenticator, the passkey the first POST added though its answer was
lost (Chrome's virtual authenticator does), which the server would refuse
as `passkey_exists`, leaving the person a key coffre does not hold. Sent
again, the first passkey completes the step, or, its enrollment having
committed, ends it with `passkey_exists`, and they sign in again with the
key their device holds. Every GET of an enrollment's options draws a user
handle of its own (D173; section 3.2): sealed in the GET's `state`
(`CreateState`), which the POST sends back and whose handle the row
stores. Two tabs of one sign-in, or the page reloaded, never hand
`create()` the same handle, so neither replaces the passkey the other
added. A page asks the authenticator to `create()` once per options:
after `passkey_failed`, which keeps the step, it asks coffre for new
options before the next press (`sendPasskey`'s `once`, review r13). The
refusal says nothing of the answers sent before it: tab A's POST commits
and its answer is lost, tab B's sign-in replaces the pending cookie, and
A's answer, sent again, fails B's challenge; a second `create()` from A's
options would name the handle coffre now holds. What an interrupted attempt can leave is a passkey on the device
that coffre never stored: a second tab's `create()` after the first's
enrollment committed (`passkey_exists`), or one made after the step ended
(`state_mismatch`). Coffre never offers it: a touch names only the
passkeys coffre holds (`allowCredentials`), so the browser does not show
it, and nobody is locked out; the person may delete it from their device.
Reviews r8 to r12 kept one handle per enrollment and shared its step
across tabs in `localStorage` instead, and each round found another path
to a second `create()` with it. The step ends five minutes after its
challenge (`issuedAt`, from which the sealed state's expiry is dated), and
its options' `timeout` is what is left of those when the GET is answered
(`remainingMs`, review r9). That `timeout` starts when the authenticator is
called, not at the GET, so the page keeps the step's deadline itself,
dated from when it sent the GET, by the wall clock and by the time elapsed
since the page opened (`performance.now`), past once either says so: a
press after it asks the authenticator nothing and asks coffre for the step
again (new options while the sign-in waits, "Sign in again" once it does
not), and a press before it calls the authenticator with what is left
(`sendPasskey`'s `ends`, review r14). Without it, a page left open past
five minutes made a passkey the server then refused. An answer already
made is still sent again past the deadline: its first POST may have
committed, and the server says which. A touch keeps its answer in the page too: a
second `get()` replaces nothing. A HEAD of the route answers as its GET,
never as its POST (review r8).
The cookie's value names its purpose, whose key
opens it (`CeremonyStates`, `packages/server/src/api/ceremony.ts`). The
callback's reads (`SigninService.afterProvider`) are step 2's, in one round
trip: the identity (`findIdentity`) and, beside it, one statement of the
members its account may be (`signinMembers`: the one its identity names and
one per verified email, each with its status, generation, passkeys ever and
live, and the vault's newest entry about its access, `access_seq`). The
Owners the deployment names come with the vault's capabilities, asked once
per isolate (`deploymentOwners`), never about a person, which would admit
them. The vault's answer about the person is asked only where those rows
leave the step undecided, a person with no passkey under `optional`, whose
role decides: and that answer is the sign-in's own, which the callback
completes with, reading and asking nothing again. Its transaction holds the
answer to the access it was read at, as `issuerStill` holds an issue: read
again under the head, an `access_seq` that moved (Ada promoted to Owner
between the answer and the commit) decides the step again, from the reads,
and Ada adds a passkey first; no count bounds that loop, each turn of which
waits on another change of hers (R70). Against today's sign-in for the same
Developer, `signin-cost.test.ts` holds the callback to its vault calls and its
statements plus the one members' read. The post's checks are in
`finishPasskey`, then `completeSignin`'s transaction with the touch
(`touchPasskey`) or the first passkey (below) in it; a first passkey whose
credential ID a passkey already has, anyone's, is refused as a passkey that
did not answer (`passkey_failed`), the unique index the one place that
decides it. `passkey-signin.test.ts` holds the flows, on both engines,
through the deployment's routes, with the software authenticator, an
Owner the configuration names whose row the vault's start has not written
yet included. The sealed cookie carries the provider's name whole; a
profile that makes it longer than the 4,096 bytes a browser must keep (RFC
6265, section 6.1), which it would drop unsaid, ends the sign-in with
`profile_too_long` instead. Every bound on the answer has a source (R70):
the credential ID's and the user handle's are the spec's, the signature's
the longest key coffre takes (RSA of 4,096 bits); the fields the spec
leaves open, the client data, the authenticator data and the attestation
object, have none of their own, and the request they come in is read to
the bound the API reads every control-plane body to (`API_BODY_BYTES`),
once the cookie it must carry has opened. Their CBOR is read with a list of
what is open, not the call stack, so however deep it nests it costs no
stack (RFC 8949, section 10), and needs no depth limit. What it decodes to
is counted, though: every item and map key of the attestation object, the
authenticator data's CBOR and the COSE key, and every value of the decoded
client data's JSON, whose unknown members are ignored (5.8.1), together, is
held to the count
the API holds a body's JSON values to (`MAX_BODY_NODES`, 20,000, R27's CPU
budget), counted again on what the body's strings decode to, so a response
costs at most twice what a body's JSON may (Fable review). Without it, a megabyte of maps
nested one byte apiece, in an attestation statement the verifier ignores,
built about 150 MiB of them before anything refused it, past the 128 MB a
Worker's isolate has (review r2 of #500). Client data counted only by its
bytes let 54 KB of an ignored array of 20,001 elements past the count
(review r12).

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
  pubKeyCredParams: [ // Ed25519, ES256, RS256
    { type: 'public-key', alg: -8 }, { type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 },
  ],
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

**And it is good for one enrollment, ever.** "No live passkey" alone would
let a state be used again after a reset: an attacker who saved Bob's
`enroll` cookie registers a key, an Owner resets it, and within the
cookie's five minutes the attacker uses the cookie again with a new key,
without passing GitHub again. So the state seals `passkeysEver`, the number
of passkey rows the person had at the callback, removed ones included, and
the transaction, under the person's factor lock (section 6.1), refuses it
unless the count is still that. Rows are never deleted, so every enrollment
moves the count for good, and no reset moves it back. The add's sealed
state from Account carries the same count.

`user.id` is 16 random bytes, drawn for each GET of an enrollment's
options and stored on the passkey row its `create()` makes
(`passkeys.user_handle`). The registration response does not echo it, so
the GET seals it in the step's `state` (`CreateState`, bound to the
enrollment's challenge, `packages/server/src/api/ceremony.ts`), the `POST`
sends it back, and the row stores that exact value; the add from Account
(PR 5) does the same. WebAuthn asks that it reveal nothing about the
person, and a hash of the email, even keyed, can be tested against
guesses by anyone who learns the key; random bytes cannot, and survive an
`APP_KEY` rotation. Each `create()` gets one of its own (D173): an
authenticator keeps one discoverable credential per RP ID and user
handle, and replaces it on a second `create()` with the same one, so a
handle shared by two tabs of one enrollment, a reload, or a page whose
answer was lost could replace the passkey coffre had stored with one it
refuses, and lock its person out (reviews r7 to r12 of #500). A person's
passkeys therefore have handles of their own, and a keychain that holds
two of them shows two entries; an interrupted attempt may leave a third
that coffre never stored and never offers (section 3.1, as built). The
`userHandle` an assertion returns is checked against the row of the
passkey it names (7.2). A configured Owner not yet admitted gets one at
registration, as anyone does; nothing about it depends on the generation.

**As built (PR 4b).** The enrollment's transaction takes the person's
factor lock first (`audited`'s `factor`, `lockFactor`), then the head; it
reads every passkey row of theirs, removed ones included, by
`passkeys_principal_idx`, holds each to its MAC, and checks their number
and that none is live, in one statement (`passkeyHistory`), adds the
passkey, ends
what no passkey stands behind (section 6.1: credentials and MCP
connections of this membership naming none, through their prepared
changes, and approved device codes not yet redeemed that name none,
denied), and issues the session, with `account.link`, `passkey.add` and
`sign_in` entries. A configured Owner the vault has not admitted is
admitted at the post, by `completeSignin`'s question to the vault, once
the attestation has verified. The passkey's name is its provider's, where
its AAGUID names one, else "Passkey <n>" (PR 6a, section 3.6). It reads the rows,
not a count, for their MACs: a removal written in the database alone
(`removed_at` set, the MAC as the app signed the live row) refuses the
sign-in, `tampered`, where a count read it as no passkey and let another
be the first (R64; review r2 of #500). A sign-in the provider alone
answers under `optional` reads the same, for the same reason.

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

**As built (PR 5b).** The page does not decide beforehand. The browser's
API client hears `403 fresh_check_required` in its transport, for every
page at once (`freshTransport`, `@coffre/ui`'s `lib/fresh.ts`), and opens
"Confirm it's you" over the page that sent the act (`FreshCheck`, mounted
by `CoffreProvider`). The dialog asks the step-up's door for its options
as it opens, so the press reaches the authenticator at once; the touch
answers there (section 6.5), the response sets the new session's cookie,
and the act goes again, once, as it was sent, but for one header: the
refusal names its caller, opaquely (`caller: 'user:<id>'`), and the act
sent again says it (`coffre-caller`). The router refuses an act whose
header names someone else than its caller, `409 conflict` with `reason:
'caller_changed'`, before anything is read or written: Ada's Save,
refused; another tab signs in as Bob meanwhile; the dialog's touch
confirms Bob's session; Ada's change, sent again on Bob's cookie, is
refused rather than made as Bob. A step-up that only rotates Ada's own
session leaves her the same caller. Acts refused together share
one dialog and one touch. Cancelled, the refusal goes on to the page,
which says nothing was changed. Ada's promotion is then: Save, refused,
the dialog, a touch, the change made; one round trip more than knowing
beforehand, which writes nothing. `GET /api/me` answers `passkeys`, and
no page reads it yet; the header's chip is not built.

A person with no passkey under `optional` is refused with `reason:
'add_passkey'`, and the dialog says "Add a passkey first": a button per
provider signs in again with `?passkey=add` (`/auth/signin/<provider>?passkey=add&next=<page>`),
whose sign-in asks to add one as an Owner's does (`PendingState.addPasskey`),
and comes back to the page. The ten-minute rule of section 3.3 holds by
construction: the provider vouched for the person a moment before. Adding
one from the session, in Account → Passkeys, is the same sign-in (PR 6a):
a first passkey is never added from a session, so the ten-minute rule of
section 3.3 is never a rule of its own. Signing in again costs a
provider's redirect, which a provider already signed in to answers at
once, and the one code path that adds a first passkey and ends what none
stood behind (section 6.1) stays the one reviews held, rather than a
second beside it.

### 3.5 The CLI

**Approving a terminal.** `coffre login` stays a device login. Approving it
takes a touch for that terminal, not the browser's window: the terminal gets
a credential that lasts 30 days, and the touch is the moment Ada says yes to
this code. So Approve, `POST /api/device-logins/QJXM-4WTP { approve: true
}`, is refused `403 touch_required`, whose `touch` carries the options of a
touch and a sealed state naming that code and the approving session; the
page asks the authenticator and sends Approve again with `touch: { state,
response }` (section 4.2, as built). The decision's transaction checks the
assertion, moves the replay mark and records the passkey
(`device_logins.passkey_id`) with the decision. The touch opens no
window (rule 1): the approving browser's session stays as it was. A fresh
browser session alone approves nothing; one touch approves one code.

The poll that redeems the code issues the CLI session with that
`passkey_id`, and the approval's `decided_at` as its `confirmed_at`. Its
transaction checks, under the person's factor lock (section 6.1), that the
approval still stands and its passkey is still live, so a passkey removed, or a
first one added, between approval and poll redeems nothing. The new CLI
session starts a 30-day lifetime of its own, as `coffre login` does today:
it comes from a browser whose own lifetime is bound to a provider sign-in,
and a terminal has no provider sign-in to inherit. A terminal starts with a five-minute window too.

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

**As built (PR 5b).** Only a session `coffre login` saved steps up this
way (`steppingUp`, `packages/cli/src/main.ts`); a token or a CI run's
credential answers the refusal as any other. The device login's label is
`coffre CLI: <the command>`; a secret is never an argument, so the label
shows none. The approval's touch is PR 5a's, and its terminal starts
confirmed when it was decided. Before it asks for the code, the CLI asks
the instance whose the saved session is (`GET /api/me`, `whoseSession`):
a session approved as anyone else, whatever another `coffre login` saved
meanwhile, is signed out and the command refused. The new session
replaces the saved one only if that is still the session the command
started on (another login's is left as it is, and the command refused),
and leaves the default instance where it was, for `--url`. The old
session is then signed out; one the instance could not end (a 503, no
answer) is said, with `coffre --url <instance> sessions revoke <id> --apply` to end it,
its id the instance's answer named. With `reason: 'add_passkey'` no code
is started: the CLI says to sign in in the browser and add one there.

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

**As built (PR 6a).** The API's side; the pages are PR 6b's, below.

- `GET /api/members/:member/passkeys` lists the person's live passkeys,
  their own (any session of theirs) or, for an Owner of the whole
  instance, anyone's, whose reset they weigh: `{ passkeys, ends, reset,
  max }`. Each passkey's name, its provider (from its AAGUID), whether it
  syncs, when it was added and last used. `ends` counts what removing one
  ends, the session asking left out, or a reset: sessions and terminals,
  personal tokens, handles, connected apps. `reset` is section 3.7's
  notice. A row that fails its MAC refuses the read, `409 tampered`,
  rather than list as fewer (R64).
- **Add another** is two requests, both **always** (section 4.1): `POST
  …/passkeys/options` answers `create()`'s options, bound to the browser
  session that asked, with a user handle drawn for that `create()` alone
  (as at sign-in, section 3.2) and the live ones excluded; `POST
  …/passkeys { state, response }` checks the attestation, then, under the
  person's factor lock and the head, that the session still stands and
  their passkeys are as they were when it was asked (none added or
  removed since: a state answers one `create()`), and adds it, with a
  `passkey.add` entry naming what confirmed the session. It ends
  nothing: every credential of theirs names a passkey already. A person
  with none is refused `add_passkey` by the router and signs in to add a
  first one (section 3.4). From a browser session only, and never under
  `off`.
- **Ten at most** (`MAX_PASSKEYS`), the number above.
- **Rename**, `PATCH …/passkeys/:id { name }`: one to 64 characters, no
  control character, no check, a `passkey.rename` entry.
- **Remove** replaces the browser's session (rule 1), so it goes through
  the passkey page's door, as the step-up does, not an API route: `GET
  /api/auth/passkey?remove=<id>` answers the touch to ask, bound to the
  session, of the person's other live passkeys, or, for their last under
  `optional`, of that one, or none under `off` (`options: null`); under
  `required` their last one answers `409 last_passkey`. `POST
  /api/auth/passkey { state, response }` checks the touch, then, under
  the factor lock and the head, the passkey is still live and still not
  their last under `required`, ends the session it came in on first (of
  two removals on one session, one goes), moves the touch's replay mark,
  removes the passkey, ends every other credential, connection and
  approved terminal code of theirs, and issues the new session: confirmed
  now by the passkey touched, or naming none. `passkey.remove` entries,
  `passkey.check` denials. A state asked under one policy answers nothing
  under another.
- **Names**: a new passkey takes its provider's name, from a list of the
  AAGUIDs passkey providers publish (`packages/server/src/passkey-names.ts`:
  1Password, Apple Passwords, Google Password Manager, Windows Hello and
  the like), else "Passkey <n>", `n` one more than every passkey row the
  person has had. Security keys publish theirs in FIDO's metadata
  service, which coffre does not read, so a YubiKey is "Passkey <n>"
  until renamed.

**As built (PR 6b): the pages.** Account → Passkeys
(`/account/passkeys`, `components/passkeys.tsx`) lists them, each with
Rename and Remove; under `required` a last one's Remove says to add
another first. Add a passkey asks `…/passkeys/options` as its dialog
opens, so that the press calls `create()` inside its own click (a
fresh check, if the window has closed, comes first, over it); its
options are asked of the authenticator once, and an answer coffre did
not answer is sent again as it is, never made again, as at sign-in. A
first passkey is added by signing in again (`?passkey=add`), back to
the tab. Remove opens the door's `?remove=<id>` as its dialog opens,
says what ends (`ends`, in words: "Removing YubiKey 5C signs you out of
3 other sessions and ends 1 personal token"), and the touch's answer
lands back on `/account/passkeys` on the new session, a full navigation.
Under `off` the tab stays, and Remove asks no touch: the way to clear
lost passkeys during recovery (3.7). The reset is a person's ⋯ menu's
Reset passkeys…, an unscoped Owner's, for anyone but themselves, an
Owner the deployment names included; its dialog reads the person's
passkeys first and says what the reset removes and ends. The prompt
of 3.3 is on Projects; Not now is the `coffre-passkey-later` cookie, a
preference as the theme is, 30 days, holding when it was pressed, so
the server renders the page without it from the first byte. The reset
notice ("Ada reset your passkeys on …") shows on the tab, in the
prompt, and on the sign-in's step that adds a new one under
`required`. A reset after a Not now shows the prompt again, to say it,
and Projects' loader reads the person's passkeys, so the server
renders the notice too (review r1 of #539).

Another passkey's options last no longer than the session stays fresh
(`timeout`, at most the five minutes since its touch): its add is held
to the fresh check too, and a `create()` answered after would meet a
step-up, which replaces the session the options name, leaving a
passkey on the device coffre never stored; the page asks for new
options instead, after the step-up. The page ends the authenticator's
call at that deadline itself (an `AbortSignal`), since browsers take
`timeout` as a hint (Chromium raises one under three minutes to
three); every `create()` and `get()` the pages make is held so
(`withinDeadline`, review r2 of #539). A 401 or 409 whose body did not
arrive whole keeps the add's answer for the next press, as the
sign-in's page does. An add whose reply was lost, sent
again, finds its passkey among the person's live ones before it counts
them and answers `409 passkey_exists`, which the dialog takes as done
(review r1 of #539).

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

**The last Owner, every passkey lost.** Keep two unscoped Owners, and
this never happens: the other one resets Ada's. With no other, no one can.
Whoever deploys coffre sets `passkeys: 'off'` and redeploys. Ada signs in
with GitHub alone, removes the lost passkeys (no check under `off`), and
the deployer puts the policy back; under `required` Ada adds a passkey at
the next sign-in. While it is `off`, a provider account is enough for
everyone, so the window should be minutes. There is no narrower lever, no
reset command and no config exemption: Erwin's answer to open question 3
(D170) is that recovery adds no concept of its own.

What `off` leaves behind when it ends: sessions, terminals, personal
tokens and MCP clients made while it lasted name no passkey, so for anyone
who has a passkey they are refused at their next request once the policy is
back, and revoked by that person's next removal or reset (section 6);
handles made meanwhile live out their lifetime unless revoked. What `off` cannot undo by itself is what such a session did:
service tokens issued, bindings made, access changed. The recovery steps in
`docs/deployment-auth.md` end with reading the log for the `off` window.

`off` keeps the rows. Passkeys are not deleted when a deployment turns
them off, so turning them back on restores everyone's.

**As built (PR 6a): the reset.** `DELETE /api/members/:member/passkeys`,
**always**: an Owner of the whole instance, signed in as themselves (not
a token's scope, nor an MCP connection), for someone else, who holds a
live passkey (`409 no_passkeys` otherwise). Under the target's factor lock
and the head, it removes every live passkey of theirs (`removed_by`, the
Owner) and ends everything they are signed in with, as a removal does,
issuing nothing; `passkey.reset` names the passkeys and how much ended.
The Owner is weighed as the vault answers when the reset starts, not as
their request was let in, and held to that answer under the head, as an
issuer is (`issuerNow`, `issuerStill`; formal/Issuing.tla's
`IssuerFence`), with the session they asked on still live and still
backed: demoted meanwhile, they reset no one (`409 access_changed`, then
`403 not_owner`). Approved terminal codes not yet redeemed are denied,
naming no passkey. The removals and revocations are asked together, so
a reset costs the same round trips for one passkey as for ten
(`change-cost.test.ts`). A passkey row failing its MAC refuses the
reset, an add and a removal, at their first step or at their commit,
`409 tampered`. Reading someone's passkeys is the Owner's alone too, but
a refused read is no attempted reset and logs nothing (`403 forbidden`).
The notice is read from the rows: while the person holds no live
passkey, a newest removal by someone else is a reset, `{ by, at }`,
which the Passkeys tab's read and the sign-in's enroll step answer. Each
removal is dated by the app's clock that wrote it, so the rule compares
no row's `created_at`, the database's. `removed_at` is under the row's
MAC, `removed_by` is not (section 5.3, `auth-rows.ts`): an edit of that one column could
turn a removal of one's own into a reset by someone else, or hide one.
So the notice informs and the log's `passkey.reset` records (R64).

## 4. What needs a fresh check

A fresh check means the session making the request was confirmed by a
passkey touch in the last five minutes: `confirmed_at` within five minutes,
on a session that rule 1 issued at that touch. The rule for what needs one:
**it guards what widens someone's reach, mints a credential, or cannot be
undone.** Removing access, revoking, freezing and protecting never need one:
in an incident they must be quick.

Five answers per route:

- **always**: a fresh session. No passkey under `optional`: add one first
  (section 3.4). Under `off`: no check.
- **holder**: a fresh session if the caller has a passkey; nothing
  otherwise.
- **ceremony**: the request carries its own assertion, for that request's
  target alone (section 3.5); a fresh session is not enough. Nothing for a
  caller without a passkey under `optional`, unless what it approves is
  **always**.
- **handler**: the handler decides, from what it reads anyway, before it
  writes; for a check that hangs on stored state the router does not see.
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
| `PATCH /api/secrets/…` that loosens a key's nature (sensitive to secret, R30; secret to plain) | a value people could not read becomes readable. **handler**: the body names the nature it wants, not the one it leaves, so the write's handler, which reads each key's current nature, answers `403 fresh_check_required` before it writes; a write that keeps or tightens a nature needs nothing |
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

**As built (PR 5b): loosening a key.** The one write that makes a value
people could not read readable is the mark of R30, a sensitive value made
a secret in place by an Owner of its project, and that is what the
`handler` answer guards: `marking` reads each key's level, and refuses
before anything is written. A write of a value with a looser level
(`{ value, sensitivity: 'plain' }` over a secret) needs nothing: its value
is new, written by whoever sends it, and every older version keeps the
level it had, so nobody reads anything they could not read before. A mark
looser by any other step is refused already (`looser`).

### 4.2 holder and ceremony

| Route | Answer | Why |
|---|---|---|
| `POST /api/device-logins/:code` with `approve: true` | ceremony | a 30-day CLI session (section 3.5) |
| `POST /api/oauth/authorizations` with `approve: true` | ceremony | an MCP client's refresh token: one touch connects one client |
| `POST /api/approvals/:id` with `approve: true` | ceremony | a change an MCP client asked for (4.4) |
| `POST /api/members/user:<self>/tokens` from a browser session | holder | a personal token outlives a 12-hour browser session; from a CLI session, never |
| `GET /auth/signin/:provider?link=1`, and its callback | holder | another provider account that signs in as you (section 4.5) |
| `POST /api/members/user:<self>/passkeys`, a second one onward | holder | a new factor |
| `DELETE /api/members/user:<self>/passkeys/:id` | ceremony | removing a factor: a touch of a passkey kept, or of the last one (section 3.6) |

**As built (PR 5a): a touch for one act.** A **ceremony** asks its touch
in its own refusal, so it needs no route of its own and no page needs to
know beforehand who holds a passkey. Ada presses Approve on `QJXM-4WTP`:

1. `POST /api/device-logins/QJXM-4WTP { approve: true }` is refused `403
   touch_required`, with `touch: { options, state }`: `get()`'s options,
   offering Ada's live passkeys, and a state sealed under a key of its
   own (`passkey-state/act/v1`) that names the act (`device`, that code),
   her session and her membership's generation. A prompt: nothing is
   decided and no entry written.
2. The page asks the authenticator at once, and sends Approve again with
   `touch: { state, response }` (`pressTouch`, `@coffre/ui`'s `touch.ts`).
   A browser that wants the touch closer to the click than a round trip
   (Safari's user activation) throws; the page keeps the ask, and the next
   press asks it first, before it sends anything, while its options last:
   the authenticator gets what is left of their five minutes, and a press
   after them drops the ask and starts over, so Ada is never asked to touch
   a challenge coffre would only answer with another `touch_required`
   (review r1 of PR 5a).
3. The route opens the state, holds it to the act and the session, finds
   the passkey the assertion names among Ada's live ones, and verifies it
   (`SigninService.touchFor`), before any transaction. A state that does
   not open as this act's, for this session (expired, or asked for another
   code), is answered with a new `touch_required`; an assertion that does
   not check, `403 touch_failed`, a `passkey.check` entry denied.
4. The act's own transaction, under the log's head, moves the passkey's
   replay mark past the challenge, on a passkey still live and Ada's at
   that generation (`touched`), and writes `passkey.check` allowed with
   the act's own entry, which names the passkey. A mark that does not move
   (the same answer sent again, the passkey removed meanwhile) refuses the
   act, `touch_failed`, and rolls it back.

An MCP client's change binds its touch to what the page showed: the
change's digest, the basis and the value typed, as a digest (a value never
rides in the state). A connection binds the request and the scopes chosen:
another choice asks again. The person's answer is the act; the touch is
asked only of a caller a passkey stands behind, under any policy but
`off`. A person who holds none under `optional` is asked nothing (section
4.4). The terminal an approval redeems names the passkey touched and is
confirmed when the approval was decided: an approval names a passkey only
with its touch, since 0.16.0 has no release without one.

The touch opens no window and replaces no session (rule 1). Every touch
that opens a window issues a new session so that a copy of the old cookie
cannot ride it; a touch for one act leaves nothing to ride, and the act it
approved cannot be approved twice. Replacing the session here would have
needed an API route to set cookies, and `#decide` to rebuild its context
around the new credential, for nothing the act needs. What it gives up:
a copy of Ada's cookie taken at 12:00 still reads at 12:02, after her
touch at 12:01, until the session expires or is revoked, where a
replacement would have ended it at 12:01. That copy could read at 11:59
as well, and approves nothing without a touch of its own; ending it is
signing out or removing the session (section 6.1), not a side effect an
attacker can count on Ada's approving a terminal to bring.

### 4.3 Reads

`POST /api/reveals` and every other read are **never**: a reveal takes no
touch, in a protected environment or any other. Protected environments
keep what they do today: a role that may use or write a key but not read
it cannot reveal its value, whether it acts through a browser, a CLI
session, a personal token or an MCP connection. Passkeys add nothing on
top.

An earlier draft had an option, `protectedReveals`, under which a person's
reveal in a protected environment took a fresh session, the vault deciding
it on every read path. Four review rounds found a hole in it each time, all
where the check meets the vault's several read paths, and no one had asked
for it. Erwin dropped it (D170, open question 4): no option, no later
phase.

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
  Approve makes the change in process, in the approving browser's request.
  `docs/design/mcp.md` names its follow-up: "a passkey with user
  verification on Approve", the one control an agent driving the person's
  browser cannot pass. A five-minute window would not be that: the agent
  could approve in the minutes after the person's own touch. So Approve is
  a **ceremony** for anyone with a passkey: its sealed state names the
  approval and the basis the page showed, and `#decide` checks the
  assertion inside the transaction that decides it, for every change, a
  secret write included. Connecting an MCP client is the same (4.2). For a
  person without a passkey under `optional`, Approve needs nothing, unless
  the change's own route is **always**: then they add one first. Today's
  `#decide` commits the approval before it makes the change and records
  `failed` if the change throws, so the ceremony and the change's own
  `FRESH_ROUTES` answer are checked before the approval is decided; a
  refusal leaves it pending. The touch opens no window and replaces no
  session (rule 1): the change runs as the approving session, through the
  connection (`via`), as it does today, and the touch stands for it at the
  router's check (PR 5b). An earlier draft replaced the session at the
  touch and rebuilt `#decide`'s context from the new credential, so that a
  change issuing a service token would not name a session the touch had
  just ended; a touch that ends nothing needs neither (PR 5a). Open
  question 9. As built (PR 5b): each change says what its route answers
  (`Change.fresh`, `always` for granting, admitting, removing, issuing a
  service's token and trusting a workload), which `#decide` holds the
  person to before it decides, with no touch: under `optional`, a person
  with no passkey is refused `fresh_check_required`, `add_passkey`, and
  the approval stays pending. The change then runs through the router,
  whose check finds the approval's touch on its connection (`McpVia.touched`)
  and takes it for the window; a change approved with none is checked as
  the session is, so a `fresh` that says `never` of a route that is
  `always` fails the change, not open.
- **Handles and `/use`**: never.

### 4.5 In code, and the routes outside the table

```ts
// packages/server/src/api/fresh-routes.ts, typed over the route table as PERSONAL_TOKEN_ROUTES is.
type Fresh = 'always' | 'holder' | 'ceremony' | 'handler' | 'never';
// What a route's handler gets, typed per route: its path parameters, its parsed body and its parsed query.
type Asked<K extends RouteKey> = { params: RouteParams<K>; input: RouteBody<K>; query: RouteQuery<K> };
export const FRESH_ROUTES: { [K in RouteKey]: Fresh | ((asked: Asked<K>, ctx: ApiContext) => Fresh) } = {
  'PATCH /access/:member': 'always',
  'PATCH /projects/:project/:environment': ({ input }) => (input.protected === false ? 'always' : 'never'),
  'POST /members/:member/tokens': ({ params, query }, ctx) => …, // dryRun: never; a service: always; personal from a browser: holder; else never
  'DELETE /projects/:project': ({ query }) => (query.dryRun === undefined ? 'always' : 'never'),
  'POST /device-logins/:code': ({ input }) => (input.approve ? 'ceremony' : 'never'),
  'POST /approvals/:id': ({ input }) => (input.approve ? 'ceremony' : 'never'),
  'PATCH /secrets/:project/:environment': 'handler',       // loosening a nature, decided where the current one is read
  'POST /reveals': 'never',                         // reads take no touch (section 4.3)
  'GET /me': 'never',
  // … every route
};
```

The router checks it after the body and query parse and before the
handler runs, with what the handler gets (`params`, `input`, `query`) and
the request's credential, which it read already. MCP approvals ask the same
function about the change they would make, with the change's own
`params`, `input` and `query`. A **ceremony** route
checks its assertion in its own handler, inside the transaction that makes
its change. A refusal is `403 fresh_check_required`, with `reason:
'add_passkey'` when the caller has no passkey yet (as built: the error's
own `reason`, which every client reads already). It writes no entry: it is a prompt.
A page meets one once a window has run out, and a script on a stolen
cookie meets one every time, so it goes to the process log, one line with
the principal, the route and the credential.

As built (PR 5b), the router asks after the route's own `needs` and before
the handler (`requireFresh`, `api/fresh-routes.ts`). A route whose handler
checks its permissions itself (a member's add, say) prompts first: a
Developer who may not add members, on a session past its window, is asked
to touch, then refused. Nothing is written either way. Only a refusal
after the prompt is logged, so from a session outside its window, an
attempt the person may not make goes to the process log, not the audit
log. On the fast paths that read ahead (a member's add, `admitAhead`), the
vault's read is made and its ticket expires unused, as for the passkey
check's refusal (section 6.4).

The sign-in routes are protocols beside the table (`auth-routes.ts`), so
they check for themselves:

| Route | Check |
|---|---|
| `GET /auth/signin/:provider?link=1` | holder, at the start, before leaving for the provider |
| `GET /auth/callback/:provider` for a link | holder again, before `linkIdentity` commits: the browser's session must still be the one the link started from and still fresh; if the window ran out at the provider, "Confirm again and link" |
| `POST /api/auth/device/token` (the poll) | the approving passkey still live, inside the issuing transaction (section 3.5) |
| `POST /api/oauth/token` (an MCP refresh) | the connection's passkey still live (section 6.2) |
| `POST /auth/signout`, `POST /api/auth/logout` | never |
| `POST /api/auth/oidc`, `POST /api/auth/workload` | never: services |

Conformance checks the link and the poll (section 13), since no type holds
them.

**As built (PR 5b): the link.** The start, outside the window, sends the
browser to the step-up, `/auth/passkey?step-up=1&next=/auth/signin/<provider>?link=1`,
whose touch comes back to the start: the one place a step-up goes on to
that is not a page, and only exactly so, for a provider the deployment
has (`stepUpNext`). The callback, outside it, links nothing and lands on
`/account?error=link_stale`, "link again". It holds the browser's session
to the person the link started for, as before, not to the very session:
a step-up between the two replaces it, and the window, checked again, is
what the session must still have. The link's entry names what
confirmed the session at the callback (section 11), as the router's
check does for an API route (`freshPass`).

## 5. Storage

### 5.1 `passkeys`

```ts
export const passkeys = pgTable('passkeys', {
  id: uuid().primaryKey(),
  authMac: bytea('auth_mac').notNull(),
  // Whose: the member and the generation it was added in, as identities are bound.
  principal: text().notNull(),
  generation: integer().notNull(),
  // The WebAuthn user handle: 16 random bytes, drawn for the create() that made this passkey (section 3.2).
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
  // Every passkey a person has had (PR 4b, migration 0072): the callback's count, and the first passkey's checked read.
  index('passkeys_principal_idx').on(table.principal),
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
// Set on browser and CLI sessions, and copied onto what they make: personal tokens, service tokens and handles
// (no confirmed_at; section 6.3).
passkeyId: uuid('passkey_id'),          // FK passkeys(id)
confirmedAt: timestamp('confirmed_at', { withTimezone: true }),

// device_logins: the passkey that approved this terminal; its decided_at is when.
passkeyId: uuid('passkey_id'),          // FK passkeys(id)

// mcp_connections: the passkey touched to connect it (section 4.2), which may be another of the person's than
// the one behind the session; under `off`, where no touch is asked, the session's own. Device approvals write
// none under `off` instead: `off` checks neither, so the two differ in what they record, not in what they allow.
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
| Chrome, made before the deployment turned `required` on | browser | null | null | refused: asks for a touch (section 6.2) |

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

**As built (PR 2).** Postgres `0063_passkeys`, SQLite `0032_passkeys`. As
above, with these choices:

- The MAC covers the user handle too (it never changes, so it costs
  nothing), and a row that names a passkey takes the kind
  `confirmed_<table>` (`packages/server/src/auth-rows.ts`), outermost, so
  a writer can neither vouch a passkey for an old session nor swap one.
- The app's `UPDATE` on `passkeys` is by column, as on every sign-in table:
  the counter, the replay mark, the name, last use, removal and the MAC;
  never whose a passkey is, its handle, credential or key
  (`packages/db/test/schema-guarantees.sql`, 22). It also gets `UPDATE
  (passkey_id)` on `device_logins`, which names its passkey when it
  is decided. `credentials` and `mcp_connections` name theirs when they are
  inserted, which the app's `INSERT` already covers.
- Checks beyond 5.1's: a 16-byte user handle and AAGUID, the counter a
  uint32, transports a JSON array, a name of 1 to 64 characters, `removed_by`
  exactly when `removed_at`; a credential's `confirmed_at` only with a
  passkey and only on a browser or CLI session (a personal token or handle
  copies the passkey alone, so it never passes a fresh check); and a device
  login's passkey only on an approval, never on a pending or denied one
  (the check spells out `decision IS NOT NULL`, since a pending row's NULL
  would otherwise pass it). So a device login that names a passkey ends by
  `consumed_at`, as the rotation ends one, never by turning `denied`.
- Every place that writes a credential, device login or MCP connection
  says which passkey stands behind it, `null` included: the MAC's row type
  requires `passkeyId` (and `confirmedAt` on credentials), so an issue site
  that forgets one does not compile. A workload's session never names one.
- During the rollout, an isolate of the previous release cannot compute
  the `confirmed_` kinds, so a confirmed session that lands on it is
  refused (401, `auth_row_tampered` logged) until the deploy finishes, as
  sessions of the `scoped_` and `placed_` kinds were when those shipped.
  The 0.16 upgrade note says so.
- On Postgres the constraints on the three existing tables are `NOT VALID`,
  as 0022's seals were: their columns are null everywhere, so nothing is
  scanned, and each table is locked for a moment only. On SQLite each check
  rides on its new column, so no table is rebuilt.
- `APP_KEY` rotation signs `passkeys` again last, after the tables it
  already had, so that a cursor the previous release wrote still names the
  table it meant.

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

**Where the change revokes, and in which order it locks** (PR 4). The app
revokes the rows itself, in its own transaction, as a member's removal
does today (`revokeCredentialsWhere` in `members.ts`): the vault's log
entries for what it ends are prepared before the transaction
(`AppChanges.prepare`), since no app transaction stays open across a vault
call, and the transaction re-reads under the lock what to end, and retries
if that is not what it prepared. Within it the factor lock comes first,
then the log's head (`audited` takes it before any row), then the rows.
Asked together, under one Sync, a factor lock that fails (a
`lock_timeout`, a cancel) fails the head's statement behind it (25P02);
`audited` hears both at once and answers the factor lock's error, so the
head's rejection is never left unhandled, which on Node would end the
process (review r13).

**The app's own issues take the head, not the factor lock** (PR 4a). Every
app transaction takes the log's head first, a sign-in's, a poll's, an MCP
consent's and the app's path for a token alike, and a change takes it
right after the factor lock, so the head is what orders an app issue
against a change: one commits before the other reads. The factor lock is
for the vault's issue, which takes no head. `formal/Factor.tla`'s
`FactorApp` scenario shows it: without the change taking the head, a
sign-in that commits between the change's read and its commit is missed
(`ChangeEndsAll`), and no app issue needs the factor lock for any
invariant. An earlier draft of this paragraph had every app issue take the
factor lock before the head too; that bought nothing but a second lock in
every sign-in. Under the head each app issue checks its source live and
the passkey rule (`AppIssueChecks`): a sign-in by the provider alone is
refused (`passkey_required`) to a person who holds a live passkey, a poll
redeems an approval only while its passkey is live (or, naming none, while
the person holds none), and an MCP consent or a token issued on the app's
path only while the session it comes from still stands behind it
(`sourceStands`).

That leaves no way back for a credential no passkey stands behind. Bob's
terminal from before the first passkey was revoked when Bob added it, and
stays revoked when an Owner later resets Bob's passkeys. A device code Bob
approved without a passkey is denied when Bob adds one, so its poll redeems
nothing. A session made while the policy was `off` is refused while its
person has a live passkey (below), and revoked by the next removal or
reset, which is the only way to stop having one.

**Why a lock of its own.** A senior review proposed dropping this lock and
the per-request check below, relying instead on the log's head, the
vault's `via` check and a recorded policy swept once at the door. Review
r12 showed the cost: the head does not cover the vault's issue (the race
above); and a recorded policy can be undone by an isolate of the previous
deployment, cold-started during a rollout, that applies its own policy
again and issues by it, which nothing would check after. The lock and the
per-request check close both, so they stay.

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

**As built (PR 4a).** `passkeyStands` in `packages/server/src/passkey-check.ts`
is the table above, for browser and CLI sessions and personal tokens
(`passkeyChecked`); handles, services' credentials and workload sessions
are not checked. The statement that reads the credential
(`credentialRow`, every variant: a request's, `GET /api/me`'s with the
vault's rows, a page's) joins the passkey it names by its primary key and
asks of `passkeys_live_idx`, then of `passkeys_principal_idx`, whether its
person holds a live passkey at the credential's generation, rows but none
live at it (removed, or of another generation), or none ever. Rows but none
live, for a credential that names none, reads them all, one statement
more, and holds each to its MAC: a removal or a generation written in the
database alone would otherwise pass a session made while the passkey was
live, under `off` or by the previous release, and fails as a tampered row
does (R64; reviews r3 and r5 of #500, PR 4b). What no MAC answers is a
row that is gone from the person: deleted, or moved to another principal
(review r6 of #500). Both are writes `coffre_app` cannot make (no `DELETE`,
no `UPDATE` of `principal` or `generation`, `schema-guarantees.sql`, check
22), only a login above it, and a person with no row reads as one who never
had a passkey, whatever the other rows' MACs say. R64 leaves that writer's
state undesigned for; telling "never had one" apart from "had one" would
take a mark of the person's own, signed and outside the rows that writer
can delete, a later change if one is wanted. A removal, which `coffre_app`
can write (`removed_at`), is what the MACs above cover. A person readmitted after
holding passkeys, and holding none since, pays that statement on each
request of a session no passkey stands behind. The passkey's MAC is checked by
`passkeyStands`, on the one branch whose answer reads the row, so a row
changed around the app refuses the credential it backs as any tampered row
does (`401 unauthenticated`), and refuses nothing the check exempts: a
service's token issued from that session, or any credential under `off`
(review r1 of #497). An MCP connection's read
(`findConnection`) does the same, for every call through it, its code and
its refreshes. `formal/Factor.tla`'s `RequestChecks` is this check:
without it, the previous release's sign-in during a rollout serves a
session no passkey stands behind (`ServedBacked`).

Three kinds of request read their credential in the vault's own call
rather than the app's statement: a use by name, one key or several
(`useByName`, `useManyByName`), a key write (`writeAhead`, T179) and a
member's add (`admitAhead`). Since T216 (migration 0073) that call reads
what stands behind a person's credential too, with passkeys not `off`, in
the same statement and as the app's own statement reads it: the passkey
the credential names, by its primary key, and whether its person holds a
live one, `passkeys_live_idx` then `passkeys_principal_idx`. It answers
those rows with the credential's, and the app's check decides on them,
their MACs included, reading nothing itself (`credentialRow`'s
`passkeyOf`, through the rows read ahead). A handle, a service's token and
a workload read none, as the check exempts them.

- **A use by name** releases values and logs their use, so its call
  decides first, before anything of the place or the key: the app's
  policy goes in `accepts` (`NamedUseInput.accepts.passkeys`), and the
  statement holds the credential to the table above, without the MACs,
  under the fence, as it holds it to the rest of what the app's config
  accepts (`Probing.tla`, `AcceptedFirst`). Refused, the credential is
  answered as a token no credential has: the request goes today's path,
  whose credential check refuses it `401 passkey_required`, before
  anything reads the key (section 6.4). A row a database writer forged
  (a passkey put back live, its MAC broken) is taken there and refused
  401 by the app's check after, as any forged row is (D154, R64).
- **A key write and an add** decide nothing of passkeys in the vault: their
  first call releases nothing and writes nothing that commits without the
  app's transaction. It answers the rows (`write_request`, `admit_read`),
  and the app's check of the credential on them, before that transaction,
  refuses one no passkey stands behind `401 passkey_required` (or `401`
  for a row that fails its MAC, `503` for a read that fails), so nothing
  is written in either log and what the vault prepared is dropped. A try
  the vault's read refused (T179 PR 6, a Developer's member add) goes the
  same way: the passkey's `401` answers it, as on today's path, whose
  credential check comes before the route's, and the vault's refusal is
  never recorded, its ticket left to expire (`passkey-check.test.ts` holds
  both paths, the fast one served on Postgres, and the refusal
  unrecorded).

So the check costs these requests no statement: `key set` and `member
added` take the round trips they took before passkeys (1 and 0 of the
app's, in `change-cost.test.ts`), and a person's reveal is the vault's one
call (`proxy-use-cost.test.ts`). From PR 4a to T216 each ran it as a
statement of its own (`passkeyByToken`), before a use by name and beside
a write's or an add's first call.

What a request issues names its credential's passkey, copied, never its
touch (`confirmed_at` null): personal tokens, handles and service tokens,
on the vault's path (which holds `via` to it, section 6.3) and the app's;
an MCP connection, the consenting session's (5.2). What a connection
issues (a service token through `issue_service_token`, or its person's
personal token) names the connection's passkey, and goes the app's way:
the vault holds `via` to a credential, which a connection is not, and
refused a passkey with no `via` as a programming error. Under the head,
`sourceStands` reads the connection as it reads a session, live and its
passkey with it, and the issue's recheck (`#currentCaller`, or the
service token's own) refuses one whose passkey has gone
(`mcp-oauth.test.ts`; review of #497 by Fable 5.1). Until PR 5's device
ceremony asks a touch per code, a device approval copies the approving
session's passkey too, and the CLI session its poll redeems names it with
no `confirmed_at`: a terminal approved by a confirmed browser keeps working
for a person who holds a passkey, and is not fresh.

### 6.3 Handles

Handles are the one kind not checked per request: they reach `/use` only,
which R44 and R58 keep to one statement. So the revocations of 6.1 carry
them, which needs every handle issue under the person's lock. A handle,
like a personal token and a service token, is issued by the vault's own
statement (`vault.issueToken`, with the app's audited transaction as the
fallback). That statement already checks the credential it is issued from
(`via`) against its seal, unrevoked, unexpired, of the person's
generation, under the member row's lock; signing out does not end the
handles a session made. What it lacks is the person's factor lock: a
removal's sweep can read the person's credentials, then wait while a
handle commits from a source it is about to revoke, and miss the handle
(review r12). So the vault's issue takes the person's factor lock first,
before the members' rows, and carries `via`'s passkey onto what it issues,
handles, personal tokens and service tokens alike. Built in PR 3
(migration 0064, `formal/Factor.tla`, `docs/formal.md`):

- **One statement, two signatures.** `issue_token` gains an overload whose
  last argument is the passkey the issue carries, `p_passkey`. It takes
  `pg_advisory_xact_lock(1717658484, hashtext(<issuer>))` first, then
  checks `via` as before, and also that `via` names exactly that passkey,
  still its issuer's, of their generation, and not removed; otherwise `ended`, with nothing
  written. The row it inserts names the passkey, which the app's MAC on
  the row covers (section 5.2). The vault never copies the passkey from
  `via` on its own: the MAC is the app's, made before the call, and a row
  naming a passkey its MAC did not cover would fail every read after.
- **The previous release's vault takes the lock too.** The old signature,
  same arguments, same grant, is now that overload with no passkey
  (`CREATE OR REPLACE`). A rollout runs both releases, and the previous
  one's issues must not race a removal by the new one's app. Carrying no
  passkey, it issues only from a credential no passkey confirmed, which is
  every credential the previous release can read (its MAC check refuses a
  confirmed one).
- **No fallback, and no capability check.** An earlier draft had a method
  of its own, `issueTokenUnderFactor`, with a fallback to the app's own
  path when an old vault refused it. Since T186 PR A (#462), every
  app→vault call goes through the release gate: an app and a vault of
  different releases answer `503 deploying` before anything runs, so a new
  app never meets an old vault, and the fallback could never run. The
  contract is `issueToken` as before, its token row gaining `passkeyId`.
- **SQLite** checks the same in `issueOnSqlite`; its one writer is the
  lock.

The app sends `passkeyId: null` until PR 4 confirms sessions; until then
no credential names a passkey, so null is always `via`'s.

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

So the named path stays, for people too, and the passkey check goes first
in it: for a person's credential, while passkeys are not `off`, the vault's
named statement holds the credential to the check of 6.2, for one key and
for several, with the rest of what the app's config accepts (`accepts`,
T216; `Probing.tla`'s `AcceptedFirst`). It reads the credential and the
person's passkeys before anything about the key, so a refusal says
nothing about the key and costs the same whatever was asked: answered as a
token no credential has, the request goes the ordinary way, whose
credential check refuses it `401 passkey_required`. Taken, the use
answers the passkey rows with the credential's, which the app's check
holds to their MACs. The check is in the call that uses, under its
fence: a change to the person's passkeys that leaves none behind the
credential revokes it (6.1), a change of the log's, which waits for that
fence, and one that committed before the call is in what it reads, the
credential revoked, which the vault checks itself (`credentialStill`). Until T216 the app ran the check in a
statement of its own before the vault's call, one more round trip a
person's reveal.

### 6.5 Fresh, and replacing a session

**Fresh** is `confirmed_at` within five minutes. Only a touch sets it, on a
credential that touch issued: a browser session at sign-in, at a step-up or
a fresh check; a CLI session from its device approval (as built, PR 5a:
confirmed when the approval was decided, by the act's own touch).

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
the pages read to decide when to open the dialog before sending. As built
(PR 5b), it answers it, and the pages leave it unread: the dialog opens on
the refusal (section 3.4). `enrolled` is whether the credential names a
passkey, which the request's own check holds to the person's holding one;
`confirmedUntil` is set inside a browser's or terminal's window alone.

**As built (PR 4b): the step-up.** A page whose `GET /api/me` answers `401
passkey_required` goes to `/auth/passkey?step-up=1&next=…` (the shell's
loader). `GET /api/auth/passkey?step-up=1` reads the browser's session
whatever its passkey (live, of a member at its generation), and answers a
touch of its person's live passkeys with a sealed state bound to it; none
live, it answers 404 and the page sends the person to sign in again,
which, under `required`, adds one. `POST /api/auth/passkey { state,
response }` checks the touch (`SigninService.stepUp`), then in one
transaction ends the session it came in on, conditionally, moves the
replay mark and issues the new session, confirmed, with the old one's
account and end; `passkey.check` entries, allowed or denied. A touch whose
challenge cannot move the replay mark, since a newer one signed in with
the same passkey meanwhile, ends the step-up (`state_mismatch`), its
transaction rolled back so the old session stands: a step-up, like a
sign-in, never offers another touch on a challenge no touch can answer
(review r12 of #500); the page's next step-up asks a fresh one. PR 5's fresh
check is the same transaction from another door.

A touch at sign-in does the same with the session cookie the browser
answered with, when it is the person's: the transaction that moves the
replay mark and issues the new session ends it too, and a cookie already
ended is no refusal there, since a sign-in needs no session. The route's
sign-out after a sign-in, which swallows its failures, is left for
another person's cookie: before, a vault or database failure, or a crash,
between the new session and that sign-out left a copy of the old cookie
alive (review r3 of #500).

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
  the public suffix list themselves: `co.uk` for `coffre.acme.co.uk`, or
  `workers.dev` for `coffre.workers.dev`, passes startup and the browser
  refuses it (`SecurityError`). coffre does not ship the list (weekly
  releases, 130 KB minified in every isolate, and a copy older or newer
  than the browser's refuses what the browser takes, or the reverse); the
  first passkey asked for, the Owner's as the deployment is set up, fails,
  and the page says `passkeys.rpId` must be the host or a registrable parent.
  Nothing is stored under the refused RP ID, so fixing the config loses
  nothing. A `publicUrl` whose host is no valid
  RP ID (an IP address, `127.0.0.1`) with a policy other than `off` fails
  at startup: no browser would make a passkey there, and every risky act
  would be out of reach.
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
- **As built (PR 4b).** The dev stack serves at `http://localhost:3000`
  (`dev/start.sh`, its `wrangler.jsonc`), and `COFFRE_DEV_PASSKEYS` sets
  its policy, `optional` unless said. Under it the Owner,
  `admin@acme.example`, adds a passkey at the seed's sign-in (section 2's
  rule for Owners, which this section predates), so a person or an agent
  signing in as the Owner by hand needs that passkey: the seed's browser
  keeps the keys it adds in a file of the stack's state, and `node
  dev/passkey.mjs <DevTools WebSocket URL>` hands the Owner's to a Chrome
  as a virtual authenticator while it runs (`agent-browser cdp-url` gives
  one); `COFFRE_DEV_PASSKEYS=off` is the dev IdP alone. A key in the file
  keeps its counter, which each signature moves: Chrome's virtual
  authenticator counts up from the one it is given and the helper writes
  Chrome's back after each touch (`WebAuthn.credentialAsserted`), so the
  seed's browser, the next run of the helper and Chrome go on from one
  count, never back to an older one, which section 7.3 refuses (a synced
  key's counter, always 0, did, once Chrome had signed with it). The
  restore drill and conformance run at `localhost` too, each with its own
  software authenticator.

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
   row's `user_handle`. Absent or null means none; an empty one is refused,
   since no `user.id` is empty. That is spec fidelity, not a guard (the
   credential ID already names one person's row): if a real client ever
   spells "no handle" as an empty buffer, treat it as null.
5. `clientDataJSON.type` is `webauthn.get`; `challenge` equals the
   state's; origin and `crossOrigin` as in 7.1.
6. `authenticatorData` is at least 37 bytes; `rpIdHash` is SHA-256 of the
   `rpId`; flags: UP set, UV set, BS set only with BE set; AT clear; ED, if
   set, followed by well-formed CBOR, whose extensions are ignored.
7. The signature verifies over `authenticatorData ‖ SHA-256(clientDataJSON)`
   with the stored key and algorithm. ES256 signatures arrive DER-encoded
   and are turned into the raw form WebCrypto takes.
8. The counter and the replay mark move, in one statement (7.3).
   Under the head, a mark that does not move means this challenge is spent
   for that passkey (a sign-in that committed though its answer was lost,
   or a newer one's), or its counter stood still: no touch of it can
   answer the challenge again, so the sign-in ends (`state_mismatch`, its
   cookie cleared) and the page sends the person to sign in again, rather
   than ask for touches that cannot pass (review r5 of #500).

For a registration, steps 1, 2 and 5 (with `webauthn.create`), then:
`authenticatorData` with AT set, UP and UV set, BS only with BE; the
attested credential ID 16 to 1023 bytes and unused across the instance and
by this person (`excludeCredentials` is the browser's courtesy, not a
check); the COSE key one of the three algorithms asked for, with valid
parameters (EC2 on P-256, OKP Ed25519, RSA of 2048 to 4096 bits: a
larger modulus would spend a Worker's CPU on one verify), its
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
Erwin's answer to open question 5 (D170): `required`, and not a setting.
`USER_VERIFICATION` in `@coffre/core/identity` is the one place it is
spelled: what `create()` and `get()` ask for, and what the verifier holds
every response to, with no way for a caller to ask for less. The verifier
checks it last (the order is in the header of
`packages/core/src/identity/webauthn.ts`), so a `user_verification` refusal means the
response passed every other check.

## 8. The app authenticates, the vault authorizes: where the check lives

`architecture.md`: "The app decides who someone is. The vault decides what
they may decrypt." A passkey is about who, so it is the app's. The question
is whether the vault should also refuse a role change or a credential issue
that no fresh passkey confirmed. Three options:

**A. The app decides (proposed).** The router enforces `FRESH_ROUTES`; the
vault decides nothing about passkeys. It is not untouched, though: it
writes personal tokens, handles and service tokens itself (`issueToken`,
`IssuedTokenRow`), so its issue contract grows to copy the issuing
credential's `passkey_id` onto them, with its statement and its model
(R45), a PR of its own (section 14). The audit entries of every guarded act
name the passkey and the time it confirmed. As built, one call of the
vault's applies the app's passkey rule too (T216, section 6.2): a use by
name, which releases values before the app sees its rows, holds a
person's credential to the policy the app sends, as it holds it to the
rest of what the app's config accepts. The rule stays the app's; the
vault applies it where the app's own check would come too late.

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

What coffre needs fits in under 400 lines in `@coffre/core/identity`
(`packages/core/src/identity/webauthn.ts`, `verifyRegistration` and
`verifyAssertion`):

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
fixtures, copied as data (`packages/core/test/vectors/webauthn.json`); one
negative fixture per step of 7.2 (`packages/core/test/webauthn.test.ts`); a
software authenticator, `@coffre/conformance/authenticator`, which writes
its own CBOR and makes real Ed25519, P-256 and RSA registrations and
assertions for the tests, `dev/browser.mjs` and conformance; and property
tests where a flipped bit in any signed byte, a changed origin or a changed
RP ID must fail (`packages/core/test/webauthn-properties.test.ts`). The
choice is worth revisiting if that checklist grows past what 400 lines
hold; the library stays the fallback.

Measured on this machine, Node 24: one assertion's verification, parsing,
key import and signature included, costs 0.25 to 0.3 ms of CPU for each of
the three algorithms.

A refusal names the check that failed: `malformed` (the response's shape,
its encodings, CBOR or JSON, anything trailing), `type`, `challenge`,
`origin` (with `crossOrigin` and `topOrigin`), `rp_id`, `user_presence`,
`user_verification`, `backup_state`, `credential` (an attested ID out of
bounds, or an assertion by another credential than the row's), `user_handle`,
`algorithm`, `key` and `signature`. The caller adds what it decides itself:
`unknown_credential` (no live passkey of the person's has that ID), `replay`
and `counter` (section 7.3).

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
comparison. Where the vault's call reads the credential (a use by name, a
key write, an add), that call reads them too (section 6.2, T216). Issues
take the person's lock, an advisory lock no other request waits on.

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
| `passkey.rename` | its person renames one (PR 6a) | passkey ID, name |
| `passkey.check` | a fresh check or a step-up, allowed or denied; a removal's touch, denied | passkey ID, purpose, the session ended and the one issued; on deny, the reason: the verifier's (section 9), or `unknown_credential`, `replay` or `counter` |

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

  As built (PR 5b): the router's check, let through on a touch, records
  what confirmed the request (`ApiContext.confirmed`): the session's
  passkey and its `confirmedAt`, or, for an MCP client's change, the
  touch that approved it (`McpVia.touched`). The app's entries take it
  in `allowed`, beside `credentialId`; every vault call carries it in
  its correlation (`correlated`), which the vault copies into the
  entries it writes, as it copies `credentialId`, and a first add's
  change and a token's issue keep it in their payloads, under the
  vault's MAC, for the audit page (`confirmed`); accepting lost
  entries hands it to the audit watch, whose `audit.loss_accepted`
  names it, and a link hands it to its `account.link`. Recorded, never
  weighed. A **holder** act let through on a fresh session names it
  too; one let through because the person holds no passkey names
  nothing, as does every act the check does not guard.

A `403 fresh_check_required` or `401 passkey_required` writes no entry; it
goes to the process log (section 4.5).

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
22. Under `required`, on an empty database and on a cold vault, through the
    deployment's real HTTP entry, the Owner the config names signs in, adds
    a passkey and lands; a provider sign-in that stops at the passkey leaves
    no session, identity, passkey or member of its own making (what the
    door's settling writes on a cold start, the same for any first request,
    is not counted).
23. A device code approved without a passkey redeems nothing once its
    person adds a first passkey, whatever happens to that passkey after.
24. `?dryRun=1` on a route that takes none, from a session not confirmed in
    the last five minutes, is `403 fresh_check_required` and changes
    nothing.
25. An MCP consent whose session a removal ended meanwhile connects
    nothing.
26. A role that may use a protected environment's key but not read it
    reveals no value of it, from a browser session confirmed a moment ago
    as from a personal token or an MCP client: a passkey widens no
    read (section 4.3).
27. The configured Owner of check 22 signs in again with the passkey added
    there.
28. A pending sign-in or enrollment whose provider's issuer the deployment
    replaced, under the same provider ID, before the passkey answered,
    completes nothing.
29. An `enroll` state used once, its passkey then reset by an Owner, used
    again within its five minutes, enrolls nothing.
30. Under `optional`, an unscoped Owner without a passkey is asked to add
    one at sign-in; a Developer is not.
31. An MCP approval, and an MCP client's consent, from a session confirmed
    a minute ago but without their own assertion, decide nothing, and the
    approval stays pending.
32. A write that loosens a key's nature, from a session not confirmed in
    the last five minutes, is `403 fresh_check_required` and writes
    nothing; the same write keeping the nature goes.
33. A deployment whose `publicUrl` is an IP address, with passkeys not
    `off`, does not start.
34. An MCP-approved service token issues, with its approval's touch, and
    the same touch approves nothing else after.
35. A handle issued while a removal of its person's passkey runs is
    revoked with everything else, or refused, never live after; on the
    previous release's vault during a rollout too, whose issue takes the
    same lock (section 6.3).

## 14. Build plan (phase 2, after 0.15)

1. **The verifier**, in `@coffre/core/identity`, with its vectors, a
   negative fixture per step of 7.2, the software authenticator and
   property tests. No wiring.
2. **Storage**: the migrations, the schema, the MAC kinds, `pnpm
   test:schema` and the backup grant.
3. **The vault's issue contract** (built): `issue_token` under the
   person's factor lock (section 6.1), for personal tokens, handles and
   service tokens, carrying `via`'s passkey; the previous release's
   signature the same statement carrying none (section 6.3); its model,
   `formal/Factor.tla`, with review r12's sweep-against-issue interleaving
   (R45). Also D170's user verification, hard-coded (section 7.4). The
   app's own issues take the same lock in PR 4.
4. **Sign-in**: `signin({ passkeys })`, the startup RP ID check, the
   callback's split, `/auth/passkey` and its page, enrolling under
   `required` and for Owners under `optional`, the configured Owner's
   first sign-in, the person's factor lock and the revocations of section
   6.1, the per-request check, the check before named reveals, the step-up,
   the seed's authenticator, and AGENTS.md's sign-in URL
   moved to `localhost`. Waits for #436 and T171, which touch the
   callback. Built in two: 4a (#497), the server's side, every check and
   the model's app side; 4b, the ceremonies, the startup check and the
   dev stack.
5. **Fresh checks**, built in two. 5a, the ceremonies: a touch for one act
   (approving a terminal, connecting an MCP client, approving its change),
   asked by the act's own `403 touch_required`, on its own page, and the
   terminal it approves confirmed when it was. 5b (built): `FRESH_ROUTES`
   and its `handler` answer, the dialog over the step-up's door, the CLI's
   step-up through 5a's device approval, the link checks, and signing in
   to add a first passkey (`?passkey=add`), which an act asks of a person
   with none under `optional` until Account → Passkeys adds one in place.
6. **Management**: Account → Passkeys, the Owner reset, the prompt under
   `optional`. Built in two: 6a (built), the API's side, as sections 3.6
   and 3.7 say; 6b (built), the pages.
7. **Conformance** checks of section 13, and docs: `docs/deployment-auth.md` (the policy, `rpId`, recovery and its log review, the `optional` takeover
   case) and `docs/offboarding.md`.


Each PR leaves `main` shippable: until PR 4, nothing is reachable.

## 15. Open questions for Erwin, answered

Asked on 2026-11-03 (D170); Erwin answered the same day. Each question as
asked, shortened, and his answer.

1. **A per-act touch or a five-minute window?** Proposed: the window, with
   three exceptions that take a touch of their own: approving a terminal
   (section 3.5), approving an MCP client's change and connecting an MCP
   client (section 4.4). **Answer: as proposed.**
2. **Owners under `optional`.** Proposed (section 2): no fourth mode, but
   unscoped and configured Owners sign in as under `required`, so the
   accounts that matter most never wait for their first risky act to get
   a passkey. **Answer: as proposed.**
3. **Recovering the last Owner: `off`, a config exemption, or a deployer
   command?** Proposed: a deployer command, `coffre-server passkeys reset
   <email>`, with `off` as the fallback. **Answer: neither the command nor
   an exemption**: no new concept and no new CLI for recovery. Another
   unscoped Owner resets (instances keep two), else `passkeys: 'off'` and a
   redeploy, documented (section 3.7).
4. **`protectedReveals`: phase 3, and what tokens may do under it.**
   Proposed: phase 3, off by default, tokens refused under it. **Answer:
   drop it entirely**, no option and no later phase: an option nobody
   asked for. Protected environments keep today's rule, and passkeys add
   nothing to reads (section 4.3).
5. **User verification: `required` or `preferred`?** Proposed `required`:
   a touch then means the person, not someone at their unlocked laptop.
   **Answer: `required`**, hard-coded in one place, not a setting (section
   7.4).
6. **Fresh checks behind Cloudflare Access?** Proposed: not in phase 2;
   Access deployments use Access's own MFA policies. **Answer: as
   proposed.**
7. **How much do passkey changes sign out?** Proposed (section 6.1):
   adding a first passkey ends everything no passkey confirmed, and
   removing one signs the person out everywhere else. **Answer: as
   proposed.**
8. **The vault (section 8).** Proposed: A now, C designed with the vault's
   next model for Owner-level acts. **Answer: as proposed.**
9. **A touch per MCP approval.** Proposed (section 4.4): a touch for every
   approval and every MCP client connected, by anyone who has a passkey,
   secret writes included. **Answer: as proposed.**
