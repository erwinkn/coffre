# Release notes

## Unreleased

- **Copy a secret without revealing it.** A hidden value now has a Copy button
  beside Reveal, for whoever may reveal it. It reads the value the way Reveal
  does, with the same audit entry, and puts it on the clipboard exactly as
  stored, newlines included, without showing it: the mask stays. If the copy
  fails, the button turns red and the row says why.
- **A revealed value breaks only at its newlines.** A long token no longer wraps
  mid-word; it scrolls sideways inside the value, so the row and its buttons
  keep their place. A multi-line value, a PEM for one, shows one line per line.
- **A new service account's page opens without an error.** Its row in the
  list asked how it signs in before the server had made it, and its page
  then showed that "Not found" until a refresh. The row now waits for the
  account to be made, and making it reads again whatever was asked of it.
- **A user's or service account's tabs switch at once.** The page reads
  what every tab shows but the activity log when it opens, and each tab
  takes it from there, refreshing it behind the page, rather than waiting
  for the network. The activity log loads in place.
- **The audit page has one control for what it lists: Actions, Everything
  or Denials.** It replaces "All events / Denials only", whose two halves
  both showed as selected, and the "Show detail" switch. Everything adds
  sign-ins, tokens and the vault's key operations; Denials lists every
  refusal, those included, so a refused sign-in now shows there.
- **Shorter copy.** The Verified badge says "Audit log verified by the app
  and vault keys, last signature at …". A deployment-declared Owner's lock
  says "Owner defined by the deployment configuration." The service
  account page drops the explanations under its sign-in sections, its
  access and its activity, and an empty activity log, a person's too, says
  "Nothing yet".
- **The header's project and environment are each one button.** The project's
  tile, slug and chevron open the list of projects; the environment's slug and
  chevron open its siblings. The project's own page, all its environments, is
  the project ticked in its list, archived or not. Each entry in the two lists
  starts loading its page as it is pointed at or reached by keyboard.
- **Projects and environments go by their slug alone.** Pages, lists, the
  command palette and the CLI show the slug; New project, Add environment,
  Rename and a project's Settings no longer ask for a display name. Renaming
  is now giving a new slug, which changes the path: `coffre projects rename
  market --slug marketplace`. The API's `name` stays, for older CLIs:
  optional on `PUT /projects/:project` and `PUT /projects/:project/:environment`,
  where it defaults to the slug, still taken by `PATCH`, and still returned,
  though nothing shows it. The CLI still takes `--name` and says it ignores
  it; `rename` with `--name` alone changes nothing. The MCP tools
  `create_project` and `create_environment` ignore a `name`, so a call
  approved before the upgrade still matches its approval. The column goes in
  a later release.

## 0.6.1 (2026-10-16)

- **Shift+Enter types a line break in a secret's value.** A value could only
  become multi-line by pasting one. In the value field of a new or edited
  secret, Shift+Enter now inserts a line break at the caret, over any
  selection, and the field turns into the focused textarea, its caret after
  it. Enter alone, Cmd/Ctrl+Enter (save) and Escape are as they were.
- **A deployment-declared Owner shows a plain Owner tag.** People no
  longer adds "· set by deployment" after it. To another Owner, the tag
  is greyed, with the hint "Set by deployment" on hover or tap, or by keyboard;
  everyone else sees the normal tag. The Users table also keeps which
  Owners the deployment names, so their row shows the lock in place of the
  menu (it showed the menu, which the vault then refused).

## 0.6.0 (2026-10-16)

**Owners replace root admins.** Root admins were emails in the vault's
configuration that held everything, outside the member table and its
rules: nobody could change or remove them, and they showed in People only
because the vault said so. Now there is one kind of principal. The most
anyone holds is the Owner role with no scope, an Owner of the whole
instance: a member like any other, in People, changed by the same rules.

- **The instance always has an Owner.** The last Owner of the whole
  instance cannot be demoted, narrowed to a scope, or removed, by anyone,
  themselves included: "you're the last Owner of the whole instance: make
  someone else an Owner first" (409, `last_owner`). An Owner of one
  project doesn't count. Two changes at once, each about a different
  Owner, never leave none: the vault counts under the log's head, and
  `formal/Coffre.tla` checks it.
- **The deployment declares its Owners.** The vault's `owners` (`OWNERS`
  in a deployment `coffre init` writes) lists people who are Owners of the
  whole instance whatever the database says. The vault makes each one an
  Owner who is not one yet as it starts (every deploy, Worker isolate or
  Node restart) and when they sign in, logged as the vault's ("the
  deployment names them one"). While listed, nobody demotes, narrows or
  removes them, themselves included (403, "the deployment names
  omar@acme.example an Owner (owners, in the vault's configuration): take
  them off that list and deploy first"), and Users shows them "Owner · set
  by deployment". Taking an email off the list demotes nobody: they stay an
  Owner, one like any other. So setup and recovery are one step: on a new
  instance the first listed person to sign in becomes the Owner, and the
  rest follow at the vault's next call; when no Owner can sign in any more,
  or someone with the database demoted one, add an email you control,
  deploy, sign in. A row written around the vault adds nobody to the list,
  which lives in the deployment's code. Keep it to people you would trust
  as Owner. `bootstrapOwners` (`BOOTSTRAP_OWNERS`) and 0.5's `rootAdmins`
  (`ROOT_ADMINS`) are read until 0.7.
- **Only Owners make Owners.** Making someone an Owner, scoped or not,
  and changing or removing an Owner take an Owner of the whole instance:
  an Admin of all of it does neither (403, `not_allowed`), and People
  offers it no Owner to set or remove. An Owner of the whole instance may
  step down, the one role change anyone makes about themselves, unless
  they are the last, or the deployment names them. The vault decides it under both rows' locks, so an
  Owner demoted meanwhile makes nobody an Owner.
- **A wrong vault key is an outage.** A vault given the wrong key checks
  no member's row, the Owner's included, so every member's request answers
  503 and nobody signs in, with the reason in the app's log, where before root
  admins got through to a `wrong_kek` answer and everyone else was refused
  as tampered ([restore.md](docs/restore.md#if-the-vault-key-is-wrong)).
- The API's `isRootAdmin` and the `root-admin` instance role are gone, as
  is the vault's `root_admin` refusal. The vault's `about()` answers
  `rootAdmins: []` until 0.7, so a 0.5 app deployed after it keeps listing,
  adding and removing members meanwhile.
  Settings no longer lists root admins; Users does, as Owners.

**Upgrading from 0.5.** Nothing to migrate, and nothing to change first:

1. **`coffre update`**, then **`coffre migrate`**, which applies nothing.
2. **Deploy.** The vault's first call makes every email its configuration
   names (`rootAdmins`, `ROOT_ADMINS`) an Owner of the whole instance, as
   `system:vault`: a member row for one who never signed in too, so nobody
   loses what they held, and again at every start while you list them.
   Someone you took off the list before upgrading is not made an Owner, nor
   is anyone 0.5 let in as a root admin whom the list no longer names,
   rolled back to 0.5 and forward included. A root admin who still held
   grants on every project of 0.4 has them converted as anyone's first,
   then becomes an Owner: `coffre migrate` lists the grants. The vault
   reads 0.5's entries by its keys, so keep any vault key it replaced in
   `previousKeks`, as always.
3. **Check Users**, where your root admins are now Owners, set by
   deployment: take those who should not be off the list, deploy, and
   demote them; make Owners of anyone else who should run coffre.
4. **Optionally, rename the setting**: `rootAdmins` and `ROOT_ADMINS` are
   read until 0.7. In `vault/src/worker.ts`, `owners:
   env.OWNERS.split(',')`, and the var in `vault/wrangler.jsonc` (on Node,
   `src/vault.ts` and `vault.env`); `coffre setup` keeps whichever name
   your vault reads.

Rolling back to 0.5 leaves the new Owners Owners, and makes the listed
emails root admins again, as long as the vault's code still passes them as
`rootAdmins`: 0.5 refuses to start without it. Roll back the rename of
step 4 with it.

**How old each value is, and which are due for rotation.** An
environment's Last written column says when each value was last written
("ada · 7mo ago", the exact time on hover), and sorts the table by it, as
the Key column sorts by name; below 44rem the two sort controls stay, a row
above the stacked keys, and every row shows its age. A rename, a move into a
folder or a new reference never counts as a change: the age is the current
version's. A reference's value is its source's, so its age is the source's
current version's, and its source rotated is its value rotated; one that
reads nothing (broken, its source archived or empty) has none. The row
shows "source · 1y ago", and who made the reference on hover, where it
showed who made it and when.
A value unchanged for more than `rotateAfterDays` whole days gets a quiet
Rotate tag, its age in days on hover. `createCoffre({ …, rotateAfterDays })`
sets it for the deployment: 365 if left out, `null` for no flag, and
anything but a whole number of days from 1 fails the deployment's start.
There is no per-project setting: one threshold is the audit's, and
`--older-than` asks any other. `coffre list` prints each value's age, "214
days ago", and "(unchanged over 365 days: rotate it)" after those due;
`coffre list market/prod --stale` lists only those, and `--older-than 90d`
those older than any age, as text or `--json`, archived keys and keys
without a value never among them. `GET /api/secrets/market/prod` answers
`rotateAfterDays` beside the keys, and a reference's `updatedAt` is its
source's current version's, where it was `null`; `updatedBy` stays `null`
for one. `ageInDays` and `olderThan` in `@coffre/client` are the rule both
use.

**The CLI picks the instance by directory.** With several instances, a
company's and your own, `coffre login <url>` pins the directory it ran in
to that instance, for it and every directory below, as well as making it
the default. A command then uses `--url`, else the nearest pinned
directory's instance, else the default, so `~/Code/acme` talks to
secrets.acme.example and `~/Code/mine` to your own, without `--url` or
another login. `coffre whoami` says why: "on https://secrets.acme.example
(pinned at ~/Code/acme)", or "(the default)"; `coffre use` lists the
directories pinned to each instance and stars the one used here. A
directory pinned to an instance you are not signed in to says to sign in
there, and never uses the default's session instead, nor does a command
that cannot tell which pin applies (a pins file it cannot read, or reached
through a symbolic link, or a directory removed since): it stops, and
`--url` names the instance. `coffre login` with a session the instance
still knows keeps it and only pins (`coffre logout` first for a new one;
only the instance saying it does not know the session starts a new
login), and one in your home directory sets the default only. `coffre
logout` unpins the instance's directories. The pins live in
`~/.coffre/directories.json`, beside the sessions rather than in their
file, so a CLI before this one, which rewrites the sessions' file in the
shape it knows, keeps every session and never drops a pin; it ignores
them and uses the default everywhere.

**A repository names its instance in `coffre.json`.** Commit
`{ "url": "https://secrets.acme.example" }` as `coffre.json`, and every
clone uses that instance below it with no `--url` and no pin: a command
uses `--url`, else the nearest pin or `coffre.json` above the directory,
your own pin first in the same one, else the default. The file picks the
URL only. Commands still send that instance's own session, so a fresh
clone's first one says `not signed in to https://secrets.acme.example,
which /home/ada/Code/acme/coffre.json names`, and `coffre login`, with no URL,
signs in there after saying which file named it, pinning nothing.
`whoami` and `use` say `named by ~/Code/acme/coffre.json`. A CI run's
`--service` needs no `--url` there either: its ID token is asked for that
URL, which no other instance takes. A secret handed to `coffre login`
(`--token`, `--access-client-id`, `--id-token`) still goes only to a URL
you name. A `coffre.json` that is a link, holds anything but `"url"`, or
names something other than an origin stops the commands below it, with
its path. One in your home directory or above it is ignored.

**A deploy can stop on a key the other environments have.** Add
`STRIPE_WEBHOOK_SECRET` to `market/staging` but not `market/prod`, and
`coffre missing market/prod --check` lists it ("STRIPE_WEBHOOK_SECRET in
staging") and exits 1, so `coffre missing market/prod --check && coffre
run market/prod -- ./deploy` stops before anything is read. A key the team
dismissed never fails it, and with `--json` it fails the same way. The
Action takes `require-complete: true` (default `false`): it checks each
environment it reads, and stops the step before exporting, with an error
annotation per environment listing its missing keys
([ci.md](docs/ci.md#a-key-the-other-environments-have)).

**Key names are visible across a project.** Missing keys are now compared
with every other live environment of the project, not only those the
caller reads: the page's strip, `coffre missing`, `GET
/api/projects/market/prod/missing` and the gate above all show a reader of
`market/prod` that `market/staging` has `STRIPE_WEBHOOK_SECRET`. That is how
a CI token that reads only prod can check it is complete. Anyone who reads
one environment of a project can now learn the key names of its other
environments, and which of them the team dismissed, but never their
values. Values are unchanged, and other projects are never compared.

**An OIDC binding can require a GitHub environment.** Name one, such as
`production`, and only jobs that run in that environment sign in, after
its protection rules (required reviewers, the branches it deploys) let
them through. Set it under "GitHub environment" in the Trust dialog, with
`coffre trust … --github-environment production`, or as the `environment`
claim over the API and MCP. GitHub changes `sub` for such a job
(`repo:acme/api:environment:production`), but no GitHub binding reads
`sub`: `ref`, `workflow_ref` and `job_workflow_ref` are unchanged, so the
plain and the reusable-workflow profiles both work with it.
GitHub's environment names ignore case, so a binding for `production`
also takes a job in `Production`; they are one environment, with the same
rules. The name is checked as GitHub takes one: at most 255 characters, no
control character, no space at either end. The binding's summary, `coffre
trust`'s description of it and its audit entry ("…, in GitHub environment
production, reaching …") name it. Existing bindings are unchanged and take
jobs in any environment, or none, as before. `githubWorkflow` and
`githubReusable` in `@coffre/core/workloads` take an optional `environment`.

**The Trust dialog finds a repository's IDs itself.** Type `acme/api` and,
once you pause or leave the field, coffre asks GitHub for its IDs. It then
shows the repository and its owner as confirmation, spelled as GitHub
spells them: `Acme/API` becomes `acme/api`, as the runs' `workflow_ref`
names it. The ID fields appear only when GitHub shows nothing, behind
"Private repository? Enter IDs", with the `gh api` command that prints
them. For a reusable workflow called from any repository of the
organization, the field asks for the organization, `acme`, and finds its ID
the same way; `coffre trust --any-repository` looks it up too, instead of
requiring `--owner-id`. Each name is asked once per page. GitHub answers
60 lookups an hour to a server that does not sign in, which every user of a
Workers deployment shares; once they are spent the dialog says so and
offers the ID fields. `GET /api/workloads/lookup` takes an owner as well as
a repository, answers with GitHub's spelling, and answers 429 when GitHub's
limit is spent and 503 when GitHub does not answer, where it said 404 for
both. In `@coffre/client`, `WorkloadIds` gains that answer,
`{ github, ownerId }` with no `repositoryId`: code that read a GitHub
answer's `repositoryId` after checking only for `github` checks
`'repositoryId' in ids`.

**Events are chosen in a combobox.** The GitHub events and GitLab pipeline
sources a binding trusts were a row of checkboxes. Now you type to filter
and choose with the arrows and Enter, each chosen one a chip that Backspace
removes. `pull_request` and `workflow_run` are marked "unreviewed code" in
the list, and the warning under the field still says what each exposes.

**A project's Add service account makes a new one too.** The dialog
lists the service accounts you could grant, and as you type a name no
account has, offers it as a new one, last: "Create and grant access" makes
the account with that grant, in one vault decision. A grant refused (more
than you hold, a role only a project takes, an account someone else
removed) makes no account either, so none is left behind holding nothing,
and the row says why in the vault's words. Anyone who sets up service
accounts sees the list and the new option, not only admins: a project's
Owner picked from a list where before they typed a name.

- **API.** `PUT /api/members/token:<name>` takes `{ "access": { "market/prod":
  "viewer" } }`, the first grants as `PATCH /api/access` takes them, and
  answers their `changes` beside `created`. A person, or `access` with a
  `role`, is a 400. The vault's `setAccess` takes `admit`; a vault older
  than the app refuses it (`not_a_member`) and admits nobody, so a
  deployment whose Workers update one after the other never makes an
  account without its grant.
- **CLI.** `coffre admit api-deploy --service --grant market/prod=viewer`,
  repeated or a comma list.
- **MCP.** `admit_member` takes `access`; its approval page shows each grant.

**Pick a repository, private ones too, where a CI run is trusted.** A
trust binding names a repository by its IDs, and coffre looked up only a
public one's: a private one's were typed, from `gh api`. Now a deployment
may pass a GitHub App, installed on its organizations, as
`workloads.github`. In "Trust a workload", the Repository field then
offers every repository the app is installed on, private ones marked, as
the name is typed; picking one fills in its IDs at once, with no lookup.
For a reusable workflow called from any repository, the Organization
field offers the accounts it is installed on. A name the list lacks is
typed whole, and resolves through the app, or through GitHub's public API
outside it, as does a name given to `coffre trust`. Installed nowhere
yet, or reaching no repository, the dialog says so and links to the app's
installation page; GitHub down, it says so and the name can still be
typed. `GET /api/workloads/repositories` is the list, `{ "app": null }`
without an app, for whoever may set up a service account. The app needs
Metadata: read-only, which every GitHub App has, and no one's personal
token. [docs/github-app.md](docs/github-app.md) registers, installs and
passes it. The key stays in the app's configuration and memory, never in
the vault, the database, a log line or an answer.

**One GitHub App signs people in and lists repositories.**
`githubApp({ appId, privateKey, clientId, clientSecret })` makes the
deployment's app once, and the deployment passes the same value to each
side: `github({ app, organization: 'acme' })` signs in with its OAuth
client, `workloads: { github: app }` lists with its key. Neither side
picks up the other's credentials, and each works alone: `github({
clientId, clientSecret })` as before, or an app with no client for the
list only, with people signing in with Google, say. A deployment `coffre
init` writes signs in with `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`
as before, and with `GITHUB_APP_ID`, a var, and `GITHUB_APP_PRIVATE_KEY`,
a secret of the app Worker, makes the app from all four for both. Its
permissions are Metadata, Email addresses and, with `organization`,
organization Members, each read-only; the organization check passes only
where the app is installed. When GitHub will not show the organization's
members (403), the sign-in is refused as before, and the server's log now
says why: the app lacks Members, or is not installed there. The sign-in
page's message for it names both remedies. GitHub Enterprise Server signs
in with an app, and `workloads.github` refuses its API, as the list's
IDs would be bound to github.com's issuer.

**The add-person dialog says what it asks.** Its field is "Email", not
"Cloudflare Access email", whichever way people sign in, and its description
of the role is gone: the role field under it already says what each role
holds. "Instance role" is "Role" in every label, and each role's hint
reads "Default permissions: …" ("None" for a Member), then "Project grants
add more."

**A row waiting on the server no longer spills over its neighbours.** In the
Users, Service accounts, grants and secrets tables, "Saving…" and
"Removing…" stood in for the row's menu in a column that fits only the
menu, and ran into the role column. Now the spinner stands there alone, the
words stay for screen readers and as its tooltip.

**Generate a secret's value in the browser.** A new secret's value field,
and an edited one's, has a Generate button. It opens a dialog that makes the
value with Web Crypto, in the page, and Use puts it in the field as if typed:
nothing is sent until the row is saved, through the same write as any other
value. It makes:

- **a random value**, 1 to 256 bytes of entropy (32 by default), as letters
  and digits (base62, each character drawn uniformly), hex, base64 or base64
  URL (unpadded). The dialog says how many characters that is and how many
  bits it holds: 32 bytes are 43 characters of base62, 256 bits.
- **an AES-GCM key**, 256 or 128 bits: the raw key, base64.
- **a key pair**, ECDSA or ECDH on P-521, P-384 or P-256: the private key
  (PKCS #8, base64) is the row's value, and the public key
  (SPKI, base64, as the private key is PKCS #8) is saved with it, under a name of its own that follows the
  first (`JWT_PRIVATE_KEY` gives `JWT_PUBLIC_KEY`). The public key is part
  of the row's edit, as the row says under its value: the row saves, or
  is cancelled, whole, in one write, so a new private key never lands
  beside the old public key. Typing over the value drops the public key.

**Pasting a multi-line value keeps its line breaks.** A new secret's value
field, and an edited single-line one's, is a text input, and a text input
drops the line breaks of what is pasted into it: a PEM private key pasted
there was saved on one line, and no longer parsed. Now a paste holding a line
break goes into the value whole, and the field becomes a textarea, focused,
its caret after the paste, and stays one until the row is saved or
cancelled. Line breaks are saved as `\n`: a `\r\n` from a Windows clipboard
becomes `\n`, as a textarea and PEM and `.env` tooling read them. Masking is
unchanged. Fields that already held a multi-line value were textareas, and
still are. Conformance pastes a key in Chrome (`pasted values`).

**`coffre get` no longer adds a newline when piped.** It printed the value
and a newline whatever stdout was, so `coffre get app/prod/KEY | wc -c`
counted one byte more than the value, and a secret copied that way into
another store (`… | scw secret version create … data=@-`) held a trailing
newline too. Now, with stdout a pipe or a file, it writes exactly the
value's bytes, newlines the value holds included, as `printf %s` would; in a
terminal it still ends the line. `$(coffre get …)` strips trailing
newlines itself, so it is unchanged. A script that removed the added
newline (`| head -c -1`) now cuts the value's last byte: drop that step.
One that relied on it (`coffre get … >> file`) adds it back with `echo`.

## 0.5.1 (2026-10-11)

**`coffre update` moves a deployment with the new release's pages.** The
deployment's own CLI, `pnpm exec coffre update`, belongs to the release
it moves from, and it used that release's list of pages. So 0.4's CLI,
moving a deployment to 0.5.0, left out the new `users.$user.apps.tsx`,
and running it again added nothing, since the deployment was at 0.5.0 by
then. Now a CLI of an earlier release asks the new release's own CLI,
`coffre update --plan <dir>`, which pages it adds and retires and which
versions its Start app and pnpm take. That runs the new release's code, so
it asks first: "Move this deployment from 0.5.1 to 0.5.2, with the pages
and pins its own CLI says, and install it?", then moves it as that CLI
says, without asking again. `--yes` answers for CI; without a terminal
and without `--yes`, nothing runs. npm installs that CLI in an empty
directory of its own, with the deployment's `.npmrc`, so it is the
registry's package the deployment's install fetches, never a copy of the
same version that a project or the global prefix has, as `npx` would run.
Its answer is checked whole before anything changes: page files only in
`app/src/routes/`, each as the deployment has it now; only the Start app's
packages, at exact versions; an exact pnpm. Fields this release doesn't
know are left out. When that CLI can't say, nothing changes and the update
exits 1. CLIs before 0.5.1 don't ask, so to move a deployment from 0.5.0 or
earlier, run the new release's CLI: `npx @coffre/cli@latest update`. A
deployment that 0.4's CLI moved to 0.5.0 still lacks the page: copy
`app/src/routes/_coffre/users.$user.apps.tsx` from
`node_modules/@coffre/cli/dist/templates/<workers or node>/`, then build,
which writes the route tree.

**`coffre migrate` names the role that owns the tables.** A login that
neither owns coffre's tables nor is a member of the role that does used
to get as far as Postgres's "permission denied for schema drizzle". Now
it stops before asking, with the owner and the fix: "coffre's tables are
owned by X, and this login, Y, is neither it nor a member of it: migrate
with X's connection string, or, as a role that administers it, run GRANT
"X" TO "Y" WITH INHERIT TRUE". A member of X that doesn't inherit its
privileges (NOINHERIT) is told so, since a plain GRANT would leave it
unable to migrate. Only the `drizzle` schema and the objects coffre's
migrations make count: another table in `public`, whoever owns it, is the
database's own. With nothing to apply, a login that can still read the
tables gets only a warning, so it can be fixed before the next migration
needs it. `coffre setup` and `coffre-server migrate` refuse the same way.

**CI runs `pnpm test:compat` again**, for both kinds: the newest release,
now 0.5.0, must stay conformant on each change's schema.

## 0.5.0 (2026-10-11)

**Upgrading from 0.4.** This release changes what people and service
accounts hold, so read what `coffre migrate` says before you deploy. The
steps are the usual ones ([Upgrading](docs/deploy.md#upgrading)):

1. **`coffre update`**, in the deployment's directory. It moves the pins
   and adds the new `users.$user.apps.tsx` page.
2. **`coffre migrate`** applies `0002_instance_roles` and
   `0003_credential_scopes`, and 0.4 keeps serving on both. Then it lists
   two things. First, each grant on every project, with what the vault
   will replace it by and anything it loses: "service:deploy: maintainer
   on every project → maintainer on market; not projects made later; loses
   access-manager on market (keeps maintainer)". Second, each service
   account's 0.4 tokens and trust bindings, which keep what the account
   holds when 0.5 first checks them. An account that holds nothing is
   flagged: "which will reach nothing: grant the account before you
   deploy". The pipeline runs it right before the deploy, so run it
   yourself first, from the deployment's directory, and read the lists.
   To choose otherwise, grant, revoke or regrant on 0.4, then run it again
   to check.
3. **Deploy in one step.** The first request converts every grant on every
   project, one member at a time, each logged as `system:vault`. A 0.4
   instance owner becomes an Admin, and the root admin stays root admin.
   Each 0.4 token and binding is sealed the first time it is checked
   (`token.seal`). A 0.4 instance still serving during a rollout answers
   401 to anything 0.5 has sealed.
4. **Check `/readyz`**, then the Audit page or `coffre verify log`.

Scripts that call `coffre grant '*'`, `coffre revoke '*'`, `coffre admit
--owner`, or `PUT /api/members/<member>` with `{ owner }` stop working.
Use roles and scopes instead (below). OIDC bindings need nothing: each
existing one keeps working as a binding on its one event. Rolling back to
0.4 is not an undo. It refuses every sealed token and binding, and every
member who is no longer a Member or an Admin, until they are replaced.

**Instance roles with scopes replace grants on every project.** Each
person has one instance role, Member, Auditor, Developer, Admin or Owner,
which applies in every project its scope takes in, the ones made later
too. A scope has two filters, Projects and Environments, each all, only
some, or all except some; environments match by name, so "Developer,
environments only dev" reads and writes every project's `dev`. Admin is
0.4's instance owner: it manages people, projects and access, and holds no
secret permission; Owner adds every secret. An Admin of the whole instance
can still reach any value, as a 0.4 owner could, by admitting a service
account, granting it a reading role and issuing its token, each step in the
log. A scoped Admin manages only inside its scope and sets no role, and
nobody changes their own role or grants themselves one, which 0.4 let an
owner or an access manager do: that stops a quiet read of one's own, not
an Admin set on reading. Grants are on a
project or an environment, and only add to the role. Service accounts hold
grants only. `*` and `*/<env>` are gone from the API, the CLI, the MCP
tools and the pages: the vault replaces the ones there are when this
version first runs, never giving more than they did, and logs each
(`docs/design/instance-roles.md` has the rule). It takes away nothing it
can keep in the projects there are now: viewer on `*` beside auditor on
billing becomes viewer on each of billing's environments, beside the
auditor grant. Where no grant can hold both, as maintainer on `*` beside
access-manager on billing for a service account, the one that reads stays.
`coffre migrate` says what it will make of each before you deploy, and
names what is lost: "loses access-manager on billing (keeps maintainer)".
A member the vault has reported tampered with is left as they are, until
their access next changes or they are started over. `coffre migrate`,
which holds no key to tell the vault's reports from forged ones, marks
such a member and still says what the conversion would be, so a forged
report never hides one the vault makes.
The first request after the upgrade converts every member holding one,
one after another, before it answers, so on an instance with many it may
be slow; one cut short leaves the rest to the next.

- **API.** `PUT /api/members/<member>` takes `{ role, scope }` instead of
  `{ owner }`; members list `instanceRole` (`member`, `auditor`,
  `developer`, `admin`, `owner` or `root-admin`) and `scope`, null but for
  those who run the instance, since a scope names projects, and a
  place's list says who reaches it by their role (`reachesByRole`).
  `GET /api/me` adds `scope` and `runsInstance`. `GET /api/members/<member>/access`
  answers a member's role, scope and the grants you manage in one query: a
  person's or service account's Access tab reads it once, not one list per
  project (`coffre access <member>`). Making a project or an
  environment no longer answers `inherited`, nor `GET /api/projects`
  `everyProject`. Refusals of what only an Admin or Owner of the whole
  instance may do log `requires_instance_admin`.
- **CLI.** `coffre admit <email> --role <role>`, with `--projects`,
  `--except-projects`, `--environments` and `--except-environments`,
  replaces `--owner` and `--no-owner`. `coffre grant '*'` and
  `coffre revoke '*'` are gone.
- **MCP.** `admit_member` takes `role` and `scope`; `set_access` takes
  projects and environments.
- **Schema.** `0002_instance_roles` adds `role` and `scope` to
  `vault_members`, and lets the vault's login update them. Rolling back to
  0.4 leaves Members and Admins everywhere as they were; anyone else is
  refused until removed.

**Anyone who holds access sets up service accounts for it.** Setting up
CI took an Admin of the whole instance; now a person who holds access adds
a service account, gives it grants, issues its tokens and trusts its
workflows by OIDC, with no Admin. They give it at most what they hold
themselves: a Developer of every `dev` gives `developer` on `market/dev`,
never `maintainer`, nor `market/prod`. They manage an account only while
they hold everything it holds, so a dev Developer issues no token for an
account that also reads prod; one that holds nothing yet is its maker's. A
new setting, **Who sets up service accounts**, keeps the rest to Admins:
environments all except prod, and prod's CI takes an Admin whose scope
takes in prod. Only those who run the instance change it, and each change
is logged with what it was. Service accounts is in the sidebar of anyone
who sets one up, listing only the accounts they manage. A person brings
back only an account they removed themselves. The setting names
environments by slug, so a Maintainer who renames `prod` takes it out of
`all except prod`, or, renaming `staging` away first, into `only dev,
staging`, for an environment they already hold: both lists follow the
current slug, and only keeping renames from them keeps prod to Admins.
Settings written into the log in the vault's name but not by it are
reported and passed over, and when the vault finds none of its own past
them, the setting is closed, never everywhere.

- **API.** `GET` and `PUT /api/settings`, `{ "serviceAccounts": <scope> }`.
  `GET /api/me` adds `setsUpServices` and `serviceSetup`; members and a
  member's access add `managed`. Removing a member answers its `report`
  only to those who run the instance (null otherwise). A refusal to
  someone who does not manage the account logs `not_service_manager`.
- **CLI.** `coffre settings`, and `coffre settings service-accounts` with
  the scope flags `coffre admit` takes. `coffre offboard` removes an account
  you manage.
- **MCP.** The service account tools are listed to anyone who holds access,
  and checked against the account; the setting is changed in the pages and
  the CLI only.

**Each service token and OIDC binding has its own scope.** A scope is
grants, as the account's are: `developer` on `market/dev`, `viewer` on
`market/prod`. It is set when the token or binding is made, at most what
the account holds and what you could give it, and all the account holds
unless you narrow it, by leaving places out or choosing a smaller role. A
request made with it reaches what both the scope and the account hold:
an Admin who later gives the account prod gives it to none of the tokens
and bindings made before, and narrowing the account narrows them all at
once. The server checks the scope for the pages, the CLI and MCP alike,
and the vault decides on it as well. It never changes: to change one,
make another and revoke the first. Someone who made one and then lost
access shrinks nothing, so CI keeps working; offboarding them lists the
tokens they issued, each with what it reaches. An account needs a grant
before it gets a token or binding, since nothing it is given later
reaches one made before. A binding that replaces others, by `--replace`
or because its issuer moved its keys, reaches what they reached unless
told otherwise; on the page, Trust a workload's picker then starts from
it. The tokens and bindings of 0.4 keep exactly what
they reached: the first time this version checks a credential, it gives
each one its account's grants then, after the conversion of grants on
every project, and logs it (`token.seal`); one a 0.4 instance makes while
both run gets its account's grants on its first use. `coffre migrate` lists them
before you deploy, and says which would reach nothing because their
account holds nothing. Rolling back to 0.4 refuses them, and so does any
0.4 instance still serving while 0.5 rolls out: it answers 401 to every
service token and CI run 0.5 has sealed until it is replaced, so deploy
in one step, or expect those to fail for the length of the rollout.

- **API.** `POST /api/members/<member>/tokens` and `/bindings` take
  `scope`, paths to roles as `PATCH /api/access` takes them; the tokens,
  bindings and offboarding's `issuedTokens` lists say each one's `scope`,
  and `token.create` and `token.bind` log it. A scope past the account or
  past you is refused, logged as `beyond_account`; one names at most 1000
  places. `POST …/tokens?dryRun=1` answers what the token would reach, and
  issues nothing, as `…/bindings?dryRun=1` does.
- **CLI.** `coffre tokens issue` and `coffre trust` take
  `--scope market/dev=viewer,…`; `coffre tokens`, `coffre trust
  <service>` and `coffre offboard` say what each reaches.
- **MCP.** `issue_service_token` and `trust_workload` take `scope`, and
  the approval page says what the token or binding will reach, as the
  server would make it: a scope past the account is refused before anyone
  is asked. If that changes before Approve, as when the account is given
  another grant, Approve is refused and the page shows it again; Approve
  makes the token or binding with the scope the page showed, so a grant
  landing just after reaches neither.
- **Schema.** `0003_credential_scopes` adds `scope` to `credentials` and
  `service_bindings`, and lets the app's login update it.

**An Auditor of the whole instance reads the whole log**, the instance's
own entries too: sign-ins, people, service accounts, settings. It verifies
the log, as `coffre verify log` and the Audit page do, and runs nothing it
reads about. A scoped Auditor still reads only the places in its scope.

**One OIDC binding per workflow, on several events, pull requests
included.** A GitHub binding now lists the events it trusts, so a workflow
that runs on push, by hand and on a schedule is one entry, not three. It
may also trust `pull_request`, matched by the branch the pull request
merges into, and `workflow_run`. Both can run code nobody reviewed: the
form, `coffre trust` and the MCP approval page say what each exposes when
it is chosen. Pull requests from forks get no ID token. `pull_request_target`
is still refused. Existing bindings keep working as they are, each a
one-event binding. GitLab bindings list pipeline sources the same way, and
`coffre trust --event a,b` now makes one binding, not one for each.
`@coffre/core/workloads`' `githubWorkflow`, `githubReusable` and
`gitlabProject` still take one `event` or `source`, as before, and now
also a list, `events` or `sources`; naming both, or neither, is refused.

**A person's connected apps are a tab of their page**, for owners, beside
Access and Activity. A deployment gains `users.$user.apps.tsx` through
`coffre update`.

**Shorter explainers.** "Sign in with OIDC" and "Bearer tokens" say what
each is, when to use it, and give one example.

**Hyperdrive's connection limits now fit the database.**
Left at Cloudflare's default, 60 per config on Paid, the app's and the
vault's configs together could outgrow a small database such as
PlanetScale's smallest, which then refused the connections a burst of
requests needed ("remaining connection slots are reserved", 53300). A
user's or service account's Access tab and the service accounts list each
send one request per project or account at once, and some of them failed
as "coffre is unavailable". `coffre setup` now reads the database's
`max_connections`, less what it reserves, and sets each config's connection
limit to half of what is left after 3 for the administrator (at most 20),
so that a burst waits in Hyperdrive instead. Cloudflare treats the limit as
a soft one, which a network failure can briefly exceed. It says how it chose, as in "max_connections
25, 3 reserved, 3 kept for the administrator and migrations: 9 each". A
run on an existing deployment lowers a higher limit, and keeps one set
lower. On a Workers deployment, setup refuses a database too small for
Hyperdrive's 5 per config right after asking for its URL: before it asks
about Cloudflare, so before any domain, custom hostname, login, password or
config changes. Without Cloudflare, its update commands set the limit too,
since setup can't see what each config allows now: it says to check each
with `wrangler hyperdrive get <id>` first, and to leave the flag out for one
set lower on purpose. To fix one now,
without setup: `wrangler hyperdrive update <id>
--origin-connection-limit=<n>` for each config.

**`coffre setup` refuses before it changes Cloudflare, as long as the
database holds still while it asks.** For
an address whose DNS is elsewhere, served through one of the account's
domains, setup made the fallback origin, its DNS record and the custom
hostname before three of its refusals: a Worker without its key over a
database that holds data, an administrator who can't create roles, and a
login that another deployment's Hyperdrive config uses on the same server,
whose message then said "Nothing was changed". Setup now checks the
administrator right after connecting, before it asks about Cloudflare, and
the other two once it has read the account, before its first change there,
adding a domain included, then again right before the logins change, in
case the database changed while setup asked its questions. That last
check comes after Cloudflare's changes, so a refusal it makes, for a
database that took data or a login another deployment uses meanwhile, can
still leave the domain, fallback origin, DNS record and custom hostname
behind; its message now says "Neither login was changed". A run after
reuses whatever a refused one left. Its Hyperdrive step also gives each config's own
connection limit when one set lower was kept ("connection limits of 5 and
7"), where it said "20 each".

**A project whose grants could not be read keeps its row** on a user's or
service account's Access tab, with the error and a Retry button. Before, a
notice sat above the table and the project's row was missing, as if the
member held nothing there.

## 0.4.6 (2026-10-07)

**MCP approvals are harder to misread or misuse**, after a security review.
`trust_workload`'s page names each ID it binds, as github.com's or
gitlab.com's API reads it back, or says to check an ID it can't name; any
other issuer is flagged, and its IDs are left for the person to check.
What the app wrote is shown as the app's ("The app calls it"). With Reveal values, the page no
longer promises the app never sees a value: it says the app can read it.
Approve refuses a page gone stale, when a version was set or a role, or
its end, changed since it was shown. Identical calls at once open one approval, and a burst
stays within five waiting. An approved change whose outcome was lost is
reported as unknown, never as "nothing changed", and the person is warned
before approving it again. The approval page's API takes only a browser
session: a CLI session, which an agent on the same machine may hold, can't
open or decide an approval. A change the person can't make is refused
before an approval opens, and a client's decline is logged.

## 0.4.5 (2026-10-06)

**`run_with_secrets` is gone from the MCP tools.** It only wrote out a
command, which the model can write itself. The server's instructions now
tell the model to run `coffre run <project>/<env> -- <command>` in the
person's terminal, with the CLI signed in, so values reach the process and
never the conversation.

**Shorter copy across the pages, the CLI and the MCP tools.** Sentences that
explained mechanics, hedged or repeated what the page already shows are cut;
warnings and the facts a person acts on stay. The consent page no longer
opens with a lede, says "30 days" for how long a connection lasts, and says
only that a new connection replaces the earlier one. `coffre update` ends
with how this deployment deploys: a push to main when it has
`.github/workflows/deploy.yml`, else `pnpm run deploy`, or a restart on
Node. `coffre whoami` puts MCP and CI sign-in on lines of their own.

## 0.4.4 (2026-10-06)

**An MCP client lists only the tools its person's roles reach.**
`tools/list`, in both protocol eras, leaves out the tools no role the
person holds reaches anywhere: a viewer's client no longer offers
`set_access`, `admit_member` or the audit log, and an access manager's no
longer offers values. A tool their roles allow but the connection's scopes
don't stays listed, so a client can still step up to it. The list is
computed per request from what the token check already read, and its
cache hints are now `cacheScope: "private"` and five minutes, not public
and an hour, so a role granted or taken shows within minutes. Calls are
checked as before: a hidden tool called by name is refused as it was.

**A Workers deployment deploys on every push.** `coffre init --workers`
writes `.github/workflows/deploy.yml`: on each push to `main`, it installs
the deployment as its lockfile says, migrates the database with
`printenv DATABASE_OWNER_URL | pnpm exec coffre migrate --yes`, then runs
`pnpm run deploy`, one run at a time. In a clone of a GitHub repository,
`coffre setup` wires it after deploying: it makes the Cloudflare API token
the workflow deploys with, scoped to the account's Workers Scripts, Account
Settings, Workers KV and Hyperdrive and the zone's Workers Routes, and sets
the repository's Actions secrets `CLOUDFLARE_API_TOKEN`,
`CLOUDFLARE_ACCOUNT_ID` and `DATABASE_OWNER_URL` through GitHub's API, each
sealed to the repository's public key by libsodium's `crypto_box_seal`
(libsodium-wrappers 0.8.4, bundled in the CLI). wrangler's login may not
make API tokens, so setup usually prints the dashboard's token form, filled
in, and checks the token you paste before taking it. It signs in to GitHub with
gh's login, or a fine-grained token that lasts a day, and shows no value.
Run again, it keeps the token; `--rotate-deploy-token` makes a new one.
Without a GitHub remote, it says how to wire it later. Workers Builds stays
documented as the alternative (docs/deploy.md, "Deploys on every push").
A deployment made by an earlier `coffre init` gets the workflow from
setup, to commit.

## 0.4.3 (2026-10-06)

**`coffre update` writes the route tree with the route files it adds.** A
release that adds or removes a page file left the committed
`app/src/routeTree.gen.ts` stale until the next build rewrote it, so an
update's diff was incomplete: 0.4.2's account tabs were four new route
files and a tree that did not name them. Update now regenerates the tree
once it has installed the release, through the deployment's own Vite and
TanStack Router, as its build does, shows it among the changes, and lists
it with the files it changed.

**The MCP tool `read_secret_values` is `reveal_secret_values`**, to match its
scope, Reveal values. No alias is kept: a client that called the old name
gets an unknown-tool error, and finds the new one in `tools/list`.

## 0.4.2 (2026-10-06)

**The account page is in tabs, and shows how to connect Claude.** Profile
(who you are, and the accounts you sign in with), Sessions, Connected apps
and Appearance are routes under `/account`, as a project's tabs are, each
reading only what it shows. Connected apps opens with **Connect an app**:
this instance's MCP URL, `https://<your instance>/mcp`, to copy; Claude
Code's `claude mcp add --transport http coffre <url>`, then `/mcp`; and
claude.ai's steps. It shows only where the deployment turns MCP on.
`coffre init` writes the tabs' four route files,
`_coffre/account.{index,sessions,apps,appearance}.tsx`, and `coffre update`
adds them; `_coffre/account.tsx`, unchanged, is now their layout.

**`GET /me` says where MCP clients connect.** `features.mcp` is the MCP
endpoint's URL, built from the deployment's public URL as MCP's metadata
builds it (`https://secrets.acme.example/mcp`), where it was `true`, and
`null` where it was `false`. Connect an app shows it as the page is
rendered, not once it loads, and `coffre whoami` says it: `MCP clients are
on, at https://secrets.acme.example/mcp`. A page's tab bar now ends where
its cards do.

**`coffre run` and `coffre export` read several environments.** `coffre
run deploy/prod auth/prod -- ./deploy` gives the command both
environments' keys, where it took nesting one `coffre run` in another,
and the inner one's key won when both had it. Every environment is read,
one audited read each, or none is: the CLI first lists each one's keys,
which reads no value, and stops if it may not read one, if one holds a
reference that cannot be read, or if two define the same key, naming the
key and both environments, never a value. `coffre export` takes the same
list, in each format, and the Action's `environment` input takes several,
separated by spaces or lines ([docs/ci.md](docs/ci.md#several-environments)).
Both commands now refuse a secret's path, `market/prod/KEY`, where they
name an environment: `run` read the whole environment for it.

**MCP's scopes are Read, Write, Reveal values and Manage access.** Browse
is now Read, and Read values is Reveal values, on the consent page, the
account's Connected apps, the tools' answers and the docs. Their OAuth
scopes follow: `read`, `write`, `reveal` and `manage-access`, where
`browse` and `read-values` were. A connection made before holds Read
alone: disconnect it, and connect again to grant the others.

**You pick a connected app's scopes when you connect it.** Clients ask for
Read alone, and Claude Desktop did not ask for more, so a connection could
read and nothing else: every write tool, approval link and
`request_secret_value` was refused. coffre's consent page now lists all
four scopes, Read, Write, Reveal values and Manage access, with what the
client asked for ticked, and grants what you tick. The token answer's
`scope` says what was granted, and `mcp.connect` in the log records what
was asked for and what was granted. A tool call short of its scope still
answers `403 insufficient_scope` for clients that step up, as Claude Code
does, and its body is now the tool's result: which scope it needs, and how
to grant it, by connecting the app again and ticking it
([docs/mcp.md](docs/mcp.md#scopes)).

**A base64 secret pasted on its own line is not imported under its own
text.** Base64 that starts with a letter is a valid key name, and its
padding supplied the `=`: `c2stbGl2ZS0xMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW4=`,
a 32-byte key, read as that key with an empty value, and
`c2stbGl2ZS0xMjM0NTY3OA==` as that key with the value `=`. `coffre import`
and the web app's import now refuse both, as lines they can't parse, named
by their number alone. **An empty value must be quoted:** `KEY=""` or
`KEY=''` imports as empty, and a bare `KEY=` is refused with `no value:
write KEY="" for an empty one`, since it can't be told from that padding.
An unquoted value of only `=` is refused too. **In an unquoted value, a `#`
after whitespace starts a comment**, as dotenv has it, found before the
value is trimmed: `KEY= # later` has no value, and is refused as a bare
`KEY=` is; it read as `# later`. `KEY=a #b` is `a`; `KEY=#fff` and
`KEY=a#b` keep their `#`. `coffre export` quotes any value that would read
differently unquoted, so its files import back as they were. A key is one
exactly when the API's `secretKey` says so.

**coffre's logo for the GitHub App setup makes.** Neither an app's
manifest nor GitHub's API sets a logo, so setup can't. Once it has made the
app, it prints where to upload one, the app's settings page, under Display
information, and the file: coffre's mark as a 512px PNG on its black tile,
which `@coffre/cli` now ships, at
`node_modules/@coffre/cli/assets/github-app-logo.png` in a deployment.

**The CLI says why it could not reach an instance.** It said only
`could not reach https://…: fetch failed`. It now gives Node's own reason,
with its code and address, such as `getaddrinfo ENOTFOUND
secrets.acme.example`, and what to try for the common ones: a name that
does not resolve here, IPv6 this network does not carry, and a
certificate that something in between presents. `@coffre/client` throws
`Unreachable`, saying the same, in place of `fetch`'s bare `TypeError`,
and `coffre verify instance` says it once, at its health check.

**`coffre import` no longer prints a line it can't parse.** It printed the
line's text, which can hold a value: a line with no `=`, or a key that is
not one, may be a secret pasted on its own. It now says the line's number,
why, and its key when it has a valid one; so does the web app's import.
`ParseProblem` in `@coffre/core/dotenv` has `key` in place of `text`.

**`coffre setup` survives a Hyperdrive config deleted while it runs.**
Setup lists the account's configs as it starts. A config deleted after
that, whose login was getting a new password, made the update answer 404
and stopped setup. It now makes the config again and says so. When the
login kept its password, which setup can't read, the run stops and says to
run setup again, which gives the login a new password and makes the config.

## 0.4.1 (2026-10-06)

**`/access` is gone.** It only sent links from before 0.4.0 on to
`/users`. `coffre update` deletes its route file,
`app/src/routes/_coffre/access.tsx`, from a 0.4.0 deployment, unless the
deployment changed it, and `@coffre/ui` no longer exports its `access`
route options.

**An owner sees a person's connected apps.** A person's page lists, to
owners, the MCP apps they connected, under **Connected apps**, and each can
be disconnected there. The member report (`GET /api/members/<member>`) has
`apps`, and `live.apps` counts them. Removing someone disconnects their
apps, not only through the generation: the removal dialog and `coffre
offboard` name them and count them first, and `revoked.apps` says how many
went. Re-admitting someone revokes the apps of their earlier membership
too, so none is listed again.

**Node: a vault in its own process no longer fails a call now and then.**
The server keeps its connections to the vault's socket open, and the
vault's HTTP server ended one idle for six seconds, Node's default. A call
the server sent on it at that moment failed with ECONNRESET, and its
request answered 503 "coffre cannot check who you are right now". The
vault now leaves idle connections open, for the server's next calls.

## 0.4.0 (2026-10-06)

**0.4.0 is a clean break.** There is no upgrade from 0.3 or earlier: deploy
0.4.0 afresh, on a new database, and bring over what you keep with
`coffre export` ([deploy.md](docs/deploy.md#from-a-release-before-040)).
The schema starts again from one baseline per engine, which only a new
database takes; `coffre migrate` refuses a database an earlier release
made, saying so. Folders are a `folder` column on projects and secrets, and
the last of 0.1's syncs is gone from the schema, the vault and the audit
page.

**Migrate, then deploy; never the other way.** Below the migrations its
release ships, the app answers everything but `/livez` and `/readyz` with
503 `migrating` (an HTML page for a browser), `/readyz` stays red, and the
scheduled job reports the same; it checks once per isolate or process,
until it holds. The per-feature checks that let a release run on the schema
before its migrations are gone, with the 503s they answered. With Workers
Builds, both Workers' builds now start with `printenv DATABASE_OWNER_URL |
pnpm exec coffre migrate --yes`, the app's too, each with the
`DATABASE_OWNER_URL` build variable ([Workers Builds](docs/deploy.md#workers-builds));
`coffre setup` says so. `coffre migrate` runs only in a deployment's
folder: its instance mode, the CLI's daily "migrations pending" line and
the pages' "Database migrations pending" banner are gone, as nothing
serves with migrations pending, and `GET /api/me` no longer reports the
instance's version and migrations. `pnpm test:compat` is off in CI for
0.4.0 and returns for 0.5.0, against 0.4.0.

**No code for releases before 0.4.0.** `coffre update` moves deployments
from 0.4.0 on, and leaves an older one as it was, saying to deploy afresh;
its 0.1-to-0.2 move to a Start app of its own is gone, with the 0.1 entry
points `coffre(env => …)` and `serve({ … })`, which threw to say so. The CLI
no longer refuses the `COFFRE_*` variables earlier CLIs read: it reads no
variable at all, as before, and says nothing of them.

**MCP and values.** `read_secret_values`, with the Read values scope only,
sends a secret's or an environment's values to the client, its answer
warning first that they are now part of the conversation; the vault logs
the reveal under the connection. `show_secret_value`, with Browse, shows the
person a value on coffre's approval page when they press Reveal, and never
sends it to the client. `generate_secret_value`, with Write, has coffre make
a random value on its own server when the person approves (base64url, hex
or alphanumeric, 16 to 128 characters; 32 bytes in base64url unless asked),
which nobody sees.

**MCP changes, each approved on coffre.** A client with the Write scope
can ask to set a secret to a value the person types (`request_secret_value`),
rename, archive, unarchive and restore secrets, and create projects and
environments; with Manage access, change a member's access, admit and
offboard members, issue and revoke service tokens, and trust and untrust
CI workloads. None changes anything when called: it opens an approval, and
the person decides it on coffre's page, `/approvals/<id>`, which shows the
app, the change and what it replaces; Approve makes the change there, once,
as the person through the connection, and its entries name the client and
the approval (`via.approvalId`), beside `mcp.approve` or `mcp.deny`. A
client on MCP 2026-07-28 that declares URL elicitation, Claude Code among
them, is asked to open the page and retries with a MACed `requestState`
bound to its connection and call; any other, claude.ai among them, gets the
link in the result and calls again with the same arguments, 2025-era
clients included: no client is read-only for its protocol version. Approvals
expire in five minutes, a connection holds five at once, and only their
person decides them, with the digest of the change the page showed. No tool takes a value; a token is shown on the
page only. A consent that grants all of an earlier connection of the same
client and more supersedes it once its code is redeemed (`mcp.disconnect`,
`superseded`), and a registration no connection names is revoked after a
week. Migration `0001_mcp_approvals` adds the approvals' table.

**Folder commands.** `coffre folders` lists the folders of projects and
what is in each, and `coffre folders market/prod` an environment's key
folders, both with `--json`. `coffre folders rename Clients Customers`
re-files every project in a folder (`… market/prod stripe payments`, every
key), and onto a folder in use merges the two; `coffre folders remove`
takes everything out of one, each item staying where it is, in no folder,
and previews when more than one would move. A folder is still a label,
there while something is filed in it: no schema change. The API's
`PATCH` and `DELETE /api/folders/<folder>` and
`/api/folders/<project>/<environment>/<folder>` do the same, in one
transaction under the log's head, one `project.move` or `secret.move` per
item; renaming a folder of projects takes `project.manage` on every
project in it. Folder headings in the projects list and in an
environment's keys have Rename and Remove folder in their menu. The
README's CLI section shows archive, unarchive and rename for keys,
environments and projects on lines of their own, and what `coffre roles`
prints.

**Settings read, not inferred.** `GET /api/me` reports what the
deployment's configuration turns on, `features: { mcp, workloads }`, and
the account page (Connected apps), a service account's page and the
directory (trust bindings), conformance and `coffre whoami` read it: a 404
from a feature's route is an ordinary error again. `coffre apps` says when
MCP is off on an instance. Every refusal the app logs now answers with its
reason too (`principal_not_registered`, `missing_secret_read`, …), which
the CLI's hints branch on, and the server's messages name a service account
`service:<name>` themselves. The consent page's describe call, asked with a
browser cookie, must come from coffre's own page, as a change must, so
another site cannot make coffre fetch an app's document, whatever the
path's spelling (`/api//oauth/authorizations/`); the page's own render
still reads it, when it is opened on its own rather than embedded in
another site. An MCP connection's client name, host and kind, and
a registration's name, are under their rows' MACs.

**MCP clients connect.** coffre is now an OAuth authorization server for
MCP clients such as Claude, which connect at `<PUBLIC_URL>/mcp` as the
people who approve them (docs/mcp.md). A client is known by its metadata
document, as Claude publishes one, or registers itself, and then shows as
Unverified; a registration's custom-scheme redirects are left out. The
consent page, `/oauth/authorize`, shows the client's website, where the
answer goes, and the scopes asked for, Browse always; nothing is granted
until the person approves, every time. Codes are PKCE-bound and last a
minute; access tokens last an hour and are good at `/mcp` only; refresh
tokens rotate, and one presented again, like a code redeemed twice, ends
the connection. The account page's Connected apps, and `coffre apps` and
`coffre apps revoke`, list and disconnect them; an owner may disconnect
anyone's. Each connection, token and disconnection is in the log under the
client's name, tokens as detail. `/mcp` speaks MCP 2026-07-28, stateless,
and answers a 2025-11-25 or 2025-06-18 client's `initialize` without a
session. Its tools browse: `whoami`, `list_projects`, `list_secrets`,
`secret_history`, `list_access`, `describe_member`, `read_audit_log`, and
`run_with_secrets`, which says how to give a command its secrets with
`coffre run` and puts no value in the conversation. Each tool is API calls
as its person, so it can do no more than they could; a call through MCP
reaches only the API routes its connection's scopes allow, and none of a
person's own sign-in. Every call is logged under the client (`mcp.read` for
a read that went through, as detail; `mcp.call` for a refusal), and the
API's own entries name the connection. `coffre init` turns it on with
`signin({ mcp })` and three limits: on Workers, the rate-limiting bindings
`MCP_PER_SOURCE`, `MCP_PER_CONNECTION` and `MCP_TOTAL`; on Node,
`processLimits()`, which now takes `perConnection` too. `coffre update`
adds the three route files to an older deployment, which turns MCP on
itself (docs/deploy.md, "MCP clients"). Migration `0010_mcp_connections`
adds the clients' and connections' tables; until it runs, connecting
answers 503.

**Missing keys.** An environment's page lists the keys its sibling
environments have and it lacks, compared only with those you can read: key
names are metadata. Each has Add, a new row with its name, and Dismiss,
plus Dismiss all; a dismissal is the team's, logged, and listed under
Dismissed with Restore. `coffre missing market/dev`, `coffre missing dismiss
market/dev/KEY` (or `--all`), `coffre missing restore`. Migration
`0009_dismissals` adds their table; until it runs, nothing is dismissed and
dismissing answers 503.

**References.** A secret can be a reference to another, in another
environment or project: `coffre set billing/prod/DATABASE_URL --ref
market/prod/DATABASE_URL`. Whoever reads `billing/prod` reads market's
current value through it, rotations included, without a grant in market:
a reference is a decision, taken by someone who reads the source and writes
where it is held. The vault makes each one, as a `reference.create` entry
under its MAC, and checks that entry at every read, so a reference row
written around the vault reads nothing. One hop: a reference never points
at a reference. Market's owners and access managers see every reference
into market, and who reads through it (`coffre references market`,
`coffre access market/prod`), and break one with `coffre references break`,
as can whoever writes where it is held.
A read through a reference is market's read, in market's log and its
offboarding report, and billing's too. A reference that cannot be read,
broken, or its source archived or deleted, stops the whole `run` or
`export`, saying why and who can fix it, rather than run without it.
Archiving what a live reference reads, the key, its environment or its
project, is refused (409) until the reference is broken, so archiving
never silently breaks another project's runs; the refusal names each
reference and who can break it, and the archive dialogs list them with
Break. A reference held inside what is archived does not block it, nor
does one held in a key, environment or project archived already (D58):
nobody reads through it, and if its holder is unarchived later, its key
shows "Source archived" and reads refuse saying how to fix it. A reference belongs to the environment that
holds it, like a value, not to whoever made it: removing them ends none,
and their offboarding report lists the references they made, read from the
log. A reference the vault sealed for a write that then stored nothing is
ended at once, `abandoned`, so no row written later can revive it. `coffre fork
--reference` makes each key a reference to its parent's. Migration
`0008_references` adds one app table and indexes on the log; until it runs,
making a reference answers 503 (docs/design/environments.md). It builds
four indexes on `audit_log` in the migration's transaction: on a large log,
appends wait while they build, so migrate a busy instance when it is quiet.

**Forks.** `coffre fork market/prod staging` makes `market/staging`, with
each of prod's live keys, its current value and its folder, and none of its
history. Copying is reading: it needs read on prod, and the vault logs one
`secret.read` per key with the purpose `copy`, then a write per key. The
UI's "Add environment" offers "Start from: a copy of prod". If a fork stops
half way, the environment stays, and forking into it again, as long as it
has no live secret, fills it. `PUT /api/projects/market/staging {"name":
"Staging", "from": "prod"}` (docs/design/environments.md).

**Folders.** Projects, and the secrets of an environment, can be filed in
folders, one level deep: `Clients / acme`, `database/`, `stripe/`. A folder
arranges a list and does nothing else: it grants, hides and renames
nothing, and `run` and `export` inject a key by its own name wherever it is
filed. `coffre move market/prod/STRIPE_KEY stripe`, `coffre move acme
Clients`, `--none` to take one out; `coffre list` and `coffre projects`
group by folder; `PATCH` takes `{"folder": …}`. Migration `0007_folders`
adds two tables, so this release runs on the schema before it, listing
everything in no folder and refusing to move until an owner runs
`coffre migrate` (docs/design/environments.md).

**An archived project, or environment, can be deleted for good.** Archiving
hides a place and keeps every value; deleting frees the space and hides it
for good. Instance owners only, and only once it is archived:

```sh
coffre projects delete market                 # what it would erase and revoke; nothing changes
coffre projects delete market --apply         # deleted
coffre environments delete market/old --apply # an environment alone
```

- Every version's ciphertext and wrapped data key is erased, in place, and
  the vault revokes every grant there, lapsed ones too. The preview counts
  the versions and names the grants, and the members left holding nothing,
  a CI service perhaps, with the `coffre offboard` that removes them.
- The vault refuses any key operation in a deleted place, as `deleted`,
  before it asks of any grant, so no grant of any kind reaches into one,
  and grants nothing there afterwards.
- The references into a deleted place, and out of it, are ended, broken,
  and the preview names them.
- An environment is deleted only once it is archived itself. A place
  restored, or granted, while its deletion runs makes the deletion stop
  with a 409, nothing erased; asked again, it revokes the new grant too.
- Two races with a deletion's commit, which a model of the locking
  protocol found, are closed. A rename, archive or restore whose request
  found the place just before it was deleted is refused with a 404,
  where it used to give the tombstone a live slug back. And a read the
  vault had checked just before the place was deleted is refused as
  `deleted`, where it used to release the key after the deletion.
  Adding an environment, or renaming, archiving or restoring a key, under
  a place deleted since the request found it is refused with a 404 too:
  nothing is written to a deleted place.
- What stays is a tombstone of names: the place, its keys and its versions'
  numbers, authors and times, which the audit log names. It is renamed
  `market~deleted-2026-10-05`, so `market` is free for a new project that
  the log never confuses with it, and it is gone from every list, archived
  ones included. `coffre audit` still reads its entries by that name, and
  `coffre verify log` passes after.
- The project's Settings, under Danger zone, and an archived environment's
  menu offer it in the browser, asking you to type the place's path first.
  Backups taken before the deletion still hold the encrypted values, which
  the dialog, the preview and [restore.md](docs/restore.md) say.
- `DELETE /api/projects/market` and `DELETE /api/projects/market/prod`,
  `?dryRun=1` to preview, logged as `project.delete` and
  `environment.delete`. A deletion cut off partway finishes when asked
  again.
- Migration `0006_deletions` widens the slug checks to admit a tombstone's,
  and lets the app empty a version's ciphertext and wrapped key, which a
  trigger makes the only change a version ever takes. It only adds: 0.3.0
  runs on it. Until it runs, deleting answers 503.
**A service account is an identity, not a token.** The CLI and the UI showed
a service as `token:deploy-slides`, so its OIDC trust bindings looked set
"on a token", though OIDC is the way to need no token at all. Now a service
account, a machine identity for CI and other machines, is
`service:<name>` wherever a person reads one: help, output, previews,
refusals, `coffre access`, `coffre audit`, the audit log's sentences and the
UI's pages. It signs in one of two ways, and they are named so: by OIDC (trust
bindings) or with bearer tokens.
- The UI's Tokens page is Service accounts, and a service account's page
  shows "Sign in with OIDC", its trust bindings, then "Bearer tokens".
- The CLI takes `service:<name>`, still takes `token:<name>`, and `--service`
  as before; `coffre admit service:deploy` needs no `--service`.
- The API, the vault and the audit log keep `token:<name>`: the log's signed
  entries hold it. Nothing is migrated, and nothing signed or verified
  changes; `@coffre/client` shows and takes the names at the edge
  (`shownMember`, `apiMember`).

**A sign-in error is said once, and a reload is a clean retry.** The page
coffre sends a refused sign-in back to, `/login?error=…`, renders the
error on the server, then takes it out of the address once its scripts
run, so a reload, or a link to the page, starts over. The same goes for
`/account?linked=…` and `/account?error=…`. Without scripts, a reload
still shows it.

**"Your email already signs in with a different account" names it.** It
now says "Your email already signs in with GitHub. Sign in with GitHub,
then link this account from your account page.", lists several when
there are, and says "another GitHub account" when the address signs in
with a different account at the same provider. Only the providers are
named, never another email or account name, and only to a visitor whose
provider has just verified that the address is theirs.

**Grants on every project.** A member or a service can hold a role on every
project, the ones created later too, or on one environment in every project:

```sh
coffre grant '*' ada@acme.example --role auditor            # every project
coffre grant '*' ci-deploy --role viewer --env dev --service  # dev in every project, never prod
coffre revoke '*' ci-deploy --env dev --service
coffre access '*'                                           # who holds them
```

- Only instance owners and root admins give or take them. They are grants
  like any other: roles (only those an environment can hold go on one
  environment's name), end dates, `access.grant` and `access.revoke` entries
  naming the place as `*` or `*/dev`, and offboarding, which revokes them
  with the rest and counts them in its preview.
- `*/dev` matches the environment's slug when it is used: a project that has
  no `dev` gains one when someone creates it, and renaming `staging` to `dev`
  brings it in. Making a project or an environment, or giving one a new slug,
  answers with who reaches it through them (`inherited`), and the CLI and
  the dialogs say so before you confirm.
- A person's or a service account's Access tab lists theirs, "All projects
  · Developer" or "dev in every project · Developer", and an owner grants
  and revokes them there: "Grant on every project" takes a role, an
  environment name or none, and an end date. A project's access list shows
  who reaches it through them. Each is shown to those who see the grants of
  a project it reaches, owners and that project's access managers, and no
  one else.
- One migration, `0005_instance_grants`: a column on `vault_grants`, and its
  checks loosened to allow these. 0.3.0 runs on the new schema, and this
  release on the old one, where it answers 503 to a grant on every project
  until `coffre migrate` has run.
- **Revoke grants on every project before rolling back past this release.**
  An older vault does not know them, and refuses everyone who holds one, as
  a member whose record was changed around it, until an owner removes them
  (deploy.md for 0.3.0, "Rolling back past grants on every project").

**`coffre trust` from first use.**
- A binding matches one event, and trusting a workflow that also runs by
  hand or on a schedule took one `coffre trust` for each. Now `--event` (and
  GitLab's `--source`) takes several, `--event
  push,workflow_dispatch,schedule`, a binding each, in one go. `push` is
  still the only default.
- The preview says which events the bindings accept, and names the flag
  that adds the others the ref allows: "Accepts runs started by push. Not
  by workflow_dispatch or schedule: add them with --event, as --event
  push,workflow_dispatch,schedule."
- For a private repository, whose IDs coffre cannot look up, it said only
  "not found". Now it says why in a line, then gives the command that gets
  the IDs and the flags to add:
  `gh api repos/OWNER/REPO --jq '"--repository-id \(.id) --owner-id \(.owner.id)"'`,
  and `glab api … | jq …` for a GitLab project.
- `coffre trust` alone prints its usage and exits 0, as `coffre help` says
  it does. A test now holds every command's `--help`, `-h` and `help
  <command>` to exit 0.

`coffre update` and `coffre migrate` without a terminal and without `--yes`
now say "Not a terminal, so nothing to confirm on: pass --yes to update
without asking."

**`coffre untrust` shows what it would end, and ends it with `--apply`**, as
every other command that ends something for good does. The preview names
the binding, its claims, and the CI runs that would lose sign-in, in a
sentence: "GitHub Actions runs of acme/api's workflow deploy.yml, on
branch main, by push would no longer sign in as token:api-deploy, and the
credentials they hold would end at once." A script that ran `coffre
untrust <service> <id>` adds `--apply`.

**wrangler 4.142, and `wrangler dev` stays up.** The Workers deployment's
wrangler moves from 4.118.0 to 4.142.0, with Cloudflare's Vite plugin
(1.50.0 to 1.61.0, which pins it) and the Workers types (5.20260926.1).
Under `wrangler dev` before 4.131, one request that met an idle internal
connection as it closed, about five seconds after the last, or a client
gone mid-upload, ended the whole dev server with an empty `✘ [ERROR]`
(cloudflare/workers-sdk#15203 and #14641, fixed by #15252): a local run, or
`pnpm conformance`, would stop partway. `coffre update` now moves wrangler
and the Workers types with the plugin.

## 0.3.0 (2026-10-05)

**Everything the API does, the CLI does.** The commands that were the
browser's alone:

```sh
coffre projects create market [--name …]       # rename, archive, unarchive
coffre environments create market/prod         # the same
coffre rename market/prod/DB_URL DATABASE_URL   # a secret's key, its versions with it
coffre archive market/prod/OLD_KEY              # unarchive brings it back
coffre admit ada@acme.example [--owner]         # a member; --no-owner ends ownership
coffre admit deploy-slides --service            # a service, for CI
coffre revoke market ada@acme.example --env prod
coffre tokens deploy-slides                     # a service's tokens
coffre tokens issue deploy-slides [--expires-in <days>] [--label …] [--output-file <path>]
coffre tokens revoke deploy-slides <id> [--apply]
coffre sessions                                 # sessions revoke <id> [--apply]
coffre identities                               # identities unlink <id> [--apply]
```

From nothing to a CI service: `coffre admit deploy-slides --service`, `coffre
grant deploy deploy-slides --role viewer --env prod --service`, then `coffre
trust deploy-slides --github … --apply`, or `coffre tokens issue
deploy-slides`. `grant` does not make a member: to one not yet admitted it
says `admit them first, coffre admit … --service`. `tokens issue` prints the
token once, on stdout, and on a terminal says that it will not be shown
again; `--output-file` writes it to a new file, 0600, never one already
there, and prints no token. What ends something for good, a token, a
session or a linked account, is shown first and done with `--apply`, as
`offboard` and `import` are. The lists take `--json`: `projects`, `list`,
`history`, `access` (which takes a place now, `access market/prod`),
`tokens`, `sessions`, `identities`, `audit` and `whoami`.

Approving a `coffre login` stays the browser's, which is what vouches for
the CLI. `packages/cli/src/commands.ts` maps every route of the API to its
commands, or to the browser with why; a route added with neither fails the
typecheck and the parity test, and the test runs every command's `--help`.

Also: `coffre --version` prints the version; `coffre <command> --help` and
`coffre help <command>` print its usage, for every command; a flag a command
does not take, or an argument too many, is refused in a line and its usage,
exit 2, never a stack trace.

**The CLI reads no environment variable, and takes no secret as a flag or an
argument.** `COFFRE_TOKEN`, `COFFRE_API_URL` and the rest used to override the
saved session where no one could see it, and a secret in a variable reaches
every process the shell starts. Now flags configure, and a command that
needs a secret asks for it: at a hidden prompt, with a label (`Database
owner URL`), or, when stdin is no terminal, from stdin, which is where a
pipeline pipes it and a file is redirected. A CI run signs in as a person
does, with `coffre login`, and the commands after it use the session it
saves:

```sh
printf '%s' "$TOKEN" | coffre login https://secrets.acme.example --token
coffre run market/prod -- ./deploy
```

The session flags, before the command, pick another instance than the
current one, `--url`, or sign one command in as a service by its ID token,
`--service`, which on GitHub Actions needs nothing else. A variable an
earlier CLI read, still set, stops the command that read it, in one line
saying what to do instead, rather than leaving the run to go elsewhere, or
as someone else, unseen:

```
coffre: COFFRE_TOKEN is no longer read: unset it; instead, run `coffre login <url> --token` and paste the token, or pipe it in
```

| Before | Now |
|---|---|
| `COFFRE_API_URL` | `--url <url>`, or `coffre login <url>` once |
| `COFFRE_TOKEN` | `coffre login <url> --token`, the token pasted or piped in |
| `COFFRE_ACCESS_CLIENT_ID`, `COFFRE_ACCESS_CLIENT_SECRET` | `coffre login <url> --access-client-id <id>`, the secret pasted or piped in |
| `COFFRE_SERVICE` | `--service <name>`; on GitHub Actions, still nothing else |
| `COFFRE_ID_TOKEN`, `COFFRE_ID_TOKEN_FILE` | `coffre login <url> --service <name> --id-token`, the ID token piped in |
| `COFFRE_AUTH_MODE` | `--auth-mode signin\|cloudflare` |
| `COFFRE_MIGRATE_DATABASE_URL` | `coffre migrate` asks, or the URL piped in: `printenv DATABASE_OWNER_URL \| coffre migrate --yes` |
| `COFFRE_SETUP_DATABASE_URL` | `coffre setup` asks, or the URL piped in |
| `COFFRE_VAULT_KEY`, `COFFRE_APP_KEY` | `coffre verify keys` asks, or both piped in, the vault key's line first |
| `COFFRE_VAULT_KEY_ID` | `coffre verify keys --vault-id <id>`, as before |
| `COFFRE_CONFORMANCE_CANARY` | `coffre verify instance --canary <path>` asks for the value, or it is piped in |
| `coffre set <path> <value>` | `coffre set <path>`, the value asked for or piped in |
| `coffre verify instance --canary <path>=<value>` | the same, the value asked for or piped in |
| `coffre migrate --url <url>` | `coffre --url <url> migrate` |

`coffre logout` forgets a service token's or an Access service token's
session there, and revokes nothing: the token is the service's. A machine
sign-in never replaces a person's session unseen: they sign out first, or
the run signs in from a home of its own. `coffre set` refuses an empty
value, which an unset variable piped in would be, and takes one as it is,
at the prompt or piped, less exactly one final line break. An empty
session flag, which is what an unset variable expands to, an instance named
both as an argument and as `--url`, a session flag after the command, and
one a command has no use for are refused. When the instance does not know
the session saved for it, as after it was reset at the same address, the
CLI says so and names `coffre login <url>`. The GitHub Action's inputs are
as they were; it pipes the token to `coffre login --token`, the CLI in a
home of the step's own, removed when the step ends. On Workers Builds, rename the vault's
build variable `COFFRE_MIGRATE_DATABASE_URL` to `DATABASE_OWNER_URL`, and
its build command to `printenv DATABASE_OWNER_URL | pnpm exec coffre migrate
--yes` ([Workers Builds](docs/deploy.md#workers-builds)). On GitLab, name the
ID token anything but `COFFRE_ID_TOKEN`, and pipe it to `coffre login
--service <name> --id-token` ([docs/ci.md](docs/ci.md#without-a-stored-token)).

**`coffre setup` on Workers takes an address whose DNS is elsewhere.** A
Worker answers only at an address Cloudflare serves, so setup makes it a
custom hostname of one of the account's domains, with Cloudflare for SaaS,
on the Free plan: it keeps or makes the domain's fallback origin, makes the
custom hostname, shows the CNAME and TXT records to add at the address's
DNS provider, and, after the deploy, waits for Cloudflare to see them. A
run stopped there picks up where it left off. With no domain on the
account, setup offers to add one, showing its nameservers, or the Worker's
workers.dev address for now. This needs Cloudflare for SaaS enabled on the
domain. When Cloudflare refuses wrangler's login a call this needs, setup
asks for an API token, hidden, saying which permissions it needs, and its
wranglers deploy under it ([deploy.md](docs/deploy.md#a-domain-whose-dns-is-elsewhere)).

## 0.2.0 (2026-10-04)

**A deployment's app is a TanStack Start app of its own** (0.2.0), a
conventional one, and coffre is a set of pieces it mounts, as an auth SDK's
are. Vite builds the app once, and nothing bundles it again: on Workers,
`wrangler deploy` uploads what Vite built, so no second pass rewrites what
the pages send the browser, as wrangler's `keep_names` did in 0.1.17. On
Node, srvx runs the same build, as TanStack Start documents, and the
vault stays a process of its own. The app's files, as `coffre init` writes
them:

- `app/src/coffre.ts`: the configuration, once, `export const coffre =
  createCoffre(…)`;
- `app/src/server.ts`: Start's handler, each request carrying coffre,
  `handler.fetch(request, { context: coffre.request(…) })`, and coffre's
  scheduled job;
- `app/src/start.ts`: `createStart(() => ({ requestMiddleware: [coffreMiddleware,
  createCsrfMiddleware(…)] }))`. coffre's middleware gives every response
  coffre's security headers and a fresh CSP nonce, and the pages the
  visitor's API client. A server route or page rendered without it fails,
  saying how to add it. Start's CSRF check for server functions, which Start
  drops once an app sets middleware of its own, stays for the app's;
- `app/src/routes/`: Start's file routes. The root, the app's own
  document, with coffre's stylesheet and icons and `<CoffreProvider>`; and a
  file for each of coffre's server routes, layouts and pages, each spreading
  coffre's route options: `createFileRoute('/_coffre/projects/')({ ...projects,
  component: ProjectsPage })`. Start splits each page into a chunk of its
  own, with its preload hints. Delete a page's file to leave it out; add
  files for the app's own pages, under coffre's nav or not. coffre's nav
  offers only the pages there. A page of the app's own may call the API as
  the signed-in visitor, `useCoffre()` in a component or `context.coffre` in
  a loader. An app that prefers routes in code mounts the same options with
  TanStack's `createRoute` ([Your own routes](docs/deploy.md#your-own-routes));
- `app/src/router.tsx`: `createRouter(routeTree)`, Start's generated tree;
- `app/vite.config.ts`: `cloudflare(…)` on Workers, `tanstackStart()`,
  `viteReact()`, and `coffre()` from `@coffre/ui/vite`, which puts the
  pages' files under `/_coffre/assets/` and checks the versions below.

The theme and the folded sidebar are cookies now, `coffre-theme` and
`coffre-sidebar`, which the server reads, so a page is drawn as the visitor
left it from the first byte, with no script of coffre's own before it: a
theme chosen before 0.2, kept in the browser's storage, is chosen once more.
coffre's look is scoped to the element `<CoffreProvider>` renders; the
app's document keeps its own.

React, TanStack Router, Start, Query and Vite are the deployment's own
dependencies now, pinned at exactly the versions `@coffre/ui` is built with;
`coffre update` moves them with coffre's packages, and adds the file of a
page a release adds. On Workers, `pnpm dev` is
now `vite dev app`, the vault beside the app. A refusal no longer waits for
the request's body: nothing in coffre reads what a caller is still sending
before answering.

To upgrade, in the deployment's directory, with the 0.2 CLI:

```sh
npx @coffre/cli@0.2.0 update
```

It moves a deployment whose files are as a release of 0.1 wrote them, its
configuration kept as that release had it, and shows each file it changes
before asking once. It changes nothing when a file is the deployment's own,
or one is already where 0.2 puts its own: it names each, and
Upgrading to 0.2 (deploy.md for 0.2.0) shows the move by hand.
A move cut short is finished by the next run. Then `pnpm typecheck`, and
deploy: on Workers Builds, the app's build command is now `pnpm exec vite
build app` and its deploy command `npx wrangler deploy -c
app/dist/server/wrangler.json`; `pnpm run deploy` does both. On Node,
`pnpm build`, then restart both processes.

## 0.1.18 (2026-10-04)

**Workers deployments: signed-in pages no longer go blank.** wrangler bundles
with esbuild's `keep_names` on, which wraps functions in an `__name` helper
that only the Worker has; seroval, which streams a page's data, writes its own
functions into the page as source, and with them the `__name` calls: in the
browser, `ReferenceError: __name is not defined`, then a blank page.
`app/wrangler.jsonc` now sets `"keep_names": false`, as `coffre init` writes
it, and `coffre update` offers to set it in an existing deployment, showing the
lines it adds. Deploy the app after. Node deployments were not affected.

Conformance loads the pages in a real browser: signed in, `/projects`, a
project and `/audit`, in headless Chrome, with no console error. Without a
Chrome on the machine, the check is skipped and says so; `--browser <path>`
names one.

`coffre setup` in a fresh clone of a deployment, with no `node_modules`,
installs it first, as its lockfile says, before Cloudflare's sign-in runs the
deployment's own wrangler: it no longer fails with `spawn …/wrangler ENOENT`.
An install that fails says why in a sentence. `coffre update` installs such
a clone as it was before moving it, so that the migrations it says the
release adds are counted from the deployment's own.

`coffre update` recognizes a CLI installed globally with pnpm 11, which
keeps it in its store's `links/` directory, and updates it with `pnpm add -g`
instead of calling it a dependency of that directory. It asks npm and pnpm
where their globals are (`ls -g`), with pnpm's `PNPM_HOME` when pnpm can't
answer; when neither claims the CLI, it says so and prints what each manager
would run. Run in a deployment, `pnpm coffre update` now knows its CLI as
one of the deployment's packages.

## 0.1.16 (2026-10-04)

`coffre update` moves a deployment from pnpm 10 to 11 without a terminal:
pnpm's question about removing `node_modules` no longer stops it. When a
lockfile another pnpm wrote holds a package too young for this one, it first
resolves again for versions old enough, and lists every version that moved;
only when no older version fits does it offer to wait or to let the package
through. An install that fails leaves `package.json`, `pnpm-workspace.yaml`
and `pnpm-lock.yaml` as they were, byte for byte, and says so.

## 0.1.15 (2026-10-03)

Deployments pin pnpm: `coffre init` writes `"packageManager": "pnpm@11.8.0"`,
and `coffre update` adds it to a deployment that lacks it, so every
install, Workers Builds' included, holds `minimumReleaseAge` alike. When
pnpm holds a package back, `coffre update` says when it is old enough, and
offers to wait or to let it through by name until then, never silently.

## 0.1.14 (2026-10-03)

`coffre update` and `coffre migrate` upgrade a deployment: update the CLI
and the deployment's coffre packages, deploy, then migrate the database
with the owner's URL, asked for at a hidden prompt. `coffre migrate` first
checks that the instance runs the CLI's own version, and shows what it will
apply. `/me` now tells owners and root admins the version an instance runs
and how many of its migrations the database has applied; owners see a
banner while some are pending, and the CLI says so once a day. `pnpm
migrate` stays, for automation. [Upgrading](docs/deploy.md#upgrading).

## 0.1.12 (2026-10-03)

Syncs are removed; use a service token with `coffre run` or `coffre export`,
or the GitHub Action.

Before upgrading, **check for syncs**, including archived destinations:

```sql
SELECT id, provider, created_by, archived_at FROM syncs;
SELECT sync_id, key FROM sync_keys;
```

The migration refuses to run if either table has any rows, rather than
silently discard a configured destination. Move each destination to your
CI/deploy pipeline, which already has its platform's write credentials.
Back up the database, then deploy the new vault and app before migrating;
they work with the old schema. Once old versions have stopped receiving
requests and scheduled events, have the database owner clear `sync_keys`
and then `syncs` after the destinations have been migrated, and run
`pnpm migrate` with the owner URL. An old app can create new syncs; do not
restart it. Workers upgrade steps (deploy.md for 0.1.12, "Upgrading to 0.1.12")
include the exact command and login.
Remove unneeded third-party tokens stored as ordinary coffre secrets and
revoke those tokens with their issuers. Removing a sync never revoked copies
of values already pushed to an external platform.

The new migration drops both sync tables and their references on Postgres
and SQLite. All old migration files remain immutable. Past `sync.*` audit
entries, checkpoints, sealed legacy members and grants remain unchanged:
the log still verifies and the audit page still renders its human sentences.
Legacy sync principals can no longer read values or acquire new grants.
