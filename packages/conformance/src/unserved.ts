// The checks of what 0.16 declares and does not serve yet, by name, each
// with what it needs and why it waits. The suite skips each, saying so,
// and runs it again once its line goes: the area that serves the route
// deletes the line, as it deletes the route's from the server's
// `api/routes/unserved.ts`. Only a route that comes back belongs here; a
// check of one 0.16 drops goes with the route.
export const UNSERVED: Readonly<Record<string, string>> = {
  'verify keys': '`coffre verify keys` reads GET /audit/keys, which answers 501 until 0.16 serves it',
  'audit page proofs': "the audit page is still 0.14's: it renders `GET /audit/verification`'s verdict, which 0.16 drops, not its entries' proofs (docs/design/0.16.md, \"Pages\"); the page's port writes each row's proof in `data-proof` and takes this line off",
  'ready once adopted': "/readyz says only that the database is migrated: whether the vault has adopted it and the signer signed comes with the vault's `about` call (T311; docs/design/0.16.md, \"Readiness\")",
  loosening: 'PATCH /secrets/:project/:environment with `{ sensitivity }` alone, a nature changed in place, comes with the nature change (docs/design/0.16.md, "The server": not in the skeleton yet)',
};
