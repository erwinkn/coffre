// The checks of what 0.16 declares and does not serve yet, by name, each
// with what it needs and why it waits. The suite skips each, saying so,
// and runs it again once its line goes: the area that serves the route
// deletes the line, as it deletes the route's from the server's
// `api/routes/unserved.ts`. Only a route that comes back belongs here; a
// check of one 0.16 drops goes with the route.
export const UNSERVED: Readonly<Record<string, string>> = {
  'verify keys': '`coffre verify keys` reads GET /audit/keys, which answers 501 until 0.16 serves it',
  'ready once adopted': "/readyz says only that the database is migrated: whether the vault has adopted it and the signer signed is still to design: both are stored, and the vault's `about` reads nothing (docs/design/0.16.md, \"Readiness\")",
  loosening: 'PATCH /secrets/:project/:environment with `{ sensitivity }` alone, a nature changed in place, comes with the nature change (docs/design/0.16.md, "The server": not in the skeleton yet)',
};
