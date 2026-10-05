# UI conventions

How coffre's pages place and word things. The styles they name are in
`src/styles/globals.css`.

## A button goes where it acts

- **On a table or a list: below it.** Outside its border, at the bottom left,
  in a `.table-actions` row right after the card or grid: Add user, New
  project, Add environment, New secret beside Import .env, Edit access, Issue
  token. A row it adds appears last, next to the button.
- **On one card: in that card.** A form's Save sits under its fields,
  bottom-left; a form that is the page's only business needs no card.
- **On a cell's content: in that cell,** at its right: a secret's Copy,
  Reveal and Edit sit in its Value cell, and while it is edited, Save and
  Cancel take their place.
- **On one row: in that row,** in its last column: one "⋯" menu for the
  rest (history, rename, archive), the column as narrow as its button.
- **Unsaved changes show on their row** until they are saved or dropped.
- **On the whole page: in the page header.** Few belong there: a principal's
  menu, Sign out, the audit log's seal.

## Everything the API does

- Every route of the API is done somewhere in the pages, as in the CLI
  (D29). `src/parity.ts` names, for each, the control and its file, or why
  no page does it, or the work in flight that brings it;
  `test/parity.test.ts` checks the call sends that route.
- What the CLI previews before `--apply` (offboarding, revoking a token,
  removing a trust binding, ending a session, unlinking an account), a
  confirm dialog shows first, with the same facts.

## Sections

- A page with several sections shows them as tabs, `PageTabs` in
  `src/components/tabs.tsx`. The first is the default and has no URL
  parameter; a tab nobody may open is not shown, and one tab shows none.

## Sizes

- Pages are left-aligned. The top bar's first control (the sidebar toggle,
  or the menu on a phone) starts on the content's left edge, one gutter in.
- A card is at most `--card-max` (56rem): most tables are a few short
  columns, and the page head's actions end where its cards do. A table of
  many or long columns (the audit log, the secrets editor) takes the column
  whole with `.card-wide`, or `<Card wide>`.
- Controls take their content's width, not the column's. A fixed-layout
  table's action column fits its button.

## Words

- Sentence case for every label, button, tag and column: "Never",
  "Expired", "Root admin", "Consider rotating". `coffre` stays lowercase.
- A machine identity is a service account; a bearer token is one of its
  credentials.
