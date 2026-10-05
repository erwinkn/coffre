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
- **On one row: in that row,** in its last column.
- **On the whole page: in the page header.** Few belong there: a principal's
  menu, Sign out, the audit log's seal.

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
