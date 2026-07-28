# Product

## Register

product

## Users

Two audiences with genuinely different postures, which is the central design
constraint:

- **Engineers**, at a desk with a terminal open beside the browser. The CLI is
  the primary interface; the UI is for the things a CLI is bad at — seeing what
  an environment holds, comparing versions, granting access. Sessions are short
  and glance-shaped. They arrive knowing what they want.
- **Auditors and access reviewers**, answering a question under DORA
  (CDR (EU) 2024/1774 Art. 12): "who read `DATABASE_URL` last month", "what does
  this leaver still hold". Sessions are long and reading-shaped. The `auditor`
  and `access-manager` roles deliberately cannot read secret values, so these
  people see a different app than the engineers do.

A glance and a read want opposite things. The UI serves both by staying dense
and keyboard-reachable for the first, and legible and scannable for the second.

## Product Purpose

An in-house secrets manager whose reason for existing is the audit log. Self-
hosted Infisical silently drops every audit entry without a licence; the failure
mode this product is built to not repeat is a control that quietly does nothing.

Success is that "who read which secret, when" is answerable, provably
un-tampered-with, and that nobody is tempted to route around the UI to get work
done.

## Brand Personality

Precise, unsentimental, evidence-first. The voice throughout the codebase states
what is true and what is not claimed, and the interface should match: no
reassurance that isn't backed by a mechanism, no "secure" as decoration.

Three words: **instrument, ledger, plain**.

The product is closer to a laboratory instrument or an accounting ledger than to
a security dashboard. It reports; it does not editorialise.

## Anti-references

- **Security-theatre dashboards.** Threat gauges, shield iconography, risk
  scores, big hero metrics. This product's honesty is its whole value
  proposition and a fake dial destroys it.
- **Cyber aesthetics.** Neon-on-black, terminal green, glitch type, matrix
  motifs. The category reflex, and at odds with "ledger".
- **Consumer-app softness.** Oversized rounded cards, illustrations, encouraging
  empty-state mascots, celebratory animation on destructive actions.
- **Infisical's own UI**, specifically its habit of surfacing features that are
  inert without a licence.

## Design Principles

1. **The mechanism is the message.** Where the product makes a guarantee, show
   the mechanism that backs it: the chain verifies, the archive is reversible,
   the rename is safe because ciphertext binds to ids. Never assert safety
   without the reason next to it.
2. **Reveal is an event, not a view.** Listing keys is free; revealing a value
   writes an audit row attributed to a person. The interface must make that
   asymmetry visible before the click, not explain it after.
3. **Permission shapes the page, not an error.** A principal who cannot do a
   thing should not see the affordance and then be refused. Sections are gated
   individually, never on one blanket "admin".
4. **Reversible by default, confirmed when not.** Archiving is reversible and
   should feel light, with undo. Anything genuinely one-way earns a confirmation
   step and says what it will do.
5. **Legible under scrutiny.** Someone will read this screen while writing a
   compliance finding. Tabular numerals, absolute timestamps on demand, no
   information conveyed by colour alone.

## Accessibility & Inclusion

- **WCAG 2.1 AA.** All text pairs verified mechanically by
  `scripts/check-contrast.mjs`, which fails the build rather than trusting a
  palette that merely looks fine.
- **Never colour alone.** `allow` / `deny` in the audit log is exactly the
  red/green pair that deuteranopia collapses. Every decision carries a glyph and
  a text label as well as a hue.
- **Full keyboard reach.** Every action is tab-reachable with a visible focus
  ring; the command palette (⌘K) is the fast path, never the only path.
- **`prefers-reduced-motion`** is honoured throughout: transitions degrade to
  opacity-only or instant, never to a broken layout.
- **Both colour schemes**, following `prefers-color-scheme` with a manual
  override, because the two audiences work in different rooms.
