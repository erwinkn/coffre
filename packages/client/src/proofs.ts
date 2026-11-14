// What a page of `GET /audit` says of its own proofs, judged once for every
// caller: `coffre verify instance` and conformance each read a page, wait
// out the signing race and word what they find, and both hold it to this.
import type { Api, AuditEntryView } from './api.ts';

type Page = Api['GET /audit']['output'];

export type ProofJudgment = {
  /** The vault's head the page was proven against; none stands before the signer's first batch. */
  head: Page['head'];
  /** Entries the head numbers, which a page waits for: a batch signed between the head's read and the log's can put every one past it. */
  numbered: number;
  proven: number;
  /** Within the head and not what it signed. */
  failed: AuditEntryView[];
  /** Neither failed nor as the head places it: unproven though the head numbers it, or proven past it. The signer signs in order, so the head numbers the log's first `size` entries. */
  misplaced: AuditEntryView[];
  /** What the page's stretch lacks, by the trees' counts: null when it cannot say, on a page that is not of the whole log, or with no head. */
  missing: Page['holes'];
};

export function judgeProofs(page: Page): ProofJudgment {
  const { head, entries } = page;
  const within = (entry: AuditEntryView) => head !== null && entry.seq < head.size;
  return {
    head,
    numbered: entries.filter(within).length,
    proven: entries.filter((entry) => entry.proof === 'proven').length,
    failed: entries.filter((entry) => entry.proof === 'failed'),
    misplaced: entries.filter((entry) => entry.proof !== 'failed' && within(entry) !== (entry.proof === 'proven')),
    missing: page.holes,
  };
}
