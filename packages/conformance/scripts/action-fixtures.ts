// Public fake values, so another job can check masking without carrying
// secrets between jobs or masking them before the Action itself runs.
export const ACTION_VALUES: Record<string, string> = {
  ACTION_TEST_PLAIN: 'coffre-action-plain-875923b921',
  ACTION_TEST_MULTILINE: 'coffre-action-line-one-72389a\ncoffre-action-line-two-082fc1\n',
  ACTION_TEST_PUNCTUATION: 'coffre-action-equals=a=b-quote-"single-\'percent-%25',
  ACTION_TEST_DELIMITER: 'coffre_delimiter_like_57829\nEOF\ncoffre_delimiter_like_72038',
  ACTION_TEST_EMPTY: '',
  GITHUB_TOKEN: 'coffre-action-github-token-943ea823',
};

export function maskProbes(): [string, string][] {
  return Object.entries(ACTION_VALUES).flatMap(([key, value]) =>
    value.split(/\r\n|\r|\n/).filter(Boolean).map((line, i): [string, string] => [`COFFRE_MASK_CHECK_${key}_${i}=`, line]),
  );
}

export function verifyMasks(log: string): void {
  const lines = log.split(/\r?\n/);
  for (const [marker, value] of maskProbes()) {
    if (log.includes(value)) throw new Error(`the runner did not mask ${marker}`);
    if (!lines.some((line) => line.endsWith(`${marker}***`))) throw new Error(`missing masked probe ${marker}`);
  }
}
