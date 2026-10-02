// Local fixtures, as in .env.dev: none of them is a secret anywhere else.
// The vault derives its signing key from the KEK, as every deployment with
// a local KEK does.
export const KEYS = {
  KEK_ID: 'conformance-1',
  KEK: 'Y29mZnJlLWxvY2FsLWRldi1rZWstMzItYnl0ZXMhISE=',
  AUDIT_CHAIN_KEY: 'Y29mZnJlLWxvY2FsLWF1ZGl0LWNoYWluLWtleS0zMmI=',
};
