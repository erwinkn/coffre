import test from 'node:test';
import assert from 'node:assert/strict';

import {
  generateToken,
  hashToken,
  isCoffreToken,
  tokenHint,
} from '../src/identity/tokens.ts';

test('tokens carry their kind as a prefix and 32 random bytes', () => {
  assert.match(generateToken('browser'), /^coffre_web_[A-Za-z0-9_-]{43}$/);
  assert.match(generateToken('cli'), /^coffre_cli_[A-Za-z0-9_-]{43}$/);
  assert.match(generateToken('service'), /^coffre_svc_[A-Za-z0-9_-]{43}$/);
  assert.notEqual(generateToken('cli'), generateToken('cli'));
});

test('isCoffreToken accepts generated tokens and nothing shaped otherwise', () => {
  for (const kind of ['browser', 'cli', 'service'] as const) {
    assert.equal(isCoffreToken(generateToken(kind)), true);
  }
  const body = 'A'.repeat(43);
  assert.equal(isCoffreToken(`coffre_cli_${body}`), true);
  assert.equal(isCoffreToken(`coffre_cli_${body}A`), false, 'too long');
  assert.equal(isCoffreToken(`coffre_cli_${body.slice(1)}`), false, 'too short');
  assert.equal(isCoffreToken(`coffre_key_${body}`), false, 'unknown kind');
  assert.equal(isCoffreToken(`coffre_cli_${body.slice(1)}=`), false, 'padding');
  assert.equal(isCoffreToken(` coffre_cli_${body}`), false, 'surrounding space');
  assert.equal(isCoffreToken('eyJhbGciOiJSUzI1NiJ9.e30.sig'), false, 'a JWT');
  assert.equal(isCoffreToken(''), false);
});

test('hashToken is SHA-256 of the whole token', () => {
  const token = generateToken('browser');
  const hash = hashToken(token);
  assert.equal(hash.length, 32);
  assert.deepEqual(hashToken(token), hash);
  assert.notDeepEqual(hashToken(generateToken('browser')), hash);
  assert.equal(
    hashToken('coffre_web_x').toString('hex'),
    'a10690e83d49993f7c06b45d9b7bffd9d48e79a81d76ab22b54caf481dcbe969',
  );
});

test('tokenHint shows the kind and the last four characters only', () => {
  assert.equal(tokenHint(`coffre_cli_${'A'.repeat(39)}WXYZ`), 'coffre_cli_…WXYZ');
  assert.equal(tokenHint(`coffre_web_${'A'.repeat(39)}wxyz`), 'coffre_web_…wxyz');
  assert.equal(tokenHint(`coffre_svc_${'A'.repeat(39)}1234`), 'coffre_svc_…1234');
});

test('tokenHint does not leak a random part that contains underscores', () => {
  // Regression: the hint used to cut at the last `_`, which base64url also
  // uses, so a token like this one showed everything after its first `_`.
  const secret = 'Qm9Y_a1b2c3d4e5f6g7h8i9j0k_l1m2n3o4p5q6r7s8';
  const token = `coffre_cli_${secret}`;
  assert.equal(isCoffreToken(token), true);

  const hint = tokenHint(token);
  assert.equal(hint, 'coffre_cli_…r7s8');
  assert.equal(hint.includes('a1b2'), false);
  assert.equal(hint.includes('l1m2'), false);

  for (let i = 0; i < 200; i += 1) {
    const generated = generateToken('service');
    const shown = tokenHint(generated);
    assert.equal(shown, `coffre_svc_…${generated.slice(-4)}`);
  }
});

test('tokenHint of something that is not a coffre token keeps only the tail', () => {
  assert.equal(tokenHint('ghp_abcdefghijklmnop'), '…mnop');
});
