import assert from 'node:assert/strict';
import {
  sha1,
  base32Decode,
  hotp,
  totp,
  parseSecretInput,
  normalizeSecret,
  isValidSecret,
} from '../src/totp.js';

function ascii(text) {
  return Uint8Array.from(text, (ch) => ch.charCodeAt(0));
}

const rfcKey = ascii('12345678901234567890');

const hotpCases = [
  [0, '755224'],
  [1, '287082'],
  [2, '359152'],
  [3, '969429'],
  [4, '338314'],
];

for (const [counter, expected] of hotpCases) {
  assert.equal(hotp(rfcKey, counter, 6), expected, 'HOTP counter ' + counter);
}

const totpCases = [
  [59, '287082'],
  [1111111109, '081804'],
  [1111111111, '050471'],
  [1234567890, '005924'],
  [2000000000, '279037'],
];

for (const [unix, expected] of totpCases) {
  assert.equal(totp(rfcKey, unix, 6, 30), expected, 'TOTP unix ' + unix);
}

const hello = base32Decode('JBSWY3DPEHPK3PXP');
assert.ok(hello);
assert.equal(Buffer.from(hello).subarray(0, 6).toString('ascii'), 'Hello!');
assert.equal(Buffer.from(hello).toString('hex'), '48656c6c6f21deadbeef');

assert.equal(base32Decode('JBSWY3DPEHPK3PX!'), null);
assert.equal(normalizeSecret(' jbsw y3dp-ehpk3pxp== '), 'JBSWY3DPEHPK3PXP');
assert.equal(isValidSecret('JBSWY3DPEHPK3PXP'), true);
assert.equal(isValidSecret('SHORT'), false);

const raw = parseSecretInput('  ABCD2345  ');
assert.equal(raw.secret, 'ABCD2345');
assert.equal(raw.unsupported, '');

const okUri = parseSecretInput('otpauth://totp/Accstall?secret=JBSWY3DPEHPK3PXP&digits=6&period=30&algorithm=SHA1');
assert.equal(okUri.secret, 'JBSWY3DPEHPK3PXP');
assert.equal(okUri.unsupported, '');

const badUri = parseSecretInput('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8');
assert.equal(badUri.secret, '');
assert.equal(badUri.unsupported, '8|30|SHA1');

const sha256 = parseSecretInput('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256');
assert.equal(sha256.unsupported, '6|30|SHA256');

const digest = sha1(ascii('abc'));
assert.equal(Buffer.from(digest).toString('hex'), 'a9993e364706816aba3e25717850c26c9cd0d89d');

console.log('accstall-2fa-generator: all vectors passed');
