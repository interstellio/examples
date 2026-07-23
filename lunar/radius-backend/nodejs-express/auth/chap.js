// CHAP authentication (RFC 2865, section 2.2).
//
// CHAP never sends the password. The NAS sends:
//
//   * CHAP-Password  - 1 byte CHAP Identifier followed by a 16-byte MD5 hash.
//   * CHAP-Challenge - the challenge the hash was computed over. When this
//                      attribute is absent, the challenge is the packet's
//                      Request Authenticator (the "authenticator" field).
//
// To verify, we recompute MD5(chap_id + password + challenge) from the password
// we hold and compare it to the hash the NAS sent. Both are forwarded by lunar
// as raw bytes ("0x" hex in the packet JSON).

"use strict";

const crypto = require("crypto");

// Return true when the CHAP response matches expectedPassword. chapPassword is
// the 17-byte CHAP-Password value (id + hash) and challenge is the
// CHAP-Challenge (or the Request Authenticator when no CHAP-Challenge was sent).
function verify(expectedPassword, chapPassword, challenge) {
  if (chapPassword.length !== 17) {
    return false;
  }

  const chapId = chapPassword[0];
  const sentHash = chapPassword.subarray(1, 17);

  const input = Buffer.concat([
    Buffer.from([chapId]),
    Buffer.from(expectedPassword, "utf8"),
    challenge,
  ]);
  const expectedHash = crypto.createHash("md5").update(input).digest();

  return crypto.timingSafeEqual(expectedHash, sentHash);
}

module.exports = { verify };
