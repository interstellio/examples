// MS-CHAPv1 authentication (RFC 2433).
//
// The NAS sends two Microsoft vendor attributes:
//
//   * MS-CHAP-Challenge - the 8-byte challenge.
//   * MS-CHAP-Response  - 50 bytes: Ident (1), Flags (1), LM-Response (24) and
//                         NT-Response (24).
//
// We verify the NT-Response only (the LM-Response is obsolete and often zero):
// the 24-byte DES response over the challenge, keyed by the NT hash of the
// password. lunar forwards both attributes as raw bytes ("0x" hex).

"use strict";

const crypto = require("crypto");
const nt = require("./nt");

// Return true when the MS-CHAPv1 NT-Response matches. challenge is the 8-byte
// MS-CHAP-Challenge and response is the 50-byte MS-CHAP-Response.
function verify(expectedPassword, challenge, response) {
  if (challenge.length !== 8 || response.length !== 50) {
    return false;
  }

  const ntResponse = response.subarray(26, 50);
  const expected = nt.ntChallengeResponse(challenge, nt.ntHash(expectedPassword));
  return crypto.timingSafeEqual(expected, ntResponse);
}

module.exports = { verify };
