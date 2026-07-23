// MS-CHAPv1 authentication (RFC 2433).
//
// The NAS sends two Microsoft vendor attributes:
//
//   - MS-CHAP-Challenge - the 8-byte challenge.
//   - MS-CHAP-Response  - 50 bytes: Ident (1), Flags (1), LM-Response (24) and
//     NT-Response (24).
//
// We verify the NT-Response only (the LM-Response is obsolete and often zero):
// the 24-byte DES response over the challenge, keyed by the NT hash of the
// password. lunar forwards both attributes as raw bytes ("0x" hex).
package auth

import "crypto/subtle"

// VerifyMSCHAP returns true when the MS-CHAPv1 NT-Response matches.
//
// challenge is the 8-byte MS-CHAP-Challenge and response is the 50-byte
// MS-CHAP-Response.
func VerifyMSCHAP(expectedPassword string, challenge, response []byte) bool {
	if challenge == nil || response == nil {
		return false
	}
	if len(challenge) != 8 || len(response) != 50 {
		return false
	}

	ntResponse := response[26:50]
	expected := ntChallengeResponse(challenge, NTHash(expectedPassword))
	return subtle.ConstantTimeCompare(expected, ntResponse) == 1
}
