// CHAP authentication (RFC 2865, section 2.2).
//
// CHAP never sends the password. The NAS sends:
//
//   - CHAP-Password  - 1 byte CHAP Identifier followed by a 16-byte MD5 hash.
//   - CHAP-Challenge - the challenge the hash was computed over. When this
//     attribute is absent, the challenge is the packet's Request Authenticator
//     (the "authenticator" field of the forwarded packet).
//
// To verify, we recompute MD5(chap_id + password + challenge) from the password
// we hold and compare it to the hash the NAS sent. Both are forwarded by lunar
// as raw bytes ("0x" hex in the packet JSON).
package auth

import (
	"crypto/md5" //nolint:gosec // CHAP is defined in terms of MD5.
	"crypto/subtle"
)

// VerifyCHAP returns true when the CHAP response matches expectedPassword.
//
// chapPassword is the 17-byte CHAP-Password value (id + hash) and challenge is
// the CHAP-Challenge (or the Request Authenticator when no CHAP-Challenge was
// sent).
func VerifyCHAP(expectedPassword string, chapPassword, challenge []byte) bool {
	if chapPassword == nil || challenge == nil {
		return false
	}
	if len(chapPassword) != 17 {
		return false
	}

	chapID := chapPassword[0:1]
	sentHash := chapPassword[1:17]

	digest := md5.New() //nolint:gosec // CHAP uses MD5.
	digest.Write(chapID)
	digest.Write([]byte(expectedPassword))
	digest.Write(challenge)
	expectedHash := digest.Sum(nil)

	return subtle.ConstantTimeCompare(expectedHash, sentHash) == 1
}
