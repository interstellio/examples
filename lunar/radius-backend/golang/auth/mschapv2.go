// MS-CHAPv2 authentication (RFC 2759).
//
// The NAS sends two Microsoft vendor attributes:
//
//   - MS-CHAP-Challenge  - the 16-byte Authenticator Challenge.
//   - MS-CHAP2-Response  - 50 bytes: Ident (1), Flags (1), Peer-Challenge (16),
//     Reserved (8) and NT-Response (24).
//
// MS-CHAPv2 first derives an 8-byte "Challenge Hash" from the peer and
// authenticator challenges and the user name, then computes the NT-Response over
// that hash (keyed by the NT hash of the password) exactly as MS-CHAPv1 does. We
// recompute it and compare. All values are forwarded by lunar as raw bytes
// ("0x" hex in the packet JSON); the user name is a normal text attribute.
//
// On success, SuccessAndKeys also returns what a server normally adds to the
// Access-Accept: the MS-CHAP2-Success value (so the client can verify the
// server - MS-CHAPv2 is mutual authentication) and the MPPE link-encryption
// keys. This module only computes the bytes; the caller sets the reply
// attributes.
package auth

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // MS-CHAPv2 is defined in terms of SHA-1.
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// challengeHash returns the 8-byte Challenge Hash (RFC 2759, GenerateNTResponse).
func challengeHash(peerChallenge, authenticatorChallenge []byte, username string) []byte {
	digest := sha1.New() //nolint:gosec // MS-CHAPv2 uses SHA-1.
	digest.Write(peerChallenge)
	digest.Write(authenticatorChallenge)
	digest.Write([]byte(username))
	return digest.Sum(nil)[:8]
}

// VerifyMSCHAPv2 returns true when the MS-CHAPv2 NT-Response matches.
//
// challenge is the 16-byte MS-CHAP-Challenge (Authenticator Challenge) and
// response is the 50-byte MS-CHAP2-Response.
func VerifyMSCHAPv2(expectedPassword, username string, challenge, response []byte) bool {
	if challenge == nil || response == nil {
		return false
	}
	if len(challenge) != 16 || len(response) != 50 {
		return false
	}

	peerChallenge := response[2:18]
	ntResponse := response[26:50]

	hash := challengeHash(peerChallenge, challenge, username)
	expected := ntChallengeResponse(hash, NTHash(expectedPassword))
	return subtle.ConstantTimeCompare(expected, ntResponse) == 1
}

// --- MS-CHAP2-Success and MPPE keys (RFC 2759 + RFC 3079) ----------------
//
// On a successful MS-CHAPv2 auth a server normally adds three Microsoft
// attributes to the Access-Accept, and this backend does the same:
//
//   - MS-CHAP2-Success  - lets the CLIENT verify the server (mutual auth). It
//     is the response Ident byte followed by an "S=<hex>" string.
//   - MS-MPPE-Send-Key   - the MPPE session keys that encrypt the PPP link
//   - MS-MPPE-Recv-Key     (PPTP, some L2TP), derived from the password hash.
//
// This module only COMPUTES the raw bytes; main.go sets the reply attributes.
// The MPPE keys are sent as PLAINTEXT 0x hex - lunar salt-encrypts them on the
// wire with the shared secret (they are marked encrypt=2 in the RADIUS
// dictionary), so this backend never needs the Request Authenticator.

// Magic constants, byte-for-byte, from RFC 2759 (success) and RFC 3079 (MPPE).
var (
	magicSign   = []byte("Magic server to client signing constant")
	magicPad    = []byte("Pad to make it do more than one iteration")
	magicMaster = []byte("This is the MPPE Master Key")
	// On the SERVER, the send key uses this constant and the receive key the other.
	magicServerSend = []byte("On the client side, this is the receive key; " +
		"on the server side, it is the send key.")
	magicServerRecv = []byte("On the client side, this is the send key; " +
		"on the server side, it is the receive key.")
)

// authenticatorResponse returns the "S=<hex>" server authenticator response
// (RFC 2759).
func authenticatorResponse(password, username string,
	peerChallenge, authenticatorChallenge, ntResponse []byte) string {
	passwordHashHash := NTHashHash(password)
	hash := challengeHash(peerChallenge, authenticatorChallenge, username)

	first := sha1.New() //nolint:gosec // MS-CHAPv2 uses SHA-1.
	first.Write(passwordHashHash)
	first.Write(ntResponse)
	first.Write(magicSign)
	digest := first.Sum(nil)

	second := sha1.New() //nolint:gosec // MS-CHAPv2 uses SHA-1.
	second.Write(digest)
	second.Write(hash)
	second.Write(magicPad)
	response := second.Sum(nil)

	return "S=" + strings.ToUpper(hex.EncodeToString(response))
}

// mppeSessionKey derives one 16-byte MPPE session key from the master key
// (RFC 3079).
func mppeSessionKey(masterKey, magic []byte) []byte {
	digest := sha1.New() //nolint:gosec // MS-CHAPv2 uses SHA-1.
	digest.Write(masterKey)
	digest.Write(bytes.Repeat([]byte{0x00}, 40))
	digest.Write(magic)
	digest.Write(bytes.Repeat([]byte{0xF2}, 40))
	return digest.Sum(nil)[:16]
}

// SuccessAndKeys returns the raw MS-CHAP2-Success value and the two MPPE keys.
//
// challenge is the 16-byte MS-CHAP-Challenge and response the 50-byte
// MS-CHAP2-Response. The caller turns the returned bytes into reply attributes.
func SuccessAndKeys(password, username string, challenge, response []byte) (success, sendKey, recvKey []byte) {
	ident := response[0:1]
	peerChallenge := response[2:18]
	ntResponse := response[26:50]

	// MS-CHAP2-Success: the response Ident byte, then the "S=<hex>" string.
	success = append(success, ident...)
	success = append(success, []byte(authenticatorResponse(
		password, username, peerChallenge, challenge, ntResponse))...)

	// MPPE keys: one 16-byte master key, then a send and a receive session key.
	master := sha1.New() //nolint:gosec // MS-CHAPv2 uses SHA-1.
	master.Write(NTHashHash(password))
	master.Write(ntResponse)
	master.Write(magicMaster)
	masterKey := master.Sum(nil)[:16]

	sendKey = mppeSessionKey(masterKey, magicServerSend)
	recvKey = mppeSessionKey(masterKey, magicServerRecv)
	return success, sendKey, recvKey
}
