// Package auth holds the credential-verification primitives for the example
// RADIUS backend, split by method so each file is small and focused:
//
//   - chap.go       - CHAP verification.
//   - mschap.go     - MS-CHAPv1 verification.
//   - mschapv2.go   - MS-CHAPv2 verification, plus the MS-CHAP2-Success and
//     MPPE key bytes returned on accept.
//   - nt.go         - the NT-hash, MD4 and DES primitives shared by the
//     MS-CHAP modules.
//
// Every function takes and returns pure bytes (or a bool decision); all JSON,
// attribute and reply handling stays in main.go.
//
// This is EXAMPLE code, favouring clarity over completeness; a production
// backend would look the user up in a real store and handle more edge cases.
package auth

import (
	"crypto/des" //nolint:gosec // DES is required by the MS-CHAP protocol.
	"encoding/binary"
	"unicode/utf16"
)

// md4 returns the 16-byte MD4 digest of message (RFC 1320).
//
// MD4 is legacy and OpenSSL-based runtimes often drop it, so - like the other
// examples - this backend ships its own small implementation and depends on
// nothing outside the standard library.
func md4(message []byte) []byte {
	var a, b, c, d uint32 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

	rol := func(x uint32, c uint) uint32 {
		return (x << c) | (x >> (32 - c))
	}
	f := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
	g := func(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
	h := func(x, y, z uint32) uint32 { return x ^ y ^ z }

	// Pad the message to a multiple of 64 bytes (MD4 padding).
	length := len(message)
	msg := make([]byte, len(message))
	copy(msg, message)
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0x00)
	}
	tail := make([]byte, 8)
	binary.LittleEndian.PutUint64(tail, uint64(length)*8)
	msg = append(msg, tail...)

	for offset := 0; offset < len(msg); offset += 64 {
		block := msg[offset : offset+64]
		var x [16]uint32
		for i := 0; i < 16; i++ {
			x[i] = binary.LittleEndian.Uint32(block[i*4 : i*4+4])
		}
		aa, bb, cc, dd := a, b, c, d

		// Round 1
		for i := 0; i < 16; i += 4 {
			a = rol(a+f(b, c, d)+x[i], 3)
			d = rol(d+f(a, b, c)+x[i+1], 7)
			c = rol(c+f(d, a, b)+x[i+2], 11)
			b = rol(b+f(c, d, a)+x[i+3], 19)
		}

		// Round 2
		for i := 0; i < 4; i++ {
			a = rol(a+g(b, c, d)+x[i]+0x5A827999, 3)
			d = rol(d+g(a, b, c)+x[i+4]+0x5A827999, 5)
			c = rol(c+g(d, a, b)+x[i+8]+0x5A827999, 9)
			b = rol(b+g(c, d, a)+x[i+12]+0x5A827999, 13)
		}

		// Round 3
		for _, i := range []int{0, 2, 1, 3} {
			a = rol(a+h(b, c, d)+x[i]+0x6ED9EBA1, 3)
			d = rol(d+h(a, b, c)+x[i+8]+0x6ED9EBA1, 9)
			c = rol(c+h(d, a, b)+x[i+4]+0x6ED9EBA1, 11)
			b = rol(b+h(c, d, a)+x[i+12]+0x6ED9EBA1, 15)
		}

		a += aa
		b += bb
		c += cc
		d += dd
	}

	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:4], a)
	binary.LittleEndian.PutUint32(out[4:8], b)
	binary.LittleEndian.PutUint32(out[8:12], c)
	binary.LittleEndian.PutUint32(out[12:16], d)
	return out
}

// NTHash returns the 16-byte NT hash of password (MD4 of the UTF-16LE bytes).
func NTHash(password string) []byte {
	codes := utf16.Encode([]rune(password))
	bytes := make([]byte, len(codes)*2)
	for i, code := range codes {
		binary.LittleEndian.PutUint16(bytes[i*2:], code)
	}
	return md4(bytes)
}

// NTHashHash returns MD4 of the NT hash.
//
// MS-CHAPv2 uses this "password-hash-hash" both for the server authenticator
// response (MS-CHAP2-Success) and to derive the MPPE session keys.
func NTHashHash(password string) []byte {
	return md4(NTHash(password))
}

// expandDESKey expands a 7-byte key into the 8-byte form DES expects.
//
// DES keys are 64 bits with one parity bit per byte, so 56 bits of real key
// material are spread across 8 bytes. This is the standard MS-CHAP key
// expansion (the parity bits themselves are ignored by DES).
func expandDESKey(key7 []byte) []byte {
	key := make([]byte, 8)
	key[0] = key7[0] >> 1
	key[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2)
	key[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3)
	key[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4)
	key[4] = ((key7[3] & 0x0F) << 3) | (key7[4] >> 5)
	key[5] = ((key7[4] & 0x1F) << 2) | (key7[5] >> 6)
	key[6] = ((key7[5] & 0x3F) << 1) | (key7[6] >> 7)
	key[7] = key7[6] & 0x7F
	for i := range key {
		key[i] = (key[i] << 1) & 0xFF
	}
	return key
}

// desEncrypt DES-ECB encrypts one 8-byte block8 with a 7-byte key.
func desEncrypt(key7, block8 []byte) []byte {
	block, err := des.NewCipher(expandDESKey(key7)) //nolint:gosec // MS-CHAP uses DES.
	if err != nil {
		// The key is always 8 bytes here, so this cannot happen.
		panic(err)
	}
	out := make([]byte, 8)
	block.Encrypt(out, block8)
	return out
}

// ntChallengeResponse returns the 24-byte NT response over an 8-byte challenge.
//
// The 16-byte NT hash is padded to 21 bytes and split into three 7-byte DES
// keys; each encrypts the same 8-byte challenge, and the three 8-byte results
// are concatenated into the 24-byte response.
func ntChallengeResponse(challenge8, passwordNTHash []byte) []byte {
	padded := make([]byte, 21)
	copy(padded, passwordNTHash)
	out := make([]byte, 0, 24)
	for i := 0; i < 21; i += 7 {
		out = append(out, desEncrypt(padded[i:i+7], challenge8)...)
	}
	return out
}
