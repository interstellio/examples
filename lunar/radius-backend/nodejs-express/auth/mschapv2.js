// MS-CHAPv2 authentication (RFC 2759).
//
// The NAS sends two Microsoft vendor attributes:
//
//   * MS-CHAP-Challenge  - the 16-byte Authenticator Challenge.
//   * MS-CHAP2-Response  - 50 bytes: Ident (1), Flags (1), Peer-Challenge (16),
//                          Reserved (8) and NT-Response (24).
//
// MS-CHAPv2 first derives an 8-byte "Challenge Hash" from the peer and
// authenticator challenges and the user name, then computes the NT-Response over
// that hash (keyed by the NT hash of the password) exactly as MS-CHAPv1 does. We
// recompute it and compare.
//
// On success, successAndKeys also returns what a server normally adds to the
// Access-Accept: the MS-CHAP2-Success value (so the client can verify the
// server - MS-CHAPv2 is mutual authentication) and the MPPE link-encryption
// keys (RFC 3079). This module only computes the bytes; the caller sets the
// reply attributes. The MPPE keys are returned as PLAINTEXT bytes - lunar
// salt-encrypts them on the wire with the shared secret (they are encrypt=2
// attributes), so this backend never needs the Request Authenticator.

"use strict";

const crypto = require("crypto");
const nt = require("./nt");

// Magic constants, byte-for-byte, from RFC 2759 (success) and RFC 3079 (MPPE).
const MAGIC_SIGN = Buffer.from("Magic server to client signing constant", "ascii");
const MAGIC_PAD = Buffer.from("Pad to make it do more than one iteration", "ascii");
const MAGIC_MASTER = Buffer.from("This is the MPPE Master Key", "ascii");
// On the SERVER, the send key uses this constant and the receive key the other.
const MAGIC_SERVER_SEND = Buffer.from(
  "On the client side, this is the receive key; " +
    "on the server side, it is the send key.",
  "ascii"
);
const MAGIC_SERVER_RECV = Buffer.from(
  "On the client side, this is the send key; " +
    "on the server side, it is the receive key.",
  "ascii"
);

// Return true when the MS-CHAPv2 NT-Response matches. challenge is the 16-byte
// MS-CHAP-Challenge (Authenticator Challenge) and response is the 50-byte
// MS-CHAP2-Response.
function verify(expectedPassword, username, challenge, response) {
  if (challenge.length !== 16 || response.length !== 50) {
    return false;
  }

  const peerChallenge = response.subarray(2, 18);
  const ntResponse = response.subarray(26, 50);

  const hash = challengeHash(peerChallenge, challenge, username);
  const expected = nt.ntChallengeResponse(hash, nt.ntHash(expectedPassword));
  return crypto.timingSafeEqual(expected, ntResponse);
}

// Return the raw MS-CHAP2-Success value and the two MPPE keys. challenge is the
// 16-byte MS-CHAP-Challenge and response the 50-byte MS-CHAP2-Response.
function successAndKeys(password, username, challenge, response) {
  const ident = response[0];
  const peerChallenge = response.subarray(2, 18);
  const ntResponse = response.subarray(26, 50);

  // MS-CHAP2-Success: the response Ident byte, then the "S=<hex>" string.
  const authResponse = authenticatorResponse(
    password,
    username,
    peerChallenge,
    challenge,
    ntResponse
  );
  const success = Buffer.concat([Buffer.from([ident]), Buffer.from(authResponse, "ascii")]);

  // MPPE keys: one 16-byte master key, then a send and a receive session key.
  const masterInput = Buffer.concat([nt.ntHashHash(password), ntResponse, MAGIC_MASTER]);
  const masterKey = crypto.createHash("sha1").update(masterInput).digest().subarray(0, 16);

  const sendKey = mppeSessionKey(masterKey, MAGIC_SERVER_SEND);
  const recvKey = mppeSessionKey(masterKey, MAGIC_SERVER_RECV);

  return { success, sendKey, recvKey };
}

// The 8-byte Challenge Hash (RFC 2759, GenerateNTResponse).
function challengeHash(peerChallenge, authenticatorChallenge, username) {
  const input = Buffer.concat([
    peerChallenge,
    authenticatorChallenge,
    Buffer.from(username, "ascii"),
  ]);
  return crypto.createHash("sha1").update(input).digest().subarray(0, 8);
}

// The "S=<hex>" server authenticator response (RFC 2759).
function authenticatorResponse(password, username, peerChallenge, authenticatorChallenge, ntResponse) {
  const passwordHashHash = nt.ntHashHash(password);
  const hash = challengeHash(peerChallenge, authenticatorChallenge, username);

  const digest = crypto
    .createHash("sha1")
    .update(Buffer.concat([passwordHashHash, ntResponse, MAGIC_SIGN]))
    .digest();
  const responseHash = crypto
    .createHash("sha1")
    .update(Buffer.concat([digest, hash, MAGIC_PAD]))
    .digest();

  return "S=" + responseHash.toString("hex").toUpperCase();
}

// Derive one 16-byte MPPE session key from the master key (RFC 3079).
function mppeSessionKey(masterKey, magic) {
  const input = Buffer.concat([
    masterKey,
    Buffer.alloc(40, 0x00),
    magic,
    Buffer.alloc(40, 0xf2),
  ]);
  return crypto.createHash("sha1").update(input).digest().subarray(0, 16);
}

module.exports = { verify, successAndKeys };
