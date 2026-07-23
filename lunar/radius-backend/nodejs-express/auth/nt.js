// Shared NT-hash and DES primitives for the MS-CHAP family.
//
// MS-CHAPv1 and MS-CHAPv2 both authenticate by encrypting a challenge with a
// key derived from the "NT hash" of the user's password. This file provides the
// low-level pieces they share, so chap/mschap/mschapv2 do not duplicate the
// crypto:
//
//   * ntHash              - the NT hash of a password (MD4 of the UTF-16LE
//                           password bytes).
//   * ntHashHash          - MD4 of the NT hash (MS-CHAPv2 server response and
//                           MPPE key derivation).
//   * ntChallengeResponse - the 24-byte DES response over an 8-byte challenge
//                           (RFC 2433 / RFC 2759).
//
// Node's crypto ships MD5, SHA1 and (via OpenSSL) many ciphers, but OpenSSL 3
// moved MD4 and single-DES into the "legacy" provider, which is OFF by default -
// so `crypto.createHash("md4")` and the `des-ecb` cipher both throw unless the
// host has that provider enabled. To keep this example self-contained and
// portable (no runtime flags, no legacy provider), MD4 (RFC 1320) and single
// DES (FIPS 46-3) are implemented here in plain JavaScript. MD5 and SHA1 - used
// by CHAP and MS-CHAPv2 - stay in Node's crypto, where they are always present.
//
// This is EXAMPLE code, favouring clarity over completeness; a production
// backend would look the user up in a real store and handle more edge cases.

"use strict";

// --- Public NT / MS-CHAP primitives ----------------------------------------

// 16-byte NT hash of a password: MD4 of the UTF-16LE bytes.
function ntHash(password) {
  // "utf16le" is UTF-16 little-endian, exactly what the NT hash is defined over.
  return md4(Buffer.from(password, "utf16le"));
}

// MD4 of the NT hash. MS-CHAPv2 uses this "password-hash-hash" both for the
// server authenticator response (MS-CHAP2-Success) and to derive the MPPE
// session keys.
function ntHashHash(password) {
  return md4(ntHash(password));
}

// The 24-byte NT response over an 8-byte challenge. The 16-byte NT hash is
// padded to 21 bytes and split into three 7-byte DES keys; each encrypts the
// same 8-byte challenge, and the three 8-byte results are concatenated.
function ntChallengeResponse(challenge8, passwordNtHash) {
  const padded = Buffer.alloc(21);
  passwordNtHash.copy(padded, 0);

  const response = Buffer.alloc(24);
  for (let i = 0; i < 3; i++) {
    const key7 = padded.subarray(i * 7, i * 7 + 7);
    const block = desEncrypt(key7, challenge8);
    block.copy(response, i * 8);
  }
  return response;
}

// --- DES --------------------------------------------------------------------

// Expand a 7-byte key into the 8-byte form DES expects. DES keys are 64 bits
// with one parity bit per byte, so 56 bits of real key material are spread
// across 8 bytes. This is the standard MS-CHAP key expansion (the parity bits
// themselves are ignored by DES via PC1 below).
function expandDesKey(key7) {
  const key = Buffer.alloc(8);
  key[0] = key7[0] >> 1;
  key[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2);
  key[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3);
  key[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4);
  key[4] = ((key7[3] & 0x0f) << 3) | (key7[4] >> 5);
  key[5] = ((key7[4] & 0x1f) << 2) | (key7[5] >> 6);
  key[6] = ((key7[5] & 0x3f) << 1) | (key7[6] >> 7);
  key[7] = key7[6] & 0x7f;
  for (let i = 0; i < 8; i++) {
    key[i] = (key[i] << 1) & 0xff;
  }
  return key;
}

// DES-ECB encrypt one 8-byte block with a 7-byte key.
function desEncrypt(key7, block8) {
  return desEncryptBlock(expandDesKey(key7), block8);
}

// Standard DES permutation / substitution tables (FIPS 46-3).
const IP = [
  58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];
const FP = [
  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];
const E = [
  32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
  12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];
const P = [
  16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
  2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
];
const PC1 = [
  57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
  10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
  14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
];
const PC2 = [
  14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];
const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
// Eight S-boxes, each a flat 4x16 table (row * 16 + column).
const S = [
  [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
  [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
  [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
  [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
  [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
  [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
  [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
  [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
];

// Encrypt one 8-byte block with a full 8-byte DES key (parity bits included;
// PC1 discards them). Works on arrays of bits (0/1) for readability.
function desEncryptBlock(key8, block8) {
  // Derive the 16 round subkeys from the key.
  const keyBits = bytesToBits(key8);
  const permutedKey = permute(keyBits, PC1); // 64 -> 56
  let c = permutedKey.slice(0, 28);
  let d = permutedKey.slice(28, 56);
  const subkeys = [];
  for (let i = 0; i < 16; i++) {
    c = rotateLeft(c, SHIFTS[i]);
    d = rotateLeft(d, SHIFTS[i]);
    subkeys.push(permute(c.concat(d), PC2)); // 56 -> 48
  }

  // Encrypt: initial permutation, 16 Feistel rounds, final permutation.
  const bits = permute(bytesToBits(block8), IP);
  let left = bits.slice(0, 32);
  let right = bits.slice(32, 64);
  for (let i = 0; i < 16; i++) {
    const next = xor(left, feistel(right, subkeys[i]));
    left = right;
    right = next;
  }
  // Note the swap: the pre-output block is R16 followed by L16.
  return bitsToBytes(permute(right.concat(left), FP));
}

// The DES round function f(R, K): expand, mix in the subkey, S-box, permute.
function feistel(right, subkey) {
  const xored = xor(permute(right, E), subkey); // 32 -> 48, then XOR key
  const out = [];
  for (let i = 0; i < 8; i++) {
    const chunk = xored.slice(i * 6, i * 6 + 6);
    const row = (chunk[0] << 1) | chunk[5];
    const col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4];
    const value = S[i][row * 16 + col];
    for (let bit = 3; bit >= 0; bit--) {
      out.push((value >> bit) & 1);
    }
  }
  return permute(out, P); // 32 -> 32
}

function bytesToBits(buffer) {
  const bits = [];
  for (const byte of buffer) {
    for (let i = 7; i >= 0; i--) {
      bits.push((byte >> i) & 1);
    }
  }
  return bits;
}

function bitsToBytes(bits) {
  const out = Buffer.alloc(bits.length / 8);
  for (let i = 0; i < out.length; i++) {
    let byte = 0;
    for (let j = 0; j < 8; j++) {
      byte = (byte << 1) | bits[i * 8 + j];
    }
    out[i] = byte;
  }
  return out;
}

// Reorder bits according to a 1-based permutation table.
function permute(bits, table) {
  return table.map((position) => bits[position - 1]);
}

function rotateLeft(bits, count) {
  return bits.slice(count).concat(bits.slice(0, count));
}

function xor(a, b) {
  return a.map((bit, i) => bit ^ b[i]);
}

// --- MD4 (RFC 1320) ---------------------------------------------------------

// A compact, self-contained MD4 (Node's crypto does not expose one by default).
function md4(message) {
  let a = 0x67452301;
  let b = 0xefcdab89;
  let c = 0x98badcfe;
  let d = 0x10325476;

  // Pad the message to a multiple of 64 bytes (MD4 padding): a 0x80 byte, then
  // zeros, then the original length in bits as a 64-bit little-endian integer.
  const bitLength = BigInt(message.length) * 8n;
  const padded = [...message, 0x80];
  while (padded.length % 64 !== 56) {
    padded.push(0x00);
  }
  for (let i = 0; i < 8; i++) {
    padded.push(Number((bitLength >> BigInt(8 * i)) & 0xffn));
  }
  const data = Uint8Array.from(padded);

  const f = (x, y, z) => (x & y) | (~x & z);
  const g = (x, y, z) => (x & y) | (x & z) | (y & z);
  const h = (x, y, z) => x ^ y ^ z;
  const rol = (value, count) => ((value << count) | (value >>> (32 - count))) >>> 0;
  // Sum any number of 32-bit words modulo 2^32.
  const add = (...words) => words.reduce((sum, word) => (sum + word) >>> 0, 0);

  for (let offset = 0; offset < data.length; offset += 64) {
    const x = new Array(16);
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      x[i] = (data[j] | (data[j + 1] << 8) | (data[j + 2] << 16) | (data[j + 3] << 24)) >>> 0;
    }

    const aa = a;
    const bb = b;
    const cc = c;
    const dd = d;

    // Round 1
    for (let i = 0; i < 16; i += 4) {
      a = rol(add(a, f(b, c, d), x[i]), 3);
      d = rol(add(d, f(a, b, c), x[i + 1]), 7);
      c = rol(add(c, f(d, a, b), x[i + 2]), 11);
      b = rol(add(b, f(c, d, a), x[i + 3]), 19);
    }

    // Round 2
    for (let i = 0; i < 4; i++) {
      a = rol(add(a, g(b, c, d), x[i], 0x5a827999), 3);
      d = rol(add(d, g(a, b, c), x[i + 4], 0x5a827999), 5);
      c = rol(add(c, g(d, a, b), x[i + 8], 0x5a827999), 9);
      b = rol(add(b, g(c, d, a), x[i + 12], 0x5a827999), 13);
    }

    // Round 3
    for (const i of [0, 2, 1, 3]) {
      a = rol(add(a, h(b, c, d), x[i], 0x6ed9eba1), 3);
      d = rol(add(d, h(a, b, c), x[i + 8], 0x6ed9eba1), 9);
      c = rol(add(c, h(d, a, b), x[i + 4], 0x6ed9eba1), 11);
      b = rol(add(b, h(c, d, a), x[i + 12], 0x6ed9eba1), 15);
    }

    a = add(a, aa);
    b = add(b, bb);
    c = add(c, cc);
    d = add(d, dd);
  }

  const result = Buffer.alloc(16);
  result.writeUInt32LE(a >>> 0, 0);
  result.writeUInt32LE(b >>> 0, 4);
  result.writeUInt32LE(c >>> 0, 8);
  result.writeUInt32LE(d >>> 0, 12);
  return result;
}

module.exports = { ntHash, ntHashHash, ntChallengeResponse };
