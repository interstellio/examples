"""Shared NT-hash and DES primitives for the MS-CHAP family.

MS-CHAPv1 and MS-CHAPv2 both authenticate by encrypting a challenge with a key
derived from the "NT hash" of the user's password. This module provides the two
low-level pieces they share, so ``mschap.py`` and ``mschapv2.py`` do not
duplicate the crypto:

* :func:`nt_hash` - the NT hash of a password (MD4 of the UTF-16LE password).
* :func:`nt_challenge_response` - the 24-byte DES response over an 8-byte
  challenge, as defined by RFC 2433 (MS-CHAPv1) and RFC 2759 (MS-CHAPv2).

DES is provided by the ``cryptography`` package. Single DES is expressed as
Triple DES with an 8-byte key (which makes K1 = K2 = K3, i.e. plain DES).

This is EXAMPLE code, favouring clarity over completeness; a production
backend would look the user up in a real store and handle more edge cases.
"""

import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, modes

# TripleDES moved to the "decrepit" module in newer cryptography releases.
# Try the new location first, then fall back to the classic one.
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # pragma: no cover - depends on cryptography version
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES


def _md4(data: bytes) -> bytes:
    """Return the MD4 digest of *data*.

    MD4 is legacy and is often absent from ``hashlib`` on OpenSSL 3 builds, so
    fall back to a small pure-Python implementation when it is unavailable.
    """
    try:
        return hashlib.new("md4", data).digest()
    except (ValueError, TypeError):
        return _md4_pure(data)


def _md4_pure(message: bytes) -> bytes:
    """A compact, self-contained MD4 (RFC 1320) used only as a fallback."""
    mask = 0xFFFFFFFF

    def rol(x, c):
        x &= mask
        return ((x << c) | (x >> (32 - c))) & mask

    def f(x, y, z):
        return (x & y) | (~x & z)

    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(x, y, z):
        return x ^ y ^ z

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    # Pad the message to a multiple of 64 bytes (MD4 padding).
    length = len(message)
    message += b"\x80"
    while len(message) % 64 != 56:
        message += b"\x00"
    message += (length * 8).to_bytes(8, "little")

    for offset in range(0, len(message), 64):
        block = message[offset:offset + 64]
        x = [int.from_bytes(block[i:i + 4], "little")
             for i in range(0, 64, 4)]
        aa, bb, cc, dd = a, b, c, d

        # Round 1
        for i in range(0, 16, 4):
            a = rol(a + f(b, c, d) + x[i], 3)
            d = rol(d + f(a, b, c) + x[i + 1], 7)
            c = rol(c + f(d, a, b) + x[i + 2], 11)
            b = rol(b + f(c, d, a) + x[i + 3], 19)

        # Round 2
        for i in range(4):
            a = rol(a + g(b, c, d) + x[i] + 0x5A827999, 3)
            d = rol(d + g(a, b, c) + x[i + 4] + 0x5A827999, 5)
            c = rol(c + g(d, a, b) + x[i + 8] + 0x5A827999, 9)
            b = rol(b + g(c, d, a) + x[i + 12] + 0x5A827999, 13)

        # Round 3
        for i in (0, 2, 1, 3):
            a = rol(a + h(b, c, d) + x[i] + 0x6ED9EBA1, 3)
            d = rol(d + h(a, b, c) + x[i + 8] + 0x6ED9EBA1, 9)
            c = rol(c + h(d, a, b) + x[i + 4] + 0x6ED9EBA1, 11)
            b = rol(b + h(c, d, a) + x[i + 12] + 0x6ED9EBA1, 15)

        a = (a + aa) & mask
        b = (b + bb) & mask
        c = (c + cc) & mask
        d = (d + dd) & mask

    return b"".join(v.to_bytes(4, "little") for v in (a, b, c, d))


def nt_hash(password: str) -> bytes:
    """Return the 16-byte NT hash of *password* (MD4 of the UTF-16LE bytes)."""
    return _md4(password.encode("utf-16-le"))


def nt_hash_hash(password: str) -> bytes:
    """Return MD4 of the NT hash.

    MS-CHAPv2 uses this "password-hash-hash" both for the server authenticator
    response (MS-CHAP2-Success) and to derive the MPPE session keys.
    """
    return _md4(nt_hash(password))


def _expand_des_key(key7: bytes) -> bytes:
    """Expand a 7-byte key into the 8-byte form DES expects.

    DES keys are 64 bits with one parity bit per byte, so 56 bits of real key
    material are spread across 8 bytes. This is the standard MS-CHAP key
    expansion (the parity bits themselves are ignored by DES).
    """
    key = bytearray(8)
    key[0] = key7[0] >> 1
    key[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2)
    key[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3)
    key[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4)
    key[4] = ((key7[3] & 0x0F) << 3) | (key7[4] >> 5)
    key[5] = ((key7[4] & 0x1F) << 2) | (key7[5] >> 6)
    key[6] = ((key7[5] & 0x3F) << 1) | (key7[6] >> 7)
    key[7] = key7[6] & 0x7F
    return bytes((byte << 1) & 0xFF for byte in key)


def _des_encrypt(key7: bytes, block8: bytes) -> bytes:
    """DES-ECB encrypt one 8-byte *block8* with a 7-byte key."""
    key8 = _expand_des_key(key7)
    # Triple DES with the same 8-byte key repeated three times (K1 == K2 ==
    # K3) is exactly single DES, and avoids the deprecated single-key form.
    encryptor = Cipher(TripleDES(key8 * 3), modes.ECB()).encryptor()
    return encryptor.update(block8) + encryptor.finalize()


def nt_challenge_response(challenge8: bytes, password_nt_hash: bytes) -> bytes:
    """Return the 24-byte NT response over an 8-byte challenge.

    The 16-byte NT hash is padded to 21 bytes and split into three 7-byte DES
    keys; each encrypts the same 8-byte challenge, and the three 8-byte results
    are concatenated into the 24-byte response.
    """
    padded = password_nt_hash + b"\x00" * (21 - len(password_nt_hash))
    return b"".join(
        _des_encrypt(padded[i:i + 7], challenge8) for i in range(0, 21, 7)
    )
