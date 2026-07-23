"""CHAP authentication (RFC 2865, section 2.2).

CHAP never sends the password. The NAS sends:

* ``CHAP-Password`` - 1 byte CHAP Identifier followed by a 16-byte MD5 hash.
* ``CHAP-Challenge`` - the challenge the hash was computed over. When this
  attribute is absent, the challenge is the packet's Request Authenticator (the
  ``authenticator`` field of the forwarded packet).

To verify, we recompute ``MD5(chap_id + password + challenge)`` from the
password we hold and compare it to the hash the NAS sent. Both are forwarded by
lunar as raw bytes (``0x`` hex in the packet JSON).
"""

import hashlib
import hmac


def verify(expected_password: str, chap_password: bytes,
           challenge: bytes) -> bool:
    """Return True when the CHAP response matches ``expected_password``.

    ``chap_password`` is the 17-byte ``CHAP-Password`` value (id + hash) and
    ``challenge`` is the CHAP-Challenge (or the Request Authenticator when no
    CHAP-Challenge was sent).
    """
    if expected_password is None or chap_password is None or challenge is None:
        return False
    if len(chap_password) != 17:
        return False

    chap_id = chap_password[0:1]
    sent_hash = chap_password[1:17]

    expected_hash = hashlib.md5(
        chap_id + expected_password.encode("utf-8") + challenge
    ).digest()
    return hmac.compare_digest(expected_hash, sent_hash)
