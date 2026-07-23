"""MS-CHAPv1 authentication (RFC 2433).

The NAS sends two Microsoft vendor attributes:

* ``MS-CHAP-Challenge`` - the 8-byte challenge.
* ``MS-CHAP-Response`` - 50 bytes: Ident (1), Flags (1), LM-Response (24) and
  NT-Response (24).

We verify the NT-Response only (the LM-Response is obsolete and often zero):
the 24-byte DES response over the challenge, keyed by the NT hash of the
password. lunar forwards both attributes as raw bytes (``0x`` hex).
"""

import hmac

from . import nt


def verify(expected_password: str, challenge: bytes, response: bytes) -> bool:
    """Return True when the MS-CHAPv1 NT-Response matches.

    ``challenge`` is the 8-byte ``MS-CHAP-Challenge`` and ``response`` is the
    50-byte ``MS-CHAP-Response``.
    """
    if expected_password is None or challenge is None or response is None:
        return False
    if len(challenge) != 8 or len(response) != 50:
        return False

    nt_response = response[26:50]
    expected = nt.nt_challenge_response(
        challenge, nt.nt_hash(expected_password))
    return hmac.compare_digest(expected, nt_response)
