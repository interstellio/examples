"""MS-CHAPv2 authentication (RFC 2759).

The NAS sends two Microsoft vendor attributes:

* ``MS-CHAP-Challenge`` - the 16-byte Authenticator Challenge.
* ``MS-CHAP2-Response`` - 50 bytes: Ident (1), Flags (1), Peer-Challenge (16),
  Reserved (8) and NT-Response (24).

MS-CHAPv2 first derives an 8-byte "Challenge Hash" from the peer and
authenticator challenges and the user name, then computes the NT-Response over
that hash (keyed by the NT hash of the password) exactly as MS-CHAPv1 does. We
recompute it and compare. All values are forwarded by lunar as raw bytes
(``0x`` hex in the packet JSON); the user name is a normal text attribute.

On success, :func:`success_and_keys` also returns what a server normally
adds to the Access-Accept: the MS-CHAP2-Success value (so the client can
verify the server - MS-CHAPv2 is mutual authentication) and the MPPE
link-encryption keys. This module only computes the bytes; the caller sets
the reply attributes.
"""

import hashlib
import hmac

from . import nt


def _challenge_hash(peer_challenge: bytes, authenticator_challenge: bytes,
                    username: str) -> bytes:
    """Return the 8-byte Challenge Hash (RFC 2759, GenerateNTResponse)."""
    digest = hashlib.sha1(
        peer_challenge + authenticator_challenge + username.encode("ascii")
    ).digest()
    return digest[:8]


def verify(expected_password: str, username: str, challenge: bytes,
           response: bytes) -> bool:
    """Return True when the MS-CHAPv2 NT-Response matches.

    ``challenge`` is the 16-byte ``MS-CHAP-Challenge`` (Authenticator
    Challenge) and ``response`` is the 50-byte ``MS-CHAP2-Response``.
    """
    if expected_password is None or username is None:
        return False
    if challenge is None or response is None:
        return False
    if len(challenge) != 16 or len(response) != 50:
        return False

    peer_challenge = response[2:18]
    nt_response = response[26:50]

    challenge_hash = _challenge_hash(peer_challenge, challenge, username)
    expected = nt.nt_challenge_response(
        challenge_hash, nt.nt_hash(expected_password)
    )
    return hmac.compare_digest(expected, nt_response)


# --- MS-CHAP2-Success and MPPE keys (RFC 2759 + RFC 3079) ----------------
#
# On a successful MS-CHAPv2 auth a server normally adds three Microsoft
# attributes to the Access-Accept, and this backend does the same:
#
#   * MS-CHAP2-Success   - lets the CLIENT verify the server (mutual auth). It
#                          is the response Ident byte followed by an "S=<hex>"
#                          string.
#   * MS-MPPE-Send-Key    - the MPPE session keys that encrypt the PPP link
#   * MS-MPPE-Recv-Key      (PPTP, some L2TP), derived from the password hash.
#
# This module only COMPUTES the raw bytes; app.py sets the reply attributes.
# The MPPE keys are sent as PLAINTEXT 0x hex - lunar salt-encrypts them on the
# wire with the shared secret (they are marked encrypt=2 in the RADIUS
# dictionary), so this backend never needs the Request Authenticator.

# Magic constants, byte-for-byte, from RFC 2759 (success) and RFC 3079 (MPPE).
_MAGIC_SIGN = b"Magic server to client signing constant"
_MAGIC_PAD = b"Pad to make it do more than one iteration"
_MAGIC_MASTER = b"This is the MPPE Master Key"
# On the SERVER, the send key uses this constant and the receive key the other.
_MAGIC_SERVER_SEND = (
    b"On the client side, this is the receive key; "
    b"on the server side, it is the send key."
)
_MAGIC_SERVER_RECV = (
    b"On the client side, this is the send key; "
    b"on the server side, it is the receive key."
)


def _authenticator_response(password, username, peer_challenge,
                            authenticator_challenge, nt_response):
    """Return the "S=<hex>" server authenticator response (RFC 2759)."""
    password_hash_hash = nt.nt_hash_hash(password)
    challenge_hash = _challenge_hash(
        peer_challenge, authenticator_challenge, username
    )
    digest = hashlib.sha1(
        password_hash_hash + nt_response + _MAGIC_SIGN
    ).digest()
    response = hashlib.sha1(digest + challenge_hash + _MAGIC_PAD).digest()
    return "S=" + response.hex().upper()


def _mppe_session_key(master_key, magic):
    """Derive one 16-byte MPPE session key from the master key (RFC 3079)."""
    return hashlib.sha1(
        master_key + b"\x00" * 40 + magic + b"\xf2" * 40
    ).digest()[:16]


def success_and_keys(password, username, challenge, response):
    """Return the raw MS-CHAP2-Success value and the two MPPE keys.

    ``challenge`` is the 16-byte MS-CHAP-Challenge and ``response`` the 50-byte
    MS-CHAP2-Response. Returns ``(success, send_key, recv_key)`` as bytes; the
    caller turns them into reply attributes.
    """
    ident = response[0:1]
    peer_challenge = response[2:18]
    nt_response = response[26:50]

    # MS-CHAP2-Success: the response Ident byte, then the "S=<hex>" string.
    success = ident + _authenticator_response(
        password, username, peer_challenge, challenge, nt_response
    ).encode("ascii")

    # MPPE keys: one 16-byte master key, then a send and a receive session key.
    master_key = hashlib.sha1(
        nt.nt_hash_hash(password) + nt_response + _MAGIC_MASTER
    ).digest()[:16]
    send_key = _mppe_session_key(master_key, _MAGIC_SERVER_SEND)
    recv_key = _mppe_session_key(master_key, _MAGIC_SERVER_RECV)

    return success, send_key, recv_key
