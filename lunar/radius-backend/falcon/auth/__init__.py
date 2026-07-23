"""Authentication primitives for the example RADIUS backend.

The credential-verification logic lives here, split by method so each file is
small and focused:

* ``chap`` - CHAP verification.
* ``mschap`` - MS-CHAPv1 verification.
* ``mschapv2`` - MS-CHAPv2 verification, plus the MS-CHAP2-Success and MPPE
  key bytes returned on accept.
* ``nt`` - the NT-hash and DES primitives shared by the MS-CHAP modules.

Each module takes and returns pure bytes (or a bool decision); all JSON,
attribute and reply handling stays in ``app.py``.
"""
