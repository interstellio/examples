=========================================
Example RADIUS backend for Lunar (Falcon)
=========================================

**This example assumes you are a Python developer with a working knowledge of
REST APIs, the Falcon framework, gunicorn wsgi server and a web server like nginx.**

A minimal, working example of a **lunar backend** written in Python with the
`Falcon <https://falconframework.org/>`_ web framework. It implements the same
API that ``lunar_backend_sim`` serves, but instead of mirroring attributes back
it performs REAL authentication and hands the subscriber a static IP.

Use it as a starting point for your own backend: copy it, replace the example
user store and the fixed IP with your real logic, and you have a functioning
AAA backend for lunar.

.. note::

   Testing or playing with lunar? Get a POC licence - without one some features
   are disabled, including accounting, Kafka streaming and more. And when you
   run benchmarks, always disable debug mode in lunar's config first, or the
   numbers will be meaningless. Contact info@interstellio.io for more information.

.. warning::

   **This is example code, not a highly tuned backend and slow.** It is written for
   clarity, not speed, so it WILL be slower than a production backend. It also
   logs every exchange in full (request, reply, all attributes and source IPs),
   which is deliberately the slowest thing it does - great for seeing exactly
   how a lunar backend works, terrible for throughput. Do not use it as a
   benchmark and do not judge lunar's performance by it - lunar is the fast
   part; this backend just answers JSON and is meant to be read, understood, and
   adapted. To test lunar's performance, use ``lunar_backend_sim`` instead. See
   `Running it properly`_ for how to scale it.

.. tip::

   Need a production-grade backend? We provide design advice, performance tuning
   and best-practice guidance through our professional services that can reach
   hundreds of thousands of access-requests per second - enquire at
   info@interstellio.io.


What it does
============

* Serves lunar its configuration: one hard-coded virtual (``TEST``) with a
  single NAS client on ``127.0.0.1`` whose shared secret is ``testing123`` -
  exactly what ``lunar_backend_sim`` serves.
* Authenticates every Access-Request. The only account is ``test`` / ``test``,
  and it accepts **PAP, CHAP, MS-CHAPv1 and MS-CHAPv2**.
* On success replies ``Access-Accept`` with ``Framed-IP-Address = 192.168.50.50``
  (a static IP for the subscriber); on failure replies ``Access-Reject``. For
  **MS-CHAPv2** it also returns the attributes a server normally adds -
  ``MS-CHAP2-Success`` (mutual authentication) and the ``MS-MPPE-Send-Key`` /
  ``MS-MPPE-Recv-Key`` link-encryption keys.
* Acknowledges accounting and CoA/Disconnect, and accepts the log and health
  endpoints.

Unlike the simulator, it does NOT echo the request attributes back - a reply
carries only what it needs.


Requirements
============

* Python 3.8+ (Python 3.12 or newer recommended - it is what this code is
  developed and tested against)
* ``falcon`` (the web framework)
* ``cryptography`` (the DES primitive used by MS-CHAP / MS-CHAPv2)
* ``gunicorn`` (the WSGI server ``run.py`` uses for the fast, concurrent demo)

All three are listed in ``requirements.txt``.


Quick install and run
=====================

.. warning::

   **Interstellio devs: do NOT create a virtualenv.** The examples project ships
   a preconfigured ``.venv`` (set up by our personal-dev playbook) - creating a
   new one on top of it will break that setup. Just activate the existing one
   and install the requirements:

   .. code:: bash

       source /opt/interstellio/examples/.venv/bin/activate
       pip install -r requirements.txt

If you are running this outside the Interstellio dev box and do not already have
a virtualenv, create one first:

.. code:: bash

    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

Then start it from this directory:

.. code:: bash

    python app.py

It listens on ``http://127.0.0.1:5555``. ``app.py`` uses Python's built-in WSGI
server, which is fine for local testing and trying things out. ``run.py`` will
also tell you (and point you back here) if any dependency is missing.

Running it properly
===================

The built-in server (and this example in general) is NOT built for speed - it is
a clear, minimal reference, and single-process Python is the wrong tool for a
hot RADIUS path. Do not judge lunar's performance by it. lunar itself is the fast
part; the backend just has to answer JSON, and you scale the backend
independently.

On top of that, this backend logs every exchange in full - the request, the
reply, every attribute and the source IPs - and formats it for humans to read.
That verbose, synchronous logging is deliberately the SLOWEST thing it does: it
turns every request into console I/O so you can watch exactly what lunar sends
and what the backend answers. It is a teaching aid, not something you would ever
run on a hot path. A real backend logs sparingly (and asynchronously), so do not
read anything into the throughput you see here - **this code exists only as a
reference example of how a lunar backend works**, not as a fast one. To measure
lunar's actual performance, use ``lunar_backend_sim``.

For anything beyond local testing, run it under a real WSGI server and put it
behind a reverse proxy:

* **Use the bundled** ``run.py`` - the quickest way to demo it fast. It detects
  how many processors the box has and starts gunicorn with several worker
  processes, each with several threads, so the many concurrent connections lunar
  opens are handled in parallel:

  .. code:: bash

      pip install -r requirements.txt
      ./run.py

  It sizes the pool automatically (``2 x cores + 1`` workers, 8 threads each)
  and listens on ``127.0.0.1:5555`` - there is nothing to configure.

  Pass ``--nodebug`` to quiet both this backend and gunicorn down to errors and
  critical only:

  .. code:: bash

      ./run.py --nodebug

  The per-request, human-formatted logging is the slowest thing this example
  does, so silencing it improves throughput - if you must benchmark this
  example, always run it with ``--nodebug`` (and remember it is still a
  reference, not a fast backend).

* **Or run gunicorn directly** if you want to tune the flags yourself:

  .. code:: bash

      gunicorn --workers 8 --threads 8 --worker-class gthread \
          --bind 127.0.0.1:5555 app:application

  Tune ``--workers`` to your CPU (a common start is ``2 x cores + 1``).

* **Put nginx in front** of gunicorn for TLS termination, connection keep-alive
  and load spreading - the same pattern lunar's own install uses. lunar keeps
  many concurrent connections open to the backend, so terminating them at nginx
  and load-balancing across gunicorn workers (or several backend hosts) is how
  you scale AAA throughput.

  Serve it over HTTPS and enable HTTP/2 on nginx (``listen 443 ssl http2;``):
  lunar automatically detects HTTP/2 on a secure connection and uses it, which
  improves performance massively - many requests are multiplexed over a single
  connection instead of one request per connection, cutting connection overhead
  on the hot path.

Even then, treat this as a starting point: a production backend does real work
(database lookups, address assignment) that dominates the time, so size and
scale it for YOUR workload.


Point lunar at it
=================

In ``/opt/lunar/etc/lunar.yaml`` enable the subscriber service and set the
endpoint to this backend (plain HTTP, so TLS verification is irrelevant):

.. code:: yaml

    services:
      subscriber: true

    subscriber:
      endpoint: http://127.0.0.1:5555
      ssl_verify: false

Do NOT enable ``protocol.radius.testing`` - that bypasses the backend entirely
and starts lunar's own built-in test virtual instead. Restart lunar; it will
fetch the ``TEST`` virtual from this backend and start a RADIUS server on
localhost.


Test it
=======

Use ``radtest`` (ships with lunar) against the running lunar instance. The NAS
secret is ``testing123``; the account is ``test`` / ``test``:

.. code:: bash

    /opt/lunar/bin/radtest --username test --password test 127.0.0.1 testing123

You should get an ``Access-Accept`` carrying ``Framed-IP-Address = 192.168.50.50``.
Try the other methods with ``-t``:

.. code:: bash

    /opt/lunar/bin/radtest -t pap --username test --password test 127.0.0.1 testing123
    /opt/lunar/bin/radtest -t chap --username test --password test 127.0.0.1 testing123
    /opt/lunar/bin/radtest -t mschap --username test --password test 127.0.0.1 testing123
    /opt/lunar/bin/radtest -t mschapv2 --username test --password test 127.0.0.1 testing123

A wrong password returns ``Access-Reject``. The backend also logs every exchange
it handles - the request, the reply and the source IPs - to its console.


Endpoints
=========

The backend implements the lunar backend API:

+-----------------------------------------------------+--------+---------------------------+
| Path                                                | Method | Purpose                   |
+=====================================================+========+===========================+
| /v1/lunar/radius/{server_id}/virtuals               | GET    | List virtuals (the TEST   |
|                                                     |        | virtual).                 |
+-----------------------------------------------------+--------+---------------------------+
| /v1/lunar/radius/{server_id}/virtual/{id}           | GET    | One virtual by id.        |
+-----------------------------------------------------+--------+---------------------------+
| /v1/lunar/radius/{server_id}/{type}/{virtual_id}    | POST   | An inbound packet;        |
|                                                     |        | type is auth/acct/coa.    |
+-----------------------------------------------------+--------+---------------------------+
| /v1/lunar/radius/{server_id}/log                    | POST   | Remote log line (201).    |
+-----------------------------------------------------+--------+---------------------------+
| /v1/lunar/radius/ping                               | GET    | Health probe (200).       |
+-----------------------------------------------------+--------+---------------------------+

It speaks JSON, the default lunar encoding. (lunar's experimental MessagePack
encoding is not implemented here.)


How authentication works
========================

lunar decodes the RADIUS packet and forwards it as JSON, so this backend never
touches the wire. Which credential attribute is present tells us the method:

* **PAP** - ``User-Password``. lunar has already decrypted it, so we compare the
  clear-text password directly.
* **CHAP** - ``CHAP-Password`` (id + MD5 hash). The challenge is
  ``CHAP-Challenge`` or, when absent, the packet's Request Authenticator. We
  recompute the hash and compare.
* **MS-CHAPv1** - ``MS-CHAP-Challenge`` (8 bytes) + ``MS-CHAP-Response``. We
  verify the NT-Response.
* **MS-CHAPv2** - ``MS-CHAP-Challenge`` (16 bytes) + ``MS-CHAP2-Response``. We
  derive the challenge hash and verify the NT-Response. On success we also
  return ``MS-CHAP2-Success`` (so the client can verify the server) and the
  ``MS-MPPE-Send-Key`` / ``MS-MPPE-Recv-Key`` MPPE keys (RFC 2759 / RFC 3079),
  as most servers do. The MPPE keys are sent as plaintext ``0x`` hex; lunar
  salt-encrypts them on the wire with the shared secret (they are ``encrypt=2``
  attributes), so this backend never needs the Request Authenticator.

Binary credential attributes are carried as ``0x`` hex in the packet JSON.


Code layout
===========

* ``app.py`` - the Falcon application and routes, plus the hard-coded ``TEST``
  virtual returned to lunar. Each route is a small resource class; the whole
  request flow (read the packet, detect the method, verify it, build the reply)
  lives inline in ``AuthResource.on_post`` so it reads top to bottom. PAP is a
  one-line comparison, so it is done inline; the other methods call the modules
  below.
* ``auth/`` - the credential-verification package (pure bytes in, a bool or key
  bytes out; no JSON or HTTP):

  * ``auth/chap.py`` - CHAP verification.
  * ``auth/mschap.py`` - MS-CHAPv1 verification.
  * ``auth/mschapv2.py`` - MS-CHAPv2 verification, plus the MS-CHAP2-Success and
    MPPE key bytes returned on accept.
  * ``auth/nt.py`` - the NT-hash and DES primitives shared by the MS-CHAP
    modules.


Make it your own
================

To turn this into a real backend:

* Replace the ``username == "test"`` / password check in ``AuthResource`` with a
  lookup against your database, directory or API.
* Replace the fixed ``FRAMED_IP_ADDRESS`` in ``app.py`` with real address
  assignment (a pool, or a per-subscriber value), and add any other reply
  attributes you need (rate limits, ``Class``, VLAN, ...).
* Handle accounting (``acct``) by recording the session, and CoA by acting on
  your own policy.
