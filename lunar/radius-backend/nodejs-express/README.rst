==================================================
Example RADIUS backend for Lunar (Node.js/Express)
==================================================

**This example assumes you are a Node.js developer with a working knowledge of
REST APIs, JavaScript, the Express framework and a web server like nginx.**

A minimal, working example of a **lunar backend** written in JavaScript with
`Express <https://expressjs.com/>`_. It implements the same API that
``lunar_backend_sim`` serves, but instead of mirroring attributes back it
performs REAL authentication and hands the subscriber a static IP.

Use it as a starting point for your own backend: copy it, replace the example
user store and the fixed IP with your real logic, and you have a functioning
AAA backend for lunar.

Its only dependency is **Express**. The MS-CHAP crypto (MD4 and DES) is
implemented on top of Node's standard library in ``auth/nt.js`` - OpenSSL 3
moved MD4 and single-DES into its "legacy" provider (off by default), so this
example ships its own so it runs anywhere with no runtime flags.

.. note::

   Testing or playing with lunar? Get a POC licence - without one some features
   are disabled, including accounting, Kafka streaming and more. And when you
   run benchmarks, always disable debug mode in lunar's config first, or the
   numbers will be meaningless. Contact info@interstellio.io for more information.

.. warning::

   **This is example code, not a highly tuned backend.** It is written for
   clarity, not speed. It also logs every exchange in full (request, reply, all
   attributes and source IPs), which is deliberately the slowest thing it does -
   great for seeing exactly how a lunar backend works, terrible for throughput.
   Do not use it as a benchmark and do not judge lunar's performance by it -
   lunar is the fast part; this backend just answers JSON and is meant to be
   read, understood, and adapted. To test lunar's performance, use
   ``lunar_backend_sim`` instead. See `Running it properly`_ for how to scale it.

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

* **Node.js 18 or newer** (``node --version`` should print ``v18`` or higher)
  and ``npm``, which ships with Node.
* The **Express** package, installed with ``npm install`` (see below). Nothing
  else - the MS-CHAP DES and MD4 primitives are implemented in ``auth/nt.js``
  using only Node's built-in ``crypto`` and ``Buffer``.


Installing Node.js
==================

Debian / Ubuntu (apt)
---------------------

The quickest option is the distribution's own package. ``apt`` (the Advanced
Package Tool) is the standard package manager on Debian-based systems and is
pre-installed on Ubuntu and Debian:

.. code:: bash

    sudo apt-get update
    sudo apt-get install -y nodejs npm

The ``sudo`` prefix runs the install as root; you will be prompted for your
password. If ``sudo`` itself is not installed, run the two commands as root
without it (e.g. from ``su -``). If the ``apt-get`` command is missing you are
almost certainly not on a Debian-based distro; use one of the options below.

The catch: the version in the distro repositories can be old (Ubuntu 24.04 ships
Node 18, which works here but is not the latest LTS). For a current Node, use
the official NodeSource feed instead, which registers a repo ``apt`` then
installs from - pick the LTS you want (``20``, ``22``, ...):

.. code:: bash

    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    sudo apt-get install -y nodejs

Version managers (any Linux/macOS)
----------------------------------

To keep several Node versions side by side without touching the system package,
use a version manager - ``nvm`` or ``fnm``:

.. code:: bash

    # nvm
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
    nvm install --lts

    # fnm (faster, single binary)
    curl -fsSL https://fnm.vercel.app/install | bash
    fnm install --lts

Other platforms
---------------

* **Fedora / RHEL / CentOS**: ``sudo dnf install nodejs npm``
* **Arch**: ``sudo pacman -S nodejs npm``
* **macOS**: ``brew install node`` (Homebrew) or the installer below.
* **Windows / any OS**: download the official installer from
  https://nodejs.org/.

After installing, confirm Node and npm are on your ``PATH``:

.. code:: bash

    node --version    # should print v18 or higher
    npm --version


Quick install and run
=====================

From this directory, install the one dependency and start the server:

.. code:: bash

    npm install
    npm start

It listens on ``http://127.0.0.1:5555``. ``npm start`` just runs
``node server.js``; a single Node process handles many concurrent connections
on its event loop, so this is already fine for local testing.

Pass ``--nodebug`` to quiet the per-exchange logging down to nothing (only the
startup line is printed):

.. code:: bash

    node server.js --nodebug

The ``RADIUS_BACKEND_NODEBUG`` environment variable has the same effect.


Running it properly
===================

This example is NOT built for speed - it is a clear, minimal reference. Do not
judge lunar's performance by it. lunar itself is the fast part; the backend just
has to answer JSON, and you scale the backend independently.

On top of that, this backend logs every exchange in full - the request, the
reply, every attribute and the source IPs - and formats it for humans to read.
That verbose, synchronous logging is deliberately the SLOWEST thing it does. It
is a teaching aid, not something you would ever run on a hot path. Always run
with ``--nodebug`` if you measure anything, and remember it is still a
reference, not a fast backend. To measure lunar's actual performance, use
``lunar_backend_sim``.

For anything beyond local testing:

* **Run several worker processes.** A single Node process uses one CPU core. Use
  the built-in ``cluster`` module or a process manager like
  `PM2 <https://pm2.keymetrics.io/>`_ to fork one worker per core, all sharing
  the same listening port:

  .. code:: bash

      RADIUS_BACKEND_NODEBUG=1 pm2 start server.js -i max

  ``-i max`` starts as many workers as there are CPU cores.

* **Put nginx in front** of Node for TLS termination, connection keep-alive and
  load spreading - the same pattern lunar's own install uses. lunar keeps many
  concurrent connections open to the backend, so terminating them at nginx and
  load-balancing across several backend processes (or hosts) is how you scale
  AAA throughput.

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

* ``server.js`` - the Express application and routes, plus the hard-coded
  ``TEST`` virtual returned to lunar. Each route is a small handler mapped with
  ``app.get`` / ``app.post``; the whole request flow (read the packet, detect
  the method, verify it, build the reply) lives inline in the ``auth`` handler
  so it reads top to bottom. PAP is a one-line comparison, so it is done inline;
  the other methods call the modules below.
* ``auth/`` - the credential-verification code (pure bytes in, a boolean or key
  bytes out; no JSON or HTTP):

  * ``auth/chap.js`` - CHAP verification.
  * ``auth/mschap.js`` - MS-CHAPv1 verification.
  * ``auth/mschapv2.js`` - MS-CHAPv2 verification, plus the MS-CHAP2-Success and
    MPPE key bytes returned on accept.
  * ``auth/nt.js`` - the NT-hash, MD4 and DES primitives shared by the MS-CHAP
    modules.
* ``package.json`` - the project manifest (Express is the only dependency).


Make it your own
================

To turn this into a real backend:

* Replace the ``username === "test"`` / password check in ``server.js`` with a
  lookup against your database, directory or API.
* Replace the fixed ``FRAMED_IP`` in ``server.js`` with real address assignment
  (a pool, or a per-subscriber value), and add any other reply attributes you
  need (rate limits, ``Class``, VLAN, ...).
* Handle accounting (``acct``) by recording the session, and CoA by acting on
  your own policy.
