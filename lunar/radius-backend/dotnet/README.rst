===============================================
Example RADIUS backend for Lunar (ASP.NET Core)
===============================================

**This example assumes you are a .NET developer with a working knowledge of
REST APIs, C#, the ASP.NET Core minimal-API model, the Kestrel server and a web
server like nginx.**

A minimal, working example of a **lunar backend** written in C# with
`ASP.NET Core minimal APIs <https://learn.microsoft.com/aspnet/core/fundamentals/minimal-apis>`_.
It implements the same API that ``lunar_backend_sim`` serves, but instead of
mirroring attributes back it performs REAL authentication and hands the
subscriber a static IP.

Use it as a starting point for your own backend: copy it, replace the example
user store and the fixed IP with your real logic, and you have a functioning
AAA backend for lunar.

It has **zero NuGet dependencies** - the MS-CHAP crypto (MD4 and DES) is
implemented on top of the .NET base class library, so ``dotnet run`` is all you
need.

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

* The **.NET SDK 8.0** or newer (``dotnet --version`` should print ``8.x`` or
  higher).
* Nothing else - there are no NuGet packages to restore. The MS-CHAP DES and
  MD4 primitives are implemented in ``Auth/Nt.cs`` using only the base class
  library.


Installing the .NET SDK
=======================

Debian / Ubuntu (apt)
---------------------

On Ubuntu 22.04+ and Debian 12+ the SDK ships in the distribution's own
repositories, so ``apt`` installs it directly - no Microsoft feed to add:

.. code:: bash

    sudo apt-get update
    sudo apt-get install -y dotnet-sdk-8.0

``apt`` (the Advanced Package Tool) is the standard package manager on
Debian-based systems and is pre-installed on Ubuntu and Debian - if the
``apt-get`` command is missing you are almost certainly not on a Debian-based
distro; use one of the options below instead. The ``sudo`` prefix runs the
install as root; you will be prompted for your password. If ``sudo`` itself is
not installed, run the two commands as root without it (e.g. from ``su -``).

Older Ubuntu/Debian releases may not carry ``dotnet-sdk-8.0`` in their own
repositories. Add Microsoft's package feed first, then install as above:

.. code:: bash

    wget https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O /tmp/pmc.deb
    sudo dpkg -i /tmp/pmc.deb
    sudo apt-get update
    sudo apt-get install -y dotnet-sdk-8.0

Other platforms
---------------

* **Fedora / RHEL / CentOS**: ``sudo dnf install dotnet-sdk-8.0``
* **Arch**: ``sudo pacman -S dotnet-sdk``
* **macOS**: ``brew install dotnet-sdk`` (Homebrew) or the installer below.
* **Windows / any OS**: download the official installer or a portable build
  from https://dotnet.microsoft.com/download.

After installing, confirm the SDK is on your ``PATH``:

.. code:: bash

    dotnet --version    # should print 8.x or higher
    dotnet --list-sdks  # lists every installed SDK



Quick install and run
=====================

From this directory:

.. code:: bash

    dotnet run

It listens on ``http://127.0.0.1:5555``. The first run compiles the project;
subsequent runs are instant. Kestrel handles many concurrent connections in a
single process, so this is already fine for local testing.

Pass ``--nodebug`` to quiet the per-exchange logging down to nothing (only the
startup line is printed):

.. code:: bash

    dotnet run -- --nodebug

The ``--`` separates ``dotnet`` arguments from the program's own. The
``RADIUS_BACKEND_NODEBUG`` environment variable has the same effect.


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

* **Publish a Release build** instead of ``dotnet run`` (which is a Debug build):

  .. code:: bash

      dotnet publish -c Release -o out
      RADIUS_BACKEND_NODEBUG=1 ./out/radius-backend

  A Release build is optimised and starts faster. Kestrel scales across all
  cores automatically via async I/O and the thread pool - there is no separate
  worker-process step to configure as there is with Python's uvicorn.

* **Put nginx in front** of Kestrel for TLS termination, connection keep-alive
  and load spreading - the same pattern lunar's own install uses. lunar keeps
  many concurrent connections open to the backend, so terminating them at nginx
  and load-balancing across several backend hosts is how you scale AAA
  throughput.

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

+----------------------------------------------+--------+---------------------------+
| Path                                         | Method | Purpose                   |
+==============================================+========+===========================+
| /v1/lunar/{server_id}/virtuals               | GET    | List virtuals (the TEST   |
|                                              |        | virtual).                 |
+----------------------------------------------+--------+---------------------------+
| /v1/lunar/{server_id}/virtual/{id}           | GET    | One virtual by id.        |
+----------------------------------------------+--------+---------------------------+
| /v1/lunar/{server_id}/{type}/{virtual_id}    | POST   | An inbound packet;        |
|                                              |        | type is auth/acct/coa.    |
+----------------------------------------------+--------+---------------------------+
| /v1/lunar/{server_id}/log                    | POST   | Remote log line (201).    |
+----------------------------------------------+--------+---------------------------+
| /v1/lunar/ping                               | GET    | Health probe (200).       |
+----------------------------------------------+--------+---------------------------+

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

* ``Program.cs`` - the minimal-API application and routes, plus the hard-coded
  ``TEST`` virtual returned to lunar. Each route is a small lambda mapped with
  ``app.MapGet`` / ``app.MapPost``; the whole request flow (read the packet,
  detect the method, verify it, build the reply) lives inline in the ``auth``
  handler so it reads top to bottom. PAP is a one-line comparison, so it is done
  inline; the other methods call the classes below.
* ``Auth/`` - the credential-verification code (pure bytes in, a bool or key
  bytes out; no JSON or HTTP):

  * ``Auth/Chap.cs`` - CHAP verification.
  * ``Auth/MsChap.cs`` - MS-CHAPv1 verification.
  * ``Auth/MsChapV2.cs`` - MS-CHAPv2 verification, plus the MS-CHAP2-Success and
    MPPE key bytes returned on accept.
  * ``Auth/Nt.cs`` - the NT-hash, MD4 and DES primitives shared by the MS-CHAP
    classes.
* ``RadiusBackend.csproj`` - the project file (targets ``net8.0``, no packages).


Make it your own
================

To turn this into a real backend:

* Replace the ``username == "test"`` / password check in ``Program.cs`` with a
  lookup against your database, directory or API.
* Replace the fixed ``FramedIp`` in ``Program.cs`` with real address assignment
  (a pool, or a per-subscriber value), and add any other reply attributes you
  need (rate limits, ``Class``, VLAN, ...).
* Handle accounting (``acct``) by recording the session, and CoA by acting on
  your own policy.
