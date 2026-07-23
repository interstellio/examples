======================================
Example RADIUS backend for Lunar (PHP)
======================================

**This example assumes you are a PHP developer with a working knowledge of
REST APIs, php-fpm and a web server like nginx.**

A minimal, working example of a **lunar backend** written in plain PHP - no
framework and no Composer. It implements the same API that ``lunar_backend_sim``
serves, but instead of mirroring attributes back it performs REAL
authentication and hands the subscriber a static IP.

Use it as a starting point for your own backend: copy it, replace the example
user store and the fixed IP with your real logic, and you have a functioning
AAA backend for lunar.

.. note::

   Testing or playing with lunar? Get a POC licence - without one some features
   are disabled, including accounting, Kafka streaming and more. And when you
   run benchmarks, always disable debug mode in lunar's config first, or the
   numbers will be meaningless. Contact info@interstellio.io for more
   information.

.. warning::

   **This is example code, not a highly tuned backend and slow.** It is written
   for clarity, not speed, so it WILL be slower than a production backend. It
   also logs every exchange in full (request, reply, all attributes and source
   IPs), which is deliberately the slowest thing it does - great for seeing
   exactly how a lunar backend works, terrible for throughput. Do not use it as
   a benchmark and do not judge lunar's performance by it - lunar is the fast
   part; this backend just answers JSON and is meant to be read, understood,
   and adapted. To test lunar's performance, use ``lunar_backend_sim`` instead.
   See `Running it properly`_ for how to scale it.

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
* On success replies ``Access-Accept`` with
  ``Framed-IP-Address = 192.168.50.50`` (a static IP for the subscriber); on
  failure replies ``Access-Reject`` with a ``Reply-Message``. For **MS-CHAPv2**
  it also returns ``MS-CHAP2-Success`` (mutual authentication) and the
  ``MS-MPPE-Send-Key`` / ``MS-MPPE-Recv-Key`` link-encryption keys.
* Acknowledges accounting and CoA/Disconnect, and accepts the log and health
  endpoints.


Requirements
============

* PHP 8.0+ (Ubuntu 24.04 ships **PHP 8.3**; the ``cli`` build is enough for the
  demo server).
* The ``openssl`` extension (DES for MS-CHAP / MS-CHAPv2), the ``hash``
  extension with ``md4`` (the NT hash), plus ``iconv`` and ``json``. All four
  are compiled into the core PHP package on Ubuntu - there is nothing extra to
  install and no Composer packages are needed.

Ubuntu 24.04 install
--------------------

For the demo (the built-in ``php -S`` server):

.. code:: bash

    sudo apt update
    sudo apt install php8.3-cli

For production (php-fpm behind nginx, see `Running it properly`_):

.. code:: bash

    sudo apt install php8.3-fpm php8.3-cli nginx

That is everything - ``openssl``, ``hash`` (with ``md4``), ``iconv`` and
``json`` all come bundled in ``php8.3-cli`` / ``php8.3-fpm``. You can confirm
they are present with:

.. code:: bash

    php -m | grep -iE 'openssl|hash|iconv|json'
    php -r "var_dump(in_array('md4', hash_algos()));"    # must print bool(true)


Install and run
===============

There is nothing to build. From this directory start PHP's built-in server
with ``index.php`` as the front controller - every request is routed through
it:

.. code:: bash

    php -S 127.0.0.1:5555 index.php

It listens on ``http://127.0.0.1:5555``. The built-in server is single-process
and fine for local testing and trying things out.


Running it properly
===================

The built-in server (and this example in general) is NOT built for speed - it
is a clear, minimal reference, and the single-process ``php -S`` server is the
wrong tool for a hot RADIUS path. Do not judge lunar's performance by it. lunar
itself is the fast part; the backend just has to answer JSON.

On top of that, this backend logs every exchange in full - the request, the
reply, every attribute and the source IPs. That verbose logging is deliberately
the SLOWEST thing it does, so you can watch exactly what lunar sends and what
the backend answers. A real backend logs sparingly, so do not read anything
into the throughput you see here.

For anything beyond local testing, run it under **php-fpm behind nginx** - the
same front controller, just a real server in front:

* **Install php-fpm and nginx**, then point a server block at this directory
  and route every request to ``index.php`` (the front controller). php-fpm's
  worker pool is what gives you concurrency:

  .. code:: nginx

      server {
          listen 443 ssl http2;
          server_name radius-backend.example.com;

          include snippets/snakeoil.conf;
          gzip off;

          root /opt/interstellio/examples/lunar/radius-backend/php;
          index index.php;

          # Every request goes to the front controller.
          location / {
              try_files $uri /index.php$is_args$args;
          }

          location ~ \.php$ {
              include fastcgi_params;
              fastcgi_pass unix:/run/php/php8.3-fpm.sock;
              fastcgi_param SCRIPT_FILENAME $document_root/index.php;
          }
      }

* **Keepalive.** The *client* side (lunar <-> nginx) is kept alive by nginx by
  default, which is the hop that matters - lunar holds many connections open and
  reuses them. We deliberately do NOT keep the *upstream* side (nginx <->
  php-fpm) alive: a persistent FastCGI connection pins one php-fpm child for its
  whole life, even while idle, so an ``upstream ... keepalive`` pool starves the
  worker pool under load. A plain ``fastcgi_pass`` to the socket (above) hands
  each request to a free child and is the safe default.

* **Tune the php-fpm pool** in ``/etc/php/8.3/fpm/pool.d/www.conf`` - this is
  the equivalent of sizing worker processes. Each php-fpm child serves one
  request at a time, so the pool size sets your concurrency:

  .. code:: ini

      pm = dynamic
      pm.max_children = 1024
      pm.start_servers = 32
      pm.min_spare_servers = 8
      pm.max_spare_servers = 32

  Reload after editing: ``sudo systemctl reload php8.3-fpm``. What each does and
  why these values:

  * ``pm = dynamic`` - php-fpm keeps a pool of idle workers ready and spawns
    more on demand up to the ceiling, then lets them go when the burst ends.
    That fits a spiky RADIUS hot path: quiet most of the time, bursty when many
    subscribers reconnect at once.
  * ``pm.max_children = 1024`` - the HARD ceiling on worker processes, and the
    single most important value. Each child handles one request at a time, so
    this is your maximum concurrency. When it is reached, new requests queue in
    the socket backlog and eventually 502 - which is exactly the "works after a
    restart, dies under load, recovers a minute later" symptom. Set it well
    above your expected concurrent request count so bursts have headroom.
  * ``pm.start_servers = 32`` - how many workers exist right after a
    (re)start, so the first burst is served immediately instead of paying
    spawn latency. 32 gives a healthy warm pool.
  * ``pm.min_spare_servers = 8`` - keep at least this many idle workers ready
    to absorb a sudden spike without waiting to fork.
  * ``pm.max_spare_servers = 32`` - trim idle workers back down to at most this
    many once a burst passes, so an idle box does not sit on hundreds of
    processes.

  Size ``pm.max_children`` to your RAM too: roughly
  ``available_RAM / average_process_size``. 1024 workers only makes sense if the
  box has the memory for it - lower the ceiling on a small box.

* **Enable HTTP/2** on nginx (``listen 443 ssl http2;`` above): lunar
  automatically detects HTTP/2 on a secure connection and uses it, which
  improves performance - many requests are multiplexed over a single connection
  instead of one request per connection, cutting connection overhead on the hot
  path.

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
    /opt/lunar/bin/radtest -t chap --username test --password test 127.0.0.1 testing123
    /opt/lunar/bin/radtest -t mschap --username test --password test 127.0.0.1 testing123
    /opt/lunar/bin/radtest -t mschapv2 --username test --password test 127.0.0.1 testing123

You can also hit the backend directly with ``curl``:

.. code:: bash

    curl -s http://127.0.0.1:5555/v1/lunar/s1/auth/TEST \
        -d '{"attributes":{"User-Name":{"values":["test"]},
             "User-Password":{"values":["test"]}}}'

A wrong password returns ``Access-Reject`` with a ``Reply-Message``. The backend
also logs every exchange it handles - the request, the reply and the source IPs
- to its error log (stderr under ``php -S``).


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

It speaks JSON, the default lunar encoding.


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
  ``MS-MPPE-Send-Key`` / ``MS-MPPE-Recv-Key`` MPPE keys (RFC 2759 / RFC 3079).
  The MPPE keys are sent as plaintext ``0x`` hex; lunar salt-encrypts them on
  the wire with the shared secret.

Binary credential attributes are carried as ``0x`` hex in the packet JSON, so
each is decoded with ``hex2bin(substr($value, 2))`` - dropping the leading
``0x`` before decoding the hex digits.


Code layout
===========

* ``index.php`` - the front controller: the hard-coded ``TEST`` virtual, the
  route table lunar calls, and one handler function per route. The whole
  request flow (read the packet, detect the method, verify it, build the reply)
  lives inline in ``auth()`` so it reads top to bottom. PAP is a one-line
  comparison, so it is done inline; the other methods call the files below.
* ``auth/chap.php`` - CHAP verification.
* ``auth/mschap.php`` - MS-CHAPv1 verification.
* ``auth/mschapv2.php`` - MS-CHAPv2 verification, plus the MS-CHAP2-Success and
  MPPE key bytes returned on accept.
* ``auth/nt.php`` - the NT-hash and DES primitives shared by the MS-CHAP files.


Make it your own
================

To turn this into a real backend:

* Replace the ``$username === USERNAME`` / password check in ``auth()`` with a
  lookup against your database, directory or API.
* Replace the fixed ``FRAMED_IP_ADDRESS`` with real address assignment (a pool,
  or a per-subscriber value), and add any other reply attributes you need.
* Handle accounting (``acct``) by recording the session, and CoA by acting on
  your own policy.
