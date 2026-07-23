==============================================
Example RADIUS backend for Lunar (Spring Boot)
==============================================

**This example assumes you are a Java developer with a working knowledge of
REST APIs, the Spring Boot framework, the embedded Tomcat server and a web
server like nginx.**

A minimal, working example of a **lunar backend** written in Java with
`Spring Boot <https://spring.io/projects/spring-boot>`_. It implements the same
API that ``lunar_backend_sim`` serves, but instead of mirroring attributes back
it performs REAL authentication and hands the subscriber a static IP.

Use it as a starting point for your own backend: copy it, replace the example
user store and the fixed IP with your real logic, and you have a functioning
AAA backend for lunar.

Its only declared dependency is **spring-boot-starter-web** (Spring MVC plus the
embedded Tomcat server). The MS-CHAP crypto (MD4 and DES) is implemented on top
of the JDK in ``auth/`` - the JDK's ``MessageDigest`` does not provide MD4, so
this example ships its own and drives ``javax.crypto``'s DES directly, so
``mvn spring-boot:run`` is all you need.

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

* **Java 17 or newer** (``java -version`` should print ``17`` or higher). Spring
  Boot 3 requires Java 17 as a minimum.
* **Apache Maven 3.6+** (``mvn -version``) to build and run it.
* Nothing else - the MS-CHAP DES and MD4 primitives are implemented in
  ``auth/Nt.java`` using only the JDK.


Installing Java and Maven
=========================

Debian / Ubuntu (apt)
---------------------

The quickest option is the distribution's own packages. ``apt`` (the Advanced
Package Tool) is the standard package manager on Debian-based systems and is
pre-installed on Ubuntu and Debian:

.. code:: bash

    sudo apt-get update
    sudo apt-get install -y default-jdk maven

The ``sudo`` prefix runs the install as root; you will be prompted for your
password. If ``sudo`` itself is not installed, run the commands as root without
it (e.g. from ``su -``). If the ``apt-get`` command is missing you are almost
certainly not on a Debian-based distro; use one of the options below.

Other platforms
---------------

* **Fedora / RHEL / CentOS**: ``sudo dnf install java-17-openjdk-devel maven``
* **Arch**: ``sudo pacman -S jdk-openjdk maven``
* **macOS**: ``brew install openjdk maven`` (Homebrew).
* **Windows / any OS**: install a JDK (for example from
  https://adoptium.net/) and Maven from https://maven.apache.org/download.cgi.

After installing, confirm both are on your ``PATH``:

.. code:: bash

    java -version    # should print 17 or higher
    mvn -version


Quick install and run
=====================

From this directory:

.. code:: bash

    mvn spring-boot:run

It listens on ``http://127.0.0.1:5555``. The first run downloads Spring Boot and
compiles the project; subsequent runs are fast. Tomcat handles many concurrent
connections across a thread pool in a single process, so this is already fine
for local testing.

Pass ``--nodebug`` to quiet the per-exchange logging down to nothing (only the
startup line is printed):

.. code:: bash

    mvn spring-boot:run -Dspring-boot.run.arguments=--nodebug

The ``RADIUS_BACKEND_NODEBUG`` environment variable has the same effect.

To build a standalone executable jar instead of running from source:

.. code:: bash

    mvn package
    java -jar target/radius-backend-1.0.0.jar


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

* **Build a release jar.** ``mvn package`` produces a single executable jar you
  can copy to the target host and run under a process manager (systemd,
  supervisor, ...). One JVM serves every request across the Tomcat thread pool
  and uses all CPU cores, so you do not fork workers the way a single-threaded
  runtime would. Tune the pool with ``server.tomcat.threads.max`` in
  ``application.properties`` for your workload.

* **Put nginx in front** of it for TLS termination, connection keep-alive and
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

* ``src/main/java/io/interstellio/radius/Application.java`` - the Spring Boot
  entry point. It reads ``--nodebug`` / ``RADIUS_BACKEND_NODEBUG``, then starts
  the embedded server.
* ``src/main/java/io/interstellio/radius/BackendController.java`` - the Spring
  MVC controller and routes, plus the hard-coded ``TEST`` virtual returned to
  lunar. Each route is a small handler mapped with ``@GetMapping`` /
  ``@PostMapping``; the whole request flow (read the packet, detect the method,
  verify it, build the reply) lives inline in the ``auth`` handler so it reads
  top to bottom. PAP is a one-line comparison, so it is done inline; the other
  methods call the classes below.
* ``src/main/java/io/interstellio/radius/auth/`` - the credential-verification
  package (pure bytes in, a boolean or key bytes out; no JSON or HTTP):

  * ``Chap.java`` - CHAP verification.
  * ``MsChap.java`` - MS-CHAPv1 verification.
  * ``MsChapV2.java`` - MS-CHAPv2 verification, plus the MS-CHAP2-Success and
    MPPE key bytes returned on accept.
  * ``Nt.java`` - the NT-hash, MD4 and DES primitives shared by the MS-CHAP
    classes.
* ``src/main/resources/application.properties`` - the listen address and port
  and the logging configuration.
* ``pom.xml`` - the Maven project (spring-boot-starter-web is the only
  dependency).


Make it your own
================

To turn this into a real backend:

* Replace the ``USERNAME`` / ``PASSWORD`` check in ``BackendController.java``
  with a lookup against your database, directory or API.
* Replace the fixed ``FRAMED_IP_ADDRESS`` in ``BackendController.java`` with
  real address assignment (a pool, or a per-subscriber value), and add any other
  reply attributes you need (rate limits, ``Class``, VLAN, ...).
* Handle accounting (``acct``) by recording the session, and CoA by acting on
  your own policy.
