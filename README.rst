=====================
Interstellio Examples
=====================

A public repository of example code for using Interstellio products - code snippets
and miniature, self-contained example backends that customers can read, copy
and adapt to their own systems.

Everything here is EXAMPLE code: written for clarity, meant to be understood and
used as a starting point, not as production-tuned software. Each example is
self-contained and ships with its own README explaining what it does, how to run
it and how to make it your own.


What's inside
=============

* ``lunar/`` - examples for **Lunar**, the Interstellio network services engine
  (today its RADIUS server, with more protocols such as SNMP and DNS to come).

  * ``lunar/radius-backend/`` - miniature backends that implement the lunar
    backend API (authentication, accounting and CoA), in several languages and
    frameworks (Falcon, async Falcon, Flask, FastAPI, PHP, ASP.NET Core,
    Node.js/Express, Go and Spring Boot). See
    ``lunar/radius-backend/README.rst``.

More examples for other products and languages will be added over time.


Licence
=======

Copyright (c) Interstellio IO (PTY) LTD.

This code is provided as-is, free for use by anybody, for any purpose, without
warranty of any kind. You may use, copy, modify and distribute it freely,
including in commercial projects.
