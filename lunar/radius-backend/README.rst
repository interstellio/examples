=================================
Example RADIUS backends for Lunar
=================================

Working example backends that implement the lunar backend API - the HTTP/JSON
API lunar calls to authenticate users, record accounting and drive dynamic
authorization. Each is a self-contained starting point you can copy and adapt to
your own systems.

Each example lives in its own directory with its own README. They are
deliberately identical in behaviour so you can compare frameworks side by side:
each authenticates a single test account (``test`` / ``test``) over **PAP,
CHAP, MS-CHAPv1 and MS-CHAPv2**, returns a static
``Framed-IP-Address = 192.168.50.50`` on success (with a ``Reply-Message`` on
reject), and acknowledges accounting, CoA, the log endpoint and the health
probe.

* ``falcon/`` - a Python backend on the **Falcon** framework (WSGI), served
  with gunicorn. See ``falcon/README.rst``.
* ``falcon-async/`` - the same backend on **async Falcon** (ASGI), served with
  uvicorn + uvloop. See ``falcon-async/README.rst``.
* ``flask/`` - a Python backend on **Flask** (WSGI), served with gunicorn. See
  ``flask/README.rst``.
* ``fastapi/`` - a Python backend on **FastAPI** (ASGI, async), served with
  uvicorn + uvloop. See ``fastapi/README.rst``.
* ``php/`` - a plain **PHP** backend (no framework, a single ``index.php`` front
  controller), served with the built-in server for the demo or php-fpm + nginx
  in production. See ``php/README.rst``.
* ``dotnet/`` - a **C# / ASP.NET Core** backend on **minimal APIs** (Kestrel),
  with zero NuGet dependencies. See ``dotnet/README.rst``.
* ``nodejs-express/`` - a **Node.js** backend on the **Express** framework, with
  Express as its only dependency. See ``nodejs-express/README.rst``.
* ``golang/`` - a **Go** backend on the standard ``net/http`` package, with zero
  third-party dependencies. See ``golang/README.rst``.
* ``java/`` - a **Java** backend on the **Spring Boot** framework (Spring MVC +
  embedded Tomcat). See ``java/README.rst``.

All of them are EXAMPLE code - clear, minimal references, not tuned backends.
Do not benchmark lunar with them; use ``lunar_backend_sim`` for performance
testing. Each README has a "Running it properly" section on how to put a real
server (and nginx) in front for production.
