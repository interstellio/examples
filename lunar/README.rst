==============
Lunar Examples
==============

Examples for **Lunar**, the Interstellio network services engine. Lunar covers
a lot of ground - today its RADIUS server, and over time more protocols such as
SNMP, DNS and others - and this section will grow to include examples for its
many features. For now it focuses on its RADIUS server and the backends that
drive it.

Everything here is EXAMPLE code: written for clarity, meant to be understood and
used as a starting point, not as production-tuned software. Each example is
self-contained and ships with its own README.


What's inside
=============

* ``radius-backend/`` - miniature backends that implement the lunar backend API
  (the HTTP/JSON API lunar calls to authenticate users, record accounting and
  drive dynamic authorization). Several languages and frameworks are provided -
  Falcon, async Falcon, Flask, FastAPI, PHP, ASP.NET Core, Node.js/Express, Go
  and Spring Boot - each behaving identically so you can compare them side by
  side. See ``radius-backend/README.rst``.

More Lunar examples will be added over time.


Licence
=======

Copyright (c) Interstellio IO (PTY) LTD.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, for any purpose, including commercial use.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.