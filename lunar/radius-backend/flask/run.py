#!/usr/bin/env python3
"""Run the example RADIUS backend under gunicorn for a fast, concurrent demo.

The built-in server in ``app.py`` is single-process and handles one request at
a time - fine to read, slow to demo. gunicorn runs several worker processes,
each with several threads, so the many concurrent connections lunar opens to
the backend are served in parallel.

This script detects how many processors the box has and sizes the worker pool
accordingly - you do not configure anything, just run it::

    ./run.py

Pass ``--nodebug`` to quiet the logs down to errors and critical only::

    ./run.py --nodebug

It listens on ``127.0.0.1:5555``.
"""

import importlib.util
import os
import signal
import subprocess
import sys

# The Python packages this backend needs, mapped to the module you import.
# Every one is listed in requirements.txt.
REQUIRED = {
    "flask": "flask",
    "cryptography": "cryptography",
    "gunicorn": "gunicorn",
}


def check_dependencies():
    """Stop with a friendly message if any required package is missing."""
    missing = [
        package
        for package, module in REQUIRED.items()
        if importlib.util.find_spec(module) is None
    ]
    if not missing:
        return

    print("Cannot start: the following dependencies are missing:",
          file=sys.stderr)
    for package in missing:
        print(f"  - {package}", file=sys.stderr)
    print(file=sys.stderr)
    print(
        "Please install them first. We recommend a virtual environment:\n"
        "\n"
        "    python -m venv .venv\n"
        "    source .venv/bin/activate\n"
        "    pip install -r requirements.txt\n"
        "\n"
        "See README.rst for the full walk-through.",
        file=sys.stderr,
    )
    sys.exit(1)


def main():
    check_dependencies()

    # --nodebug quiets both this backend and gunicorn to errors only.
    nodebug = "--nodebug" in sys.argv[1:]
    env = os.environ.copy()
    if nodebug:
        env["RADIUS_BACKEND_NODEBUG"] = "1"

    # os.cpu_count() can return None on exotic platforms; fall back to 1.
    cores = os.cpu_count() or 1

    # A common starting point for workers is "2 x cores + 1". Threads add cheap
    # concurrency on top, which suits this mostly I/O-bound JSON backend.
    workers = cores * 2 + 1
    threads = 8
    bind = "127.0.0.1:5555"

    # Run from this script's directory so "app:application" resolves.
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    print(
        f"Detected {cores} cores - starting RADIUS backend: "
        f"{workers} gunicorn workers x {threads} threads on {bind}"
    )

    # gunicorn from the active virtualenv (same directory as this python).
    gunicorn = os.path.join(os.path.dirname(sys.executable), "gunicorn")
    argv = [
        gunicorn,
        "--workers", str(workers),
        "--threads", str(threads),
        "--worker-class", "gthread",
        "--graceful-timeout", "5",
        "--bind", bind,
    ]
    if nodebug:
        argv += ["--log-level", "error"]
    argv.append("app:application")

    # Run gunicorn in its own process group (start_new_session) so Ctrl-C is
    # delivered to us, not straight to gunicorn. That lets us guarantee the
    # whole server is torn down even if a worker is wedged and ignores the
    # first, polite signal.
    process = subprocess.Popen(argv, start_new_session=True, env=env)

    # Treat SIGTERM (e.g. from systemd) exactly like Ctrl-C: raising
    # KeyboardInterrupt drops us into the teardown below.
    def on_sigterm(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_sigterm)
    try:
        process.wait()
    except KeyboardInterrupt:
        pass
    finally:
        if process.poll() is None:
            # Ask the whole group to stop, then force-kill anything still
            # alive after the grace period so run.py can never hang.
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


if __name__ == "__main__":
    main()
