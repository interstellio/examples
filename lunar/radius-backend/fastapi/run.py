#!/usr/bin/env python3
"""Run the example RADIUS backend under uvicorn for a fast, concurrent demo.

The built-in server in ``app.py`` runs a single uvicorn worker - fine to read,
slow to demo. This script runs several uvicorn worker processes on the fast
uvloop event loop, so the many concurrent connections lunar opens to the
backend are served in parallel.

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
    "fastapi": "fastapi",
    "cryptography": "cryptography",
    "uvicorn": "uvicorn",
    "uvloop": "uvloop",
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

    # --nodebug quiets both this backend and uvicorn to errors only.
    nodebug = "--nodebug" in sys.argv[1:]
    env = os.environ.copy()
    if nodebug:
        env["RADIUS_BACKEND_NODEBUG"] = "1"

    # os.cpu_count() can return None on exotic platforms; fall back to 1.
    cores = os.cpu_count() or 1

    # A common starting point for workers is "2 x cores + 1". Each uvicorn
    # worker runs an async event loop (uvloop) that handles many concurrent
    # connections without threads.
    workers = cores * 2 + 1
    host, port = "127.0.0.1", "5555"

    # Run from this script's directory so "app:application" resolves.
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    print(
        f"Detected {cores} cores - starting RADIUS backend: "
        f"{workers} uvicorn workers (uvloop) on {host}:{port}"
    )

    # uvicorn from the active virtualenv (same directory as this python).
    uvicorn = os.path.join(os.path.dirname(sys.executable), "uvicorn")
    argv = [
        uvicorn,
        "--workers", str(workers),
        "--loop", "uvloop",
        "--host", host,
        "--port", port,
        "--timeout-graceful-shutdown", "5",
    ]
    if nodebug:
        argv += ["--log-level", "error"]
    argv.append("app:application")

    # Run uvicorn in its own process group (start_new_session) so Ctrl-C is
    # delivered to us, not straight to uvicorn. That lets us guarantee the
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
