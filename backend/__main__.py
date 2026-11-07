"""``python -m backend``: run the API under uvicorn with the hardened settings.

Exit codes are in ``backend.core.exit_codes``: 77 refused to run as root, 78 invalid configuration, 3 startup failed
(the application, or binding the port). A service manager can tell a permanent refusal from a crash.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping

import uvicorn

from backend.api.app import create_app
from backend.core.config import ConfigError, load_settings
from backend.core.exit_codes import EXIT_CONFIG, EXIT_REFUSED_ROOT, EXIT_STARTUP_FAILED
from backend.core.logging import configure_logging


def _running_as_root() -> bool:
    geteuid = getattr(os, "geteuid", None)  # absent on Windows development hosts
    return geteuid is not None and geteuid() == 0


def main(environ: Mapping[str, str] | None = None) -> int:
    if _running_as_root():
        sys.stderr.write("pai-backend: refusing to run as root\n")  # deliberately no override
        return EXIT_REFUSED_ROOT
    try:
        settings = load_settings(os.environ if environ is None else environ)
    except ConfigError as exc:
        sys.stderr.write(f"pai-backend: {exc}\n")
        return EXIT_CONFIG

    configure_logging(settings.log_level)
    config = uvicorn.Config(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        workers=1,
        reload=False,
        lifespan="on",  # a failed startup must abort, never fall back to serving without it
        ws="none",  # the API has no WebSocket routes
        server_header=False,
        proxy_headers=False,  # nothing sits in front of this service; never trust forwarded headers
        access_log=False,  # request lines can carry secrets in query strings
        log_config=None,  # uvicorn's records flow through the redacting JSON handler instead
        log_level=settings.log_level,
    )
    # Hold the port before the application starts. Startup publishes the bearer token, and that token must only
    # ever exist for an instance that owns the listener: uvicorn binds after the lifespan startup, so letting it
    # bind would publish a token even when another process already holds the port. Connections made while
    # startup runs wait in the backlog and are answered once the application is up (the guard refuses every
    # request until the token is installed).
    try:
        listener = config.bind_socket()
    except SystemExit:  # bind_socket has logged the reason; the status it exits with differs between versions
        return EXIT_STARTUP_FAILED
    listener.listen(config.backlog)
    server = uvicorn.Server(config)
    server.run(sockets=[listener])
    return 0 if server.started else EXIT_STARTUP_FAILED  # as uvicorn.run: a failed startup is not a clean exit


if __name__ == "__main__":
    sys.exit(main())
