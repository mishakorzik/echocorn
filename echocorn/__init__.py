"""
Echocorn - a fast, lightweight ASGI server with HTTP/1.1 and HTTP/2 support.

Public API::

    from echocorn import ASGIServer, ServerConfig

    server = ASGIServer(app, ServerConfig(host="0.0.0.0", port=8000))
    server.run() # or: await server.serve()

Embedding a configuration file::

    from echocorn import ASGIServer, load_settings

    settings = load_settings("echocorn.toml")
    ASGIServer(import_app(settings.app), settings.config).run()

The command line takes exactly one option, ``--config PATH``, which names the
configuration file; there is no environment variable and no other flag.
"""

from __future__ import annotations

from .config import ConfigError, ServerConfig, Settings, load_settings, proxy_target
from .proxy import ProxyApp
from .server import ASGIServer, import_app, main, resolve_app
from .utils import VERSION as __version__

__all__ = [
    "ASGIServer",
    "ConfigError",
    "ProxyApp",
    "ServerConfig",
    "Settings",
    "import_app",
    "load_settings",
    "main",
    "proxy_target",
    "resolve_app",
    "__version__",
]
