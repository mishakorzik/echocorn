"""
Runtime configuration for the Echocorn ASGI server.

The server is configured entirely by a TOML file, read with the standard
library ``tomllib`` and pointed at by ``echocorn --config PATH``.  Settings are
grouped into sections - ``[server]``, ``[http1]``, ``[http2]``,
``[websocket]``, ``[logging]`` and ``[tls]`` - so each protocol can be turned
on or off on its own.

Every key is validated while the file is loaded, so a typo or a wrong type is
reported with the file name and the offending key instead of silently changing
how the server behaves.
"""

from __future__ import annotations

import difflib
import ipaddress
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, NamedTuple, Optional, Tuple

__all__ = [
    "ServerConfig",
    "ConfigError",
    "Settings",
    "SCHEMA",
    "LOG_LEVELS",
    "load_settings",
    "proxy_target",
]

#: ``app`` names either an ASGI application (``module:attribute``) or a local
#: server to proxy to (``127.0.0.1:5000``).  Only a loopback, private or
#: link-local host matches, so a configuration file can never point the server
#: at a public machine and become an open proxy.
_PROXY_TARGET_RE = re.compile(r"^(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+):(?P<port>[0-9]{1,5})$")

#: Canonical log levels, most severe first.  These five names are the only ones
#: the server ever prints; ``WARNING`` and ``CRITICAL`` are accepted in the
#: configuration file as aliases and stored under their short name.
LOG_LEVELS = ("CRIT", "ERROR", "WARN", "INFO", "DEBUG")
_LEVEL_ALIASES = {"WARNING": "WARN", "CRITICAL": "CRIT"}

#: ``section -> key -> (kind, ServerConfig field)``.  This table is the single
#: source of truth for what the configuration file may contain.
SCHEMA: Mapping[str, Mapping[str, Tuple[str, str]]] = {
    "server": {
        "host": ("str", "host"),
        "port": ("int", "port"),
        "workers": ("int", "workers"),
        "request_timeout": ("float", "request_timeout"),
        "keep_alive_timeout": ("float", "keep_alive_timeout"),
        "graceful_timeout": ("float", "graceful_timeout"),
        "max_connections": ("int", "max_connections"),
        "backlog": ("int", "backlog"),
        "max_header_size": ("int", "max_header_size"),
        "max_header_count": ("int", "max_header_count"),
        "max_request_size": ("int", "max_request_size"),
        "bind_domain": ("str", "bind_domain"),
        "compression": ("bool", "compression"),
        "safe_headers": ("bool", "safe_headers"),
    },
    "http1": {
        "enabled": ("bool", "http1_enabled"),
    },
    "http2": {
        "enabled": ("bool", "http2_enabled"),
        "max_concurrent_streams": ("int", "h2_max_concurrent_streams"),
        "initial_window_size": ("int", "h2_initial_window_size"),
        "max_frame_size": ("int", "h2_max_frame_size"),
        "max_header_list_size": ("int", "h2_max_header_list_size"),
    },
    "websocket": {
        "enabled": ("bool", "websockets"),
        "max_message_size": ("int", "max_websocket_message_size"),
    },
    "logging": {
        "level": ("level", "log_level"),
        "access": ("bool", "access_log"),
        "color": ("bool", "log_color"),
    },
    "tls": {
        "certfile": ("path", "certfile"),
        "keyfile": ("path", "keyfile"),
    },
    "redirect": {
        "enabled": ("bool", "redirect_enabled"),
        "host": ("str", "redirect_host"),
        "port": ("int", "redirect_port"),
        "status": ("int", "redirect_status"),
    },
}


class ConfigError(Exception):
    """The configuration file is missing, unreadable or invalid."""


class Settings(NamedTuple):
    """A loaded configuration file: the settings, the app and where it came from."""

    config: ServerConfig
    app: str
    path: Path


@dataclass
class ServerConfig:
    """
    Every tunable knob of :class:`echocorn.server.ASGIServer`.

    The defaults are production oriented: they keep a misbehaving or malicious
    peer from holding connections open, uploading without limit or forcing the
    server to buffer memory, without changing how a well behaved application
    behaves.
    """

    # Application and binding.
    app: Optional[Any] = None
    host: str = ""
    port: int = 8000

    # Process model.
    workers: int = 1

    # Protocol switches.  Each protocol can be served on its own; the server
    # advertises only what is enabled through ALPN.
    http1_enabled: bool = True
    """Serve HTTP/1.1 (RFC 9110, RFC 9112)."""

    http2_enabled: bool = True
    """Serve HTTP/2 (RFC 9113) over TLS with ALPN, or ``h2c`` with prior knowledge."""

    websockets: bool = True
    """Accept WebSocket upgrades (RFC 6455) over HTTP/1.1."""

    # TLS.
    certfile: Optional[str] = None
    keyfile: Optional[str] = None

    # HTTP to HTTPS redirect. The redirect listener is a separate, plaintext
    # socket that answers every request with a redirect to the TLS origin; it
    # needs TLS and is served by exactly one worker (the primary one), because
    # it is cheap and not on the critical path.
    redirect_enabled: bool = False
    """Answer plaintext requests on ``redirect_port`` with a redirect to HTTPS."""

    redirect_host: str = ""
    """Address of the redirect listener; empty follows ``host``."""

    redirect_port: int = 80
    """Port of the redirect listener. 0 lets the OS choose one."""

    redirect_status: int = 308
    """Redirect status: 308 (default), 301, 302 or 307."""

    # Features.
    compression: bool = False
    """Enable transparent gzip/deflate response compression."""

    safe_headers: bool = False
    """Add a conservative set of security response headers."""

    bind_domain: str = ""
    """When set, requests whose Host/:authority does not match are answered with 421 Misdirected Request."""

    # Limits.
    max_header_size: int = 16 * 1024
    """Maximum size of the whole request head (HTTP/1.1) or header list (HTTP/2)."""

    max_header_count: int = 128
    """Maximum number of header fields accepted on a single request."""

    max_request_size: int = 0
    """Maximum request body size in bytes. 0 disables the limit."""

    max_websocket_message_size: int = 4 * 1024 * 1024
    """Maximum size of one WebSocket message, across all its fragments."""

    max_connections: int = 0
    """Maximum number of simultaneous connections. 0 disables the limit."""

    backlog: int = 2048
    """listen(2) backlog for the listening socket."""

    # Timeouts in seconds.
    request_timeout: float = 10.0
    """
    The single timeout that guards one request, in every phase.

    * Waiting for the request: counted from the moment the connection is
      accepted, TLS handshake included, until the head and body have been
      received. Trickling bytes does not extend it.
    * Producing the response: restarted every time the server manages to write
      bytes, so a stalled application or a client that stopped reading is
      dropped while a streaming response may run for as long as it keeps
      flowing.

    On expiry the connection is reset (RST), never left half answered. 0
    disables the timeout, which is only advisable behind another timeout.
    """

    keep_alive_timeout: float = 5.0
    """Idle time between two requests on a keep-alive connection."""

    graceful_timeout: float = 10.0
    """How long in-flight requests may take during shutdown."""

    # HTTP/2 tuning.
    h2_max_concurrent_streams: int = 100
    """SETTINGS_MAX_CONCURRENT_STREAMS advertised to clients."""

    h2_initial_window_size: int = 65535
    """SETTINGS_INITIAL_WINDOW_SIZE advertised to clients."""

    h2_max_frame_size: int = 16384
    """SETTINGS_MAX_FRAME_SIZE advertised to clients."""

    h2_max_header_list_size: int = 16 * 1024
    """SETTINGS_MAX_HEADER_LIST_SIZE advertised to clients.

    Also caps the HPACK decoder, which protects against header list bombs."""

    # Logging.
    log_level: str = "INFO"
    """One of :data:`LOG_LEVELS`."""

    access_log: bool = True
    """Write one line per request (or per WebSocket session)."""

    log_color: bool = False
    """Colour the level of every log line with ANSI escapes (for a terminal)."""

    def __post_init__(self) -> None:
        if not 0 <= self.port <= 65535:
            raise ValueError("port must be within 0..65535")
        if self.workers < 1:
            raise ValueError("workers must be at least 1")
        if self.backlog < 1:
            raise ValueError("backlog must be at least 1")
        level = _LEVEL_ALIASES.get(self.log_level.upper(), self.log_level.upper())
        if level not in LOG_LEVELS:
            raise ValueError("log_level must be one of %s" % ", ".join(LOG_LEVELS))
        self.log_level = level
        if not (self.http1_enabled or self.http2_enabled):
            raise ValueError("at least one of http1.enabled and http2.enabled must be true")
        if self.websockets and not self.http1_enabled:
            # WebSockets are only carried over HTTP/1.1 here, so the toggle
            # would be dead configuration: refuse it instead.
            raise ValueError("websocket.enabled requires http1.enabled")
        if self.keep_alive_timeout < 0:
            raise ValueError("keep_alive_timeout must not be negative")
        if self.graceful_timeout < 0:
            raise ValueError("graceful_timeout must not be negative")
        if self.h2_max_concurrent_streams < 1:
            raise ValueError("h2_max_concurrent_streams must be positive")
        if self.h2_max_header_list_size < 256:
            raise ValueError("h2_max_header_list_size must be at least 256 bytes")
        if self.max_header_size < 256:
            raise ValueError("max_header_size must be at least 256 bytes")
        if self.max_header_count < 1:
            raise ValueError("max_header_count must be positive")
        if self.max_request_size < 0:
            raise ValueError("max_request_size must not be negative")
        if self.max_websocket_message_size < 125:
            raise ValueError("max_websocket_message_size must be at least 125")
        if self.max_connections < 0:
            raise ValueError("max_connections must not be negative")
        if self.request_timeout < 0:
            raise ValueError("request_timeout must not be negative")
        if not 0 <= self.redirect_port <= 65535:
            raise ValueError("redirect_port must be within 0..65535")
        if self.redirect_status not in (301, 302, 307, 308):
            raise ValueError("redirect_status must be 301, 302, 307 or 308")
        if self.redirect_enabled and not (self.certfile and self.keyfile):
            raise ValueError("redirect.enabled requires tls.certfile and tls.keyfile")
        if self.redirect_enabled and self.redirect_port and self.redirect_port == self.port:
            raise ValueError("redirect.port must differ from server.port")
        if not 16384 <= self.h2_max_frame_size <= 16777215:
            raise ValueError("h2_max_frame_size must be within 16384..16777215")
        if not 0 <= self.h2_initial_window_size <= 2**31 - 1:
            raise ValueError("h2_initial_window_size out of range")


def _is_local(host: str) -> bool:
    """
    True when ``host`` is this machine or a machine on a local network.

    ``localhost`` and every private, loopback or link-local address counts
    (``127.0.0.0/8``, ``10.0.0.0/8``, ``172.16.0.0/12``, ``192.168.0.0/16``,
    ``169.254.0.0/16``, ``::1``, ``fc00::/7``, ``fe80::/10``).  A public
    address, and a name that is not an address at all, does not: a
    configuration file must not be able to turn the server into an open proxy.
    """
    if host.lower() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def proxy_target(value: str) -> Optional[Tuple[str, int]]:
    """
    Return ``(host, port)`` when ``app`` names a local server to proxy to.

    ``app = "127.0.0.1:5000"`` puts the server in front of a program that is
    already listening somewhere on this machine or on a local network - loopback
    like ``::1``, or a private address like ``192.168.0.105:5000``.  Only such a
    local address is accepted: a configuration file must not be able to turn the
    server into an open proxy, so anything else has to name an ASGI application
    as ``module:attribute``.  ``None`` means the value is not a ``host:port``
    pair at all; a malformed or non-local one raises :class:`ValueError`.
    """
    match = _PROXY_TARGET_RE.match(value.strip())
    if match is None:
        return None
    host = match.group("host")
    bare = host[1:-1] if host.startswith("[") else host
    if not _is_local(bare):
        raise ValueError(
            "only a local address (loopback or a private network) can be proxied, not %r"
            % bare
        )
    port = int(match.group("port"))
    if not 1 <= port <= 65535:
        raise ValueError("the proxied port must be within 1..65535")
    return bare, port


def _suggest(name: str, section: Optional[str] = None) -> str:
    """
    Return a short "did you mean" hint for an unknown key.

    The closest key of the same section wins; otherwise the name is looked for
    in every section (so a flat, pre-sections file is pointed at ``server.port``
    rather than left to guess), and finally among the section names.
    """
    if section is not None:
        matches = difflib.get_close_matches(
            name, list(SCHEMA[section]), n=3, cutoff=0.6
        )
        if matches:
            return "; did you mean %s?" % ", ".join(matches)

    for candidate, keys in SCHEMA.items():
        hits = difflib.get_close_matches(name, list(keys), n=3, cutoff=0.6)
        if hits:
            return "; did you mean %s?" % ", ".join(
                "%s.%s" % (candidate, key) for key in hits
            )

    sections = difflib.get_close_matches(name, list(SCHEMA), n=3, cutoff=0.6)
    if sections:
        return "; did you mean %s?" % ", ".join(sections)
    return ""


def _check(name: str, kind: str, value: Any, source: Path) -> Any:
    """Validate one value, returning the value to store in the config."""

    def reject(expected: str) -> "ConfigError":
        return ConfigError("%s: %s must be %s, got %s" % (source, name, expected, type(value).__name__))

    if kind == "bool":
        if not isinstance(value, bool):
            raise reject("true or false")
        return value
    if kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise reject("an integer")
        return value
    if kind == "float":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise reject("a number")
        return float(value)
    if kind == "level":
        if not isinstance(value, str):
            raise reject("a string")
        level = _LEVEL_ALIASES.get(value.strip().upper(), value.strip().upper())
        if level not in LOG_LEVELS:
            raise ConfigError("%s: %s must be one of %s" % (source, name, ", ".join(LOG_LEVELS)))
        return level
    if kind == "path":
        if not isinstance(value, str):
            raise reject("a string path")
        if not value:
            return None
        candidate = Path(value)
        if not candidate.is_absolute():
            # Relative paths are read from where the configuration lives, which
            # keeps a deployment directory self contained.
            candidate = source.parent / candidate
        return str(candidate)
    if not isinstance(value, str):
        raise reject("a string")
    return value


def _settings_from_mapping(data: Dict[str, Any], source: Path) -> Settings:
    """Turn a parsed TOML document into validated settings."""
    values: Dict[str, Any] = {}
    app: Optional[Any] = None

    for name, section in data.items():
        if name == "app":
            app = section
            continue
        if name not in SCHEMA:
            raise ConfigError("%s: unknown setting %r%s" % (source, name, _suggest(name)))
        if not isinstance(section, dict):
            raise ConfigError("%s: [%s] must be a table of settings, got %s" % (source, name, type(section).__name__))
        for key, value in section.items():
            entry = SCHEMA[name].get(key)
            if entry is None:
                qualified = "%s.%s" % (name, key)
                raise ConfigError("%s: unknown setting %r%s" % (source, qualified, _suggest(key, name)))
            kind, field = entry
            values[field] = _check("%s.%s" % (name, key), kind, value, source)

    if app is None:
        raise ConfigError("%s: an 'app' key is required, for example app = \"app:app\"" % source)
    if not isinstance(app, str):
        raise ConfigError("%s: app must be a string" % source)
    app = app.strip()
    try:
        target = proxy_target(app)
    except ValueError as exc:
        raise ConfigError("%s: app %s" % (source, exc)) from None
    if target is None:
        module_name, _, attribute = app.partition(":")
        if not module_name or not attribute:
            raise ConfigError(
                "%s: app must name an ASGI application as \"module:callable\" or a "
                "local server to proxy to as \"host:port\" (127.0.0.1:5000)" % source
            )

    if bool(values.get("certfile")) != bool(values.get("keyfile")):
        raise ConfigError("%s: tls.certfile and tls.keyfile must be set together or left out together" % source)

    try:
        config = ServerConfig(**values)
    except ValueError as exc:
        raise ConfigError("%s: %s" % (source, exc)) from None
    return Settings(config=config, app=app, path=source)


def load_settings(path: Any) -> Settings:
    """
    Read, parse and validate the configuration file at ``path``.

    Anything wrong with the file - missing, unreadable, invalid TOML, unknown
    key, wrong type or an out of range value - is reported as a
    :class:`ConfigError` naming the file it came from.
    """
    source = Path(path)
    if source.is_dir():
        # Checked first: platforms disagree on which error opening a directory.
        raise ConfigError("%s is a directory, not a configuration file" % source)
    try:
        with open(source, "rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        raise ConfigError("no configuration file at %s" % source) from None
    except PermissionError:
        raise ConfigError("cannot read %s: permission denied" % source) from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError("%s is not valid TOML: %s" % (source, exc)) from None
    except OSError as exc:
        raise ConfigError("cannot read %s: %s" % (source, exc)) from None

    if not isinstance(data, dict):  # pragma: no cover - tomllib always returns a dict
        raise ConfigError("%s: the configuration must be a table of settings" % source)
    return _settings_from_mapping(data, source)
