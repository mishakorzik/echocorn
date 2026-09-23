"""Server bootstrap: protocol dispatch, TLS, lifespan, workers and the CLI."""

from __future__ import annotations

import asyncio
import logging
import multiprocessing
import os
import signal
import socket
import ssl
import sys
import time
from collections.abc import Callable
from multiprocessing import Process
from pathlib import Path

try:
    import uvloop
except ImportError:
    uvloop = None

from . import utils
from .config import ConfigError, ServerConfig, load_settings, proxy_target
from .http1 import CONNECTION_PREFACE, HTTP11Handler
from .proxy import ProxyApp
from .ratelimit import RateLimiter, SharedCounters
from .redirect import RedirectProtocol

# hyper-h2 is an optional dependency: without it the server speaks HTTP/1.1
# only and never offers "h2" through ALPN.
try:
    from .http2 import HTTP2Handler

    H2_AVAILABLE = True
except ImportError:
    HTTP2Handler = None
    H2_AVAILABLE = False

__all__ = [
    "ASGIServer",
    "ColoredFormatter",
    "ConnectionProtocol",
    "LOG_COLORS",
    "ProxyApp",
    "WorkerGroup",
    "format_address",
    "main",
    "import_app",
    "resolve_app",
]

logger = logging.getLogger("echocorn")

#: Startup and shutdown lines. They are pinned to INFO, so "the server is up"
#: stays visible even when the configured level mutes everything else.
banner = logging.getLogger("echocorn.lifecycle")

#: The five level names the server uses, and what they mean to ``logging``.
LEVELS = {
    "CRIT": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARN": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}

#: Signals that stop the server. On Windows Ctrl+Break is the only console
#: event a program can raise for itself, so it is handled as well.
SIGNALS = (signal.SIGINT, signal.SIGTERM)
if hasattr(signal, "SIGBREAK"):
    SIGNALS += (signal.SIGBREAK,)

#: The one line format the server uses. Only the level token and the
#: timestamp are ever colourised, so the readable part of a line does not
#: change when colour is switched on for a terminal. The escape has to sit
#: outside the brackets for that to hold: it is written around the whole
#: ``[LEVEL]``, never in the middle of it, so ``[INFO ]`` stays on the line.
LOG_FORMAT = "%(asctime)s [%(levelname)-5s] %(process)7d: %(message)s"
LOG_COLOR_FORMAT = "\033[90m%(asctime)s \033[0m[%(levelcolor)s%(levelname)-5s\033[0m] %(process)7d: %(message)s"

#: What each of the five level names looks like with colour enabled.
LOG_COLORS = {
    "DEBUG": "\033[94m",
    "INFO": "\033[34m",
    "WARN": "\033[93m",
    "ERROR": "\033[91m",
    "CRIT": "\033[95m",
}

#: How long a worker may take to bind its socket before startup fails.
WORKER_STARTUP_TIMEOUT = 10.0


class ColoredFormatter(logging.Formatter):
    """
    Colour the timestamp and the level of every line with ANSI escapes.

    The level is looked up by the short name the server installs with
    ``logging.addLevelName`` (``WARN``, ``CRIT``), so a record from a third
    party library that propagates to the same handler stays legible: a level
    without a colour is simply written plain.
    """

    def format(self, record: logging.LogRecord) -> str:
        record.levelcolor = LOG_COLORS.get(record.levelname.upper(), "")
        return super().format(record)


def format_address(sock: socket.socket) -> str:
    """
    Format a bound socket the way the "Serving HTTP on" line shows it.

    A wildcard host is left out (``Serving HTTPS on :8000``), which is what a
    server listening on every interface would print.
    """
    try:
        address = sock.getsockname()
    except OSError:
        return ""
    host, port = address[0], address[1]
    if host in ("", "0.0.0.0", "::"):
        return ":%d" % port
    if ":" in host:
        host = "[%s]" % host  # an explicit IPv6 address needs brackets
    return "%s:%d" % (host, port)


async def _watch_supervisor(stop_event: object, supervisor: Callable[[], bool] | None, stop: asyncio.Event) -> None:
    """
    Stop a worker when its supervisor asks - or disappears.

    A ``multiprocessing.Event`` cannot be awaited and a dead parent cannot be
    signalled, so both are polled: one cheap timer per worker, and only when
    the server was started by a supervisor. Watching the parent too is what
    keeps a killed master from leaving workers behind.
    """
    while True:
        if stop_event is not None and stop_event.is_set():
            break
        if supervisor is not None and not supervisor():
            logger.warning("The process that started this worker is gone; stopping")
            break
        await asyncio.sleep(0.25)
    stop.set()


def _worker_supervisor() -> Callable[[], bool] | None:
    """A liveness check for the process that started this worker, if any."""
    parent = multiprocessing.parent_process()
    if parent is None:
        return None
    return parent.is_alive


def resolve_app(value: str, config: ServerConfig) -> Callable:
    """
    Return the ASGI application an ``app`` setting names.

    ``module:attribute`` is imported; a local ``host:port`` value makes the
    server a reverse proxy in front of a program that is already listening
    there (see :mod:`echocorn.proxy`), so ``app = "127.0.0.1:5000"`` - or a
    private address like ``10.0.0.16:8080`` - is all it takes to put TLS,
    HTTP/2, limits and the redirect in front of it.
    """
    target = proxy_target(value)
    if target is None:
        return import_app(value)
    return ProxyApp(target[0], target[1], config)


async def _redirect_only_app(scope: object, receive: object, send: object) -> None:  # pragma: no cover - never called
    """Placeholder of the worker that serves only the HTTP to HTTPS redirect."""
    raise RuntimeError("this worker serves the redirect, not the application")


def import_app(path: str) -> Callable:
    """Import ``module:attribute`` and return the referenced ASGI application."""
    if not isinstance(path, str) or ":" not in path:
        raise ValueError("application must be given as module:callable")
    module_name, attribute = path.split(":", 1)
    if not module_name or not attribute:
        raise ValueError("application must be given as module:callable")
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    module = __import__(module_name, fromlist=[attribute])
    try:
        return getattr(module, attribute)
    except AttributeError as exc:
        raise ImportError("%s has no attribute %r" % (module_name, attribute)) from exc


class ConnectionProtocol(asyncio.Protocol):
    """
    Dispatches each connection to the HTTP/1.1 or HTTP/2 handler.

    The protocol is picked from the TLS ALPN result when available. For
    cleartext connections the HTTP/2 client preface (``h2c`` with prior
    knowledge, RFC 9113 section 3.2) is sniffed from the first bytes; anything
    else is treated as HTTP/1.1.
    """

    def __init__(self, app: Callable, config: ServerConfig, connections: set["ConnectionProtocol"], logger_: logging.Logger, on_release: Callable[[], None] | None = None, rate_limiter: RateLimiter | None = None) -> None:
        self.app = app
        self.config = config
        self.logger = logger_
        self._connections = connections
        self._on_release = on_release
        self.rate_limiter = rate_limiter
        self._released = False
        self._connections.add(self)
        self.transport: asyncio.Transport | None = None
        self.peername: object = None
        self.server_addr: object = None
        self.ssl_object: object = None
        self._handler: object = None
        self._pending: bytearray | None = None
        self._mode = "h1"
        self._decision_timer: asyncio.TimerHandle | None = None
        self._closed = False

    # lifecycle
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport
        self.peername = transport.get_extra_info("peername")
        sock = transport.get_extra_info("socket")
        try:
            self.server_addr = sock.getsockname() if sock is not None else None
        except Exception:
            self.server_addr = None
        self.ssl_object = transport.get_extra_info("ssl_object")
        self._tune_socket(sock)

        limit = self.config.max_connections
        if limit and len(self._connections) > limit:
            self.logger.warning("Rejecting connection from %s: connection limit of %d reached", self.peername, limit)
            self._reject_over_limit()
            return

        if self.ssl_object is not None:
            try:
                alpn = self.ssl_object.selected_alpn_protocol()
            except Exception:
                alpn = None
            if alpn == "h2":
                self._install_http2()
            else:
                self._install_http1()
        else:
            self._pending = bytearray()
            # The clock also covers the phase before the first byte arrives, so
            # a peer that connects and stays silent is reset, not kept around.
            # Only an explicit 0 for both timeouts turns this off.
            delay = self.config.request_timeout or self.config.keep_alive_timeout
            if delay > 0:
                loop = asyncio.get_running_loop()
                self._decision_timer = loop.call_later(delay, self._decide_timeout)

    def _decide_timeout(self) -> None:
        self._decision_timer = None
        if self._handler is None:
            self.logger.debug("Resetting a connection that never sent a request")
            self._abort()

    def _cancel_decision_timer(self) -> None:
        if self._decision_timer is not None:
            self._decision_timer.cancel()
            self._decision_timer = None

    def _install_http1(self) -> None:
        if not self.config.http1_enabled:
            self._reject_unsupported("HTTP/1.1 is disabled on this server")
            return
        self._handler = HTTP11Handler(
            self.app,
            self.config,
            self.transport,
            self.peername,
            self.server_addr,
            self.ssl_object,
            self.logger,
            on_close=self._release,
            rate_limiter=self.rate_limiter,
        )
        self._handler.connection_made()

    def _install_http2(self) -> None:
        if not self.config.http2_enabled:
            self._reject_unsupported("HTTP/2 is disabled on this server")
            return
        if not H2_AVAILABLE:
            self._reject_unsupported("HTTP/2 support is not installed")
            return
        self._handler = HTTP2Handler(
            self.app,
            self.config,
            self.transport,
            self.peername,
            self.server_addr,
            self.ssl_object,
            self.logger,
            on_close=self._release,
            rate_limiter=self.rate_limiter,
        )
        self._handler.connection_made()

    def _release(self) -> None:
        """Forget the connection once, so shutdown can wait for it to go."""
        if self._released:
            return
        self._released = True
        self._connections.discard(self)
        if self._on_release is not None:
            self._on_release()

    def _close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._cancel_decision_timer()
        try:
            if self.transport is not None:
                self.transport.close()
        except Exception:
            pass
        self._release()

    @staticmethod
    def _tune_socket(sock: object) -> None:
        """Latency and liveness options for an accepted socket."""
        utils.tune_socket(sock)

    def _reject_over_limit(self) -> None:
        """Answer with a minimal 503 and close: the limit was reached."""
        if self._closed:
            return
        self._closed = True
        self._cancel_decision_timer()
        body = b"Service Unavailable\n"
        head = (
            b"HTTP/1.1 503 Service Unavailable\r\n"
            b"content-type: text/plain; charset=utf-8\r\n"
            b"content-length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"connection: close\r\n\r\n"
        )
        try:
            if self.transport is not None:
                self.transport.write(head + body)
                self.transport.close()
        except Exception:  # pragma: no cover - defensive
            pass
        self._release()

    def _reject_unsupported(self, reason: str) -> None:
        """
        Answer with a minimal 505 when the protocol is not served.

        This runs before a single byte has been parsed, so the answer is
        written as HTTP/1.1: every client understands it, and the connection is
        closed immediately afterwards.
        """
        if self._closed:
            return
        self._closed = True
        self._cancel_decision_timer()
        body = ("505 HTTP Version Not Supported\n%s\n" % reason).encode("latin-1")
        head = (
            b"HTTP/1.1 505 HTTP Version Not Supported\r\n"
            b"content-type: text/plain; charset=utf-8\r\n"
            b"content-length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"connection: close\r\n"
            b"date: " + utils.format_http_date().encode("latin-1") + b"\r\n"
            b"server: " + utils.SERVER_HEADER.encode("latin-1") + b"\r\n\r\n"
        )
        try:
            if self.transport is not None:
                self.transport.write(head + body)
                self.transport.close()
        except Exception:  # pragma: no cover - defensive
            pass
        self._release()

    def _abort(self) -> None:
        """Drop the connection with a TCP reset, without a graceful close."""
        if self._closed:
            return
        self._closed = True
        self._cancel_decision_timer()
        if self.transport is not None:
            utils.force_reset(self.transport)
        self._release()

    def abort(self) -> None:
        """Force the connection closed (used during shutdown)."""
        self._abort()

    # data
    def data_received(self, data: bytes) -> None:
        if self._closed:
            # A connection that was refused (over the limit, or speaking a
            # protocol this server does not serve) is gone; bytes that were
            # already in flight must not reach an application.
            return
        if self._handler is not None:
            self._handler.data_received(data)
            return
        if self._pending is None:  # pragma: no cover - defensive
            self._install_http1()
            self._handler.data_received(data)
            return
        self._pending.extend(data)
        if not self._decide_cleartext():
            return
        self._cancel_decision_timer()
        # The buffer is handed over as it is, so the first request of a
        # connection is not copied a second time; hyper-h2 is the one caller
        # that wants ``bytes``.
        pending: object = self._pending
        self._pending = None
        if self._mode == "h2":
            self._install_http2()
            self._handler.data_received(bytes(pending))
        else:
            self._install_http1()
            self._handler.data_received(pending)

    def _decide_cleartext(self) -> bool:
        buffer = self._pending
        assert buffer is not None
        if len(buffer) >= len(CONNECTION_PREFACE):
            self._mode = "h2" if buffer.startswith(CONNECTION_PREFACE) else "h1"
            return True
        if not CONNECTION_PREFACE.startswith(buffer):
            # Cannot possibly become the HTTP/2 preface any more.
            self._mode = "h1"
            return True
        # Everything else is a strict prefix of the preface, so waiting for
        # more input is always correct - including the prefixes that happen to
        # contain a CRLFCRLF ("PRI * HTTP/2.0\r\n\r\n" is 18 bytes of the 24).
        # Deciding "HTTP/1.1" on those would break an h2c connection whose
        # preface the network split into two segments, which is a real thing
        # that happens on a WAN (and the decision timer bounds the wait).
        return False

    # asyncio callbacks
    def eof_received(self) -> bool:
        if self._handler is not None:
            return bool(self._handler.eof_received())
        self._close()
        return False

    def pause_writing(self) -> None:
        if self._handler is not None:
            self._handler.pause_writing()

    def resume_writing(self) -> None:
        if self._handler is not None:
            self._handler.resume_writing()

    def connection_lost(self, exc: BaseException | None) -> None:
        self._closed = True
        self._cancel_decision_timer()
        if self._handler is not None:
            self._handler.connection_lost(exc)
        self._release()

    def is_idle(self) -> bool:
        """True when the connection has no request in flight."""
        return self._handler is None or bool(self._handler.is_idle())

    def shutdown(self) -> None:
        """Force the connection to close during server shutdown."""
        self._cancel_decision_timer()
        if self._handler is not None:
            self._handler.shutdown()
        else:
            self._close()


# Lifespan
async def run_lifespan(app: Callable, timeout: float = 10.0) -> object:
    """Drive the ASGI lifespan protocol and return a context with ``shutdown``."""
    receive_queue: asyncio.Queue = asyncio.Queue()
    started = asyncio.Event()
    stopped = asyncio.Event()
    failure: dict[str, BaseException | None] = {"error": None}

    async def receive() -> dict[str, object]:
        return await receive_queue.get()

    async def send(message: dict[str, object]) -> None:
        message_type = message.get("type")
        if message_type == "lifespan.startup.complete":
            started.set()
        elif message_type == "lifespan.startup.failed":
            failure["error"] = RuntimeError("lifespan.startup.failed: %s" % (message.get("message"),))
            started.set()
        elif message_type == "lifespan.shutdown.complete":
            stopped.set()
        elif message_type == "lifespan.shutdown.failed":
            failure["error"] = RuntimeError("lifespan.shutdown.failed: %s" % (message.get("message"),))
            stopped.set()

    task = asyncio.ensure_future(app({"type": "lifespan"}, receive, send))
    receive_queue.put_nowait({"type": "lifespan.startup"})

    # The wait also ends when the application returns or fails: a WSGI bridge
    # (asgiref) rejects a non-HTTP scope outright, and such an application must
    # not cost the full timeout at startup, nor again at shutdown.
    waiter = asyncio.ensure_future(started.wait())
    supported = True
    try:
        await asyncio.wait({waiter, task}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
    except asyncio.CancelledError:
        waiter.cancel()
        task.cancel()
        raise
    finally:
        waiter.cancel()

    if not started.is_set():
        supported = False
        if task.done():
            error = None if task.cancelled() else task.exception()
            if error is None:
                logger.info("Application does not support the lifespan protocol; continuing without it")
            else:
                logger.info("Application does not support the lifespan protocol (%r); continuing without it", error)
        else:
            logger.warning("Lifespan startup did not complete within %.1fs; continuing anyway", timeout)
    elif failure["error"] is not None:
        logger.error("Application failed during lifespan startup: %r", failure["error"])

    class LifespanContext:
        async def shutdown(self, shutdown_timeout: float = 10.0) -> None:
            try:
                if supported and not task.done():
                    receive_queue.put_nowait({"type": "lifespan.shutdown"})
                    try:
                        await asyncio.wait_for(stopped.wait(), timeout=shutdown_timeout)
                    except asyncio.TimeoutError:
                        logger.warning("Lifespan shutdown did not complete within %.1fs", shutdown_timeout,)
            finally:
                if not task.done():
                    task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

    return LifespanContext()


# Server
class ASGIServer:
    """
    An ASGI server speaking HTTP/1.1 and HTTP/2.

    ``ASGIServer(app, config)`` is the modern form; keyword arguments matching
    :class:`~echocorn.config.ServerConfig` fields are still accepted for
    backwards compatibility with the 1.0 API.

    ``shared_counters`` is the rate limit table every worker of this server
    counts into; ``None`` with a configuration that asks for sharing means this
    process creates one for itself (which is what an embedded server does), and
    ``create_shared = False`` refuses even that, for a worker whose master's
    table could not be mapped.
    """

    def __init__(self, app: Callable, config: ServerConfig | None = None, shared_counters: SharedCounters | None = None, create_shared: bool = True, **overrides: object) -> None:
        self.app = app
        self.config = config if config is not None else ServerConfig()
        self.config.app = app
        for key, value in overrides.items():
            if not hasattr(self.config, key):
                raise TypeError("unknown server option %r" % (key,))
            setattr(self.config, key, value)
        self.logger = logger
        self.ssl_context = self._create_ssl_context()
        if (shared_counters is None and create_shared and self.config.ratelimit_enabled and self.config.workers > 1):
            shared_counters = _open_shared_counters(self.config)
        if shared_counters is not None and not shared_counters.start():
            # The memory cannot be mapped in this process: count in it instead
            # of failing, and say so once.
            logger.warning("The shared rate limit table could not be mapped; this worker counts on its own")
            shared_counters = None
        self.shared_counters = shared_counters
        #: Rate limiting state for this worker, shared by every connection it
        #: accepts. ``None`` when the configuration turns it off.
        self.rate_limiter = RateLimiter.from_config(self.config, shared_counters)
        self._connections: set[ConnectionProtocol] = set()
        self._server: asyncio.AbstractServer | None = None
        #: The plaintext listener that redirects to HTTPS, when it is enabled.
        self._redirect_server: asyncio.AbstractServer | None = None
        self._stop_event: asyncio.Event | None = None
        #: Set when a connection is released; created on the serving loop.
        self._released = asyncio.Event()

    # TLS
    def _create_ssl_context(self) -> ssl.SSLContext | None:
        if not self.config.certfile or not self.config.keyfile:
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.config.certfile, self.config.keyfile)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if hasattr(ssl, "OP_NO_COMPRESSION"):
            context.options |= ssl.OP_NO_COMPRESSION
        if hasattr(ssl, "OP_NO_RENEGOTIATION"):
            context.options |= ssl.OP_NO_RENEGOTIATION
        if hasattr(ssl, "OP_CIPHER_SERVER_PREFERENCE"):
            context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        try:
            context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
        except ssl.SSLError:
            self.logger.warning("Could not restrict the cipher suite list")
        protocols: list[str] = []
        if self.config.http2_enabled and H2_AVAILABLE:
            protocols.append("h2")
        if self.config.http1_enabled:
            protocols.append("http/1.1")
        if protocols:  # only offer what is actually served
            context.set_alpn_protocols(protocols)
        return context

    # sockets
    def create_listen_socket(self, host: str | None = None, port: int | None = None, reuse_port: bool | None = None) -> socket.socket:
        """
        Bind and listen on ``host``/``port``.

        ``None`` falls back to ``[server] host``/``port``, which is how the main
        listener is created; the redirect listener passes its own pair.
        ``reuse_port`` overrides whether ``SO_REUSEPORT`` is set (default: when
        ``workers > 1``); the redirect listener opts out, because exactly one
        process serves it however many workers the application runs.
        """
        host = self.config.host if host is None else host
        port = self.config.port if port is None else port
        if not host:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if (self.config.workers > 1 if reuse_port is None else reuse_port) and hasattr(socket, "SO_REUSEPORT"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            if hasattr(socket, "TCP_NODELAY"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        try:
            sock.bind((host, port))
        except OSError:
            sock.close()
            raise
        sock.listen(self.config.backlog)
        sock.setblocking(False)
        return sock

    @property
    def redirect_address(self) -> object:
        """The bound address of the redirect listener, or ``None``."""
        server = self._redirect_server
        if server is None or not server.sockets:
            return None
        return server.sockets[0].getsockname()

    def close_rate_limiter(self) -> None:
        """
        Give up the rate limit counters.

        A table this process created is removed here, so a server that starts
        and stops leaves nothing behind in shared memory; a table it only
        mapped is unmapped, and the process that created it removes it.
        """
        limiter, self.rate_limiter = self.rate_limiter, None
        if limiter is not None:
            limiter.close()
        self.shared_counters = None

    # serving
    def _make_protocol(self) -> ConnectionProtocol:
        return ConnectionProtocol(self.app, self.config, self._connections, logging.getLogger("echocorn"), on_release=self._released.set, rate_limiter=self.rate_limiter)

    async def _create_redirect_server(self, loop: asyncio.AbstractEventLoop, app_sock: socket.socket | None = None) -> asyncio.AbstractServer:
        """
        Open the plaintext listener that redirects every request to HTTPS.

        It is created here, on the serving loop, and only by one worker: the
        redirect is cheap, so a single listener serves the whole application.
        """
        host = self.config.redirect_host or self.config.host
        sock = self.create_listen_socket(host, self.config.redirect_port, reuse_port=False)
        # The TLS listener is already bound, so the redirect knows the port it
        # should send clients to - even when the configuration asked for 0.
        https_port = self.config.port
        sockets = self._server.sockets if self._server is not None else None
        if sockets:
            https_port = sockets[0].getsockname()[1]
        elif app_sock is not None:
            try:
                https_port = app_sock.getsockname()[1]
            except OSError:  # pragma: no cover - defensive
                pass

        def factory() -> RedirectProtocol:
            return RedirectProtocol(
                self.config,
                self._connections,
                logging.getLogger("echocorn"),
                https_port=https_port,
                on_release=self._released.set,
                rate_limiter=self.rate_limiter,
            )

        try:
            return await loop.create_server(factory, sock=sock)
        except Exception:
            sock.close()
            raise

    def run(self, sock: socket.socket | None = None) -> None:
        """Blocking helper: run the server on a fresh event loop."""
        _run(self.serve(sock))

    def request_stop(self) -> None:
        """
        Ask a running server to shut down.

        Safe to call from another thread through
        ``loop.call_soon_threadsafe(server.request_stop)``.
        """
        if self._stop_event is not None:
            self._stop_event.set()

    async def shutdown(self) -> None:
        """Ask a running server to shut down (coroutine friendly alias)."""
        self.request_stop()

    async def serve(self, sock: socket.socket | None = None, *, announce: bool = True, on_ready: Callable[[], None] | None = None, stop_event: object = None, supervisor: Callable[[], bool] | None = None, redirect: bool = True, redirect_only: bool = False) -> None:
        """
        Start accepting connections until a signal asks the server to stop.

        ``sock`` may be supplied by the caller (useful for tests and for
        inheriting a socket from a supervisor process). ``on_ready`` runs as
        soon as the listening socket is bound, which is how a worker announces
        itself; ``stop_event`` (a ``multiprocessing.Event``) lets the process
        that started this one request the same graceful stop, and
        ``supervisor`` reports whether that process is still alive.

        ``redirect`` says whether this process may open the HTTP to HTTPS
        listener; ``redirect_only`` goes further and makes it the *only* thing
        this process serves: the socket handed in is then left to the workers
        that accept on it, and the application (its lifespan included) is never
        touched here.
        """
        loop = asyncio.get_running_loop()
        if sock is None:
            sock = self.create_listen_socket()
        self._released = asyncio.Event()
        if redirect_only and not (redirect and self.config.redirect_enabled):
            raise ValueError("redirect_only needs a configured redirect listener")

        # In redirect-only mode the application listener belongs to the other
        # workers: this process keeps the socket open so the port stays bound,
        # but never accepts on it.
        self._server = None
        if not redirect_only:
            create_kwargs: dict[str, object] = {"sock": sock, "ssl": self.ssl_context}
            if self.ssl_context is not None and self.config.request_timeout > 0:
                # The single request deadline also bounds the TLS handshake,
                # which happens before the application ever sees the connection.
                create_kwargs["ssl_handshake_timeout"] = self.config.request_timeout
            self._server = await loop.create_server(self._make_protocol, **create_kwargs)

        self._redirect_server = None
        if redirect and self.config.redirect_enabled:
            self._redirect_server = await self._create_redirect_server(loop, sock)

        if on_ready is not None:
            try:
                on_ready()
            except BaseException:
                # Startup failed before the first request: release the socket
                # quietly instead of pretending to have served anything.
                self._server.close()
                try:
                    await self._server.wait_closed()
                except Exception:
                    pass
                self.close_rate_limiter()
                raise

        stop = asyncio.Event()
        self._stop_event = stop
        try:
            self._install_signal_handlers(loop, stop)
        except Exception:
            self.logger.warning("Could not install signal handlers", exc_info=True)

        lifespan = None
        if not redirect_only:
            try:
                lifespan = await run_lifespan(self.app)
            except Exception:
                self.logger.exception("Lifespan startup failed; serving without it")

        if announce:
            # The plaintext listener is announced first: it is what an HTTP
            # client meets before it is sent on to the TLS one.
            redirect_sockets = self._redirect_server.sockets if self._redirect_server is not None else None
            if redirect_sockets:
                banner.info("Serving HTTP on %s", format_address(redirect_sockets[0]))
            scheme = "HTTPS" if self.ssl_context is not None else "HTTP"
            sockets = self._server.sockets if self._server is not None else None
            if sockets:
                banner.info("Serving %s on %s", scheme, format_address(sockets[0]))
            elif sock is not None:
                # A redirect-only worker still reports where the application is
                # reachable, because that is the line the operator looks for.
                banner.info("Serving %s on %s", scheme, format_address(sock))

        watcher: asyncio.Task | None = None
        if stop_event is not None or supervisor is not None:
            watcher = asyncio.ensure_future(_watch_supervisor(stop_event, supervisor, stop))
        try:
            await stop.wait()
        except asyncio.CancelledError:
            pass
        finally:
            if watcher is not None:
                watcher.cancel()
            await self._shutdown(lifespan)

    def _install_signal_handlers(self, loop: asyncio.AbstractEventLoop, stop: asyncio.Event) -> None:
        """
        Stop the server on SIGINT/SIGTERM.

        ``loop.add_signal_handler`` is unavailable on Windows (and on loops
        that are not running in the main thread), so fall back to
        ``signal.signal`` with a thread-safe hand-off to the event loop.
        """
        for sig in SIGNALS:
            try:
                loop.add_signal_handler(sig, stop.set)
                continue
            except (NotImplementedError, RuntimeError, AttributeError, ValueError):
                # RuntimeError on POSIX when the loop is not running in the main
                # thread ("set_wakeup_fd only works in main thread"), which is
                # exactly the case for an embedded or threaded server.
                pass
            try:
                signal.signal(sig, lambda *_: loop.call_soon_threadsafe(stop.set))
            except (ValueError, OSError, RuntimeError):
                # signal.signal() is main-thread only as well; without handlers
                # the server still stops through request_stop().
                pass

    async def _shutdown(self, lifespan: object) -> None:
        banner.info("Shutting down")
        loop = asyncio.get_running_loop()
        server = self._server
        if server is not None:
            server.close()
        redirect_server = self._redirect_server
        if redirect_server is not None:
            redirect_server.close()

        # Idle keep-alive connections go away at once; only connections with an
        # in-flight request get the full grace period.
        deadline = loop.time() + max(self.config.graceful_timeout, 0.0)
        while self._connections and loop.time() < deadline:
            for protocol in list(self._connections):
                if protocol.is_idle():
                    protocol.shutdown()
            if not self._connections:
                break
            # Wake as soon as any connection really goes away. The short
            # timeout only covers connections that turn idle on their own, so
            # shutdown does not poll the whole grace period away.
            self._released.clear()
            if not self._connections:
                break
            try:
                await asyncio.wait_for(self._released.wait(), timeout=max(0.0, min(0.5, deadline - loop.time())))
            except asyncio.TimeoutError:
                pass

        if self._connections:
            self.logger.warning("Graceful shutdown timed out; closing %d connection(s)", len(self._connections))
        for protocol in list(self._connections):
            try:
                protocol.shutdown()
            except Exception:
                pass
        if self._connections:
            await asyncio.sleep(0.05)
            for protocol in list(self._connections):
                try:
                    protocol.abort()
                except Exception:
                    pass

        if server is not None:
            try:
                await asyncio.wait_for(server.wait_closed(), timeout=2.0)
            except asyncio.TimeoutError:
                pass
        if redirect_server is not None:
            try:
                await asyncio.wait_for(redirect_server.wait_closed(), timeout=2.0)
            except asyncio.TimeoutError:
                pass

        self.close_rate_limiter()

        if lifespan is not None:
            try:
                await lifespan.shutdown(self.config.graceful_timeout)
            except Exception:
                self.logger.exception("Lifespan shutdown failed")
        banner.info("Shutdown complete")


# Event loop and process handling
def _new_event_loop() -> asyncio.AbstractEventLoop:
    if uvloop is not None:
        return uvloop.new_event_loop()
    return asyncio.new_event_loop()


def _run(coro: object) -> object:
    """Run ``coro`` to completion on a fresh loop (uvloop when available)."""
    if hasattr(asyncio, "Runner"):
        with asyncio.Runner(loop_factory=_new_event_loop) as runner:
            return runner.run(coro)
    loop = _new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        finally:
            asyncio.set_event_loop(None)
            loop.close()


def _configure_logging(level: str, color: bool = False) -> None:
    """
    Install the single log format the server uses.

    Every line starts with the local time and its UTC offset, the level, the
    process id and the message::

        2026-09-22 19:44:24 +0300 [INFO ]  381063: Serving HTTPS on :8000

    Only five level names are ever printed: DEBUG, INFO, WARN, ERROR and CRIT.
    Lifecycle lines go through a logger pinned to INFO, so they still show up
    when everything else has been muted; third party libraries keep the root
    logger, which stays at WARN so their chatter does not drown the output.

    ``color`` (``logging.color`` in the configuration file) paints the level
    with an ANSI escape through :class:`ColoredFormatter`; the layout of a line
    does not change, so the same log file stays machine readable when the
    colour is left out.
    """
    logging.addLevelName(logging.WARNING, "WARN")
    logging.addLevelName(logging.CRITICAL, "CRIT")
    handler = _StderrHandler()
    if color:
        formatter: logging.Formatter = ColoredFormatter(LOG_COLOR_FORMAT, datefmt="%Y-%m-%d %H:%M:%S %z")
    else:
        formatter = logging.Formatter(LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S %z")
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.WARNING)
    logger.setLevel(LEVELS.get(level, logging.INFO))
    banner.setLevel(logging.INFO)


def _add_import_path(config_path: object) -> None:
    """Let ``app = "app:app"`` find a module next to the configuration file."""
    directory = str(Path(config_path).parent.resolve())
    if directory not in sys.path:
        sys.path.insert(0, directory)


class _StderrHandler(logging.StreamHandler):
    """
    Write to the current ``sys.stderr``, not the one bound at startup.

    An application that replaces ``sys.stderr`` - a supervisor rotating the
    console, a test harness - keeps seeing the server output where it belongs.
    """

    def emit(self, record: logging.LogRecord) -> None:
        self.stream = sys.stderr
        super().emit(record)


class WorkerGroup:
    """
    The extra workers a master process starts and supervises.

    The process that reads the configuration is worker #1 and serves traffic
    itself, so ``WorkerGroup(4)`` starts three more processes that bind the same
    port with ``SO_REUSEPORT``. Each child reports back once its socket is
    bound, which is what makes the startup output predictable::

        Waiting for all workers (4)
        Worker #1 ready (current)
        Worker #3 ready
        Worker #2 ready
        Worker #4 ready
        Serving HTTPS on :8000
    """

    def __init__(self, count: int) -> None:
        self.count = count
        self.children: list[Process] = []
        self.stop_event = multiprocessing.Event()
        self._ready: object = multiprocessing.SimpleQueue()

    def start(self, config_path: Path, sock: socket.socket, shared: SharedCounters | None = None) -> None:
        """
        Announce the startup, spawn the children and wait for each one.

        The listening socket is created here, once, and handed to every child:
        they all accept on the same port without binding it again, which is
        what makes ``workers`` work on platforms without ``SO_REUSEPORT``.
        ``shared`` is the rate limit table the master created: its name and its
        mutexes are handed over as well, so every worker counts into the same
        memory instead of one table per process.
        """
        banner.info("Waiting for all workers (%d)", self.count)
        banner.info("Worker #1 ready (current)")
        name = shared.name if shared is not None else None
        locks = list(shared.locks) if shared is not None else None
        for index in range(2, self.count + 1):
            process = Process(
                target=_worker_entry,
                args=(str(config_path), index, self._ready, self.stop_event, sock, name, locks),
                name="echocorn-worker-%d" % index,
            )
            process.start()
            self.children.append(process)
        self._wait_ready()

    def _wait_ready(self) -> None:
        """
        Block until every child reported in, or fail the startup.

        A child that dies or never binds is fatal: serving with a partial set
        of workers would silently halve the capacity the operator asked for.
        """
        ready = 0
        deadline = time.monotonic() + WORKER_STARTUP_TIMEOUT
        while ready < len(self.children):
            if not self._ready.empty():
                self._ready.get()
                ready += 1
                continue
            dead = [child for child in self.children if child.exitcode is not None]
            if dead:
                logger.error("Worker %d exited during startup (code %s)", dead[0].pid, dead[0].exitcode)
                raise SystemExit(1) from None
            if time.monotonic() > deadline:
                logger.error("Workers did not become ready within %.0fs", WORKER_STARTUP_TIMEOUT)
                raise SystemExit(1) from None
            # Startup only: a few milliseconds of waiting, nothing afterwards.
            time.sleep(0.02)

    def stop(self, timeout: float) -> None:
        """Ask the children to shut down and leave none of them behind."""
        self.stop_event.set()
        if os.name == "posix":
            # A child that is blocked somewhere the stop event cannot reach
            # still gets the signal its own handler understands.
            for process in self.children:
                if process.is_alive():
                    try:
                        os.kill(process.pid, signal.SIGTERM)
                    except OSError:
                        pass
        deadline = time.monotonic() + max(timeout, 0.0)
        for process in self.children:
            process.join(timeout=max(0.0, deadline - time.monotonic()))
        for process in self.children:
            if process.is_alive():
                logger.warning("Worker %d did not stop; killing it", process.pid)
                process.kill()
                process.join(timeout=5.0)


def _start_server(settings: object, *, worker_index: int = 1, ready: object = None, stop_event: object = None, group: WorkerGroup | None = None, sock: socket.socket | None = None, supervisor: Callable[[], bool] | None = None, shared: SharedCounters | None = None, create_shared: bool = True) -> None:
    """Build the application and serve it until it is stopped."""
    # The redirect is served by a worker of its own, which only pays off when
    # another worker is left to serve the application. With a single process
    # there is no worker to spare, so the redirect stays off (main() warns).
    redirect = worker_index == 1 and group is not None and settings.config.redirect_enabled

    if (shared is None and worker_index == 1 and settings.config.ratelimit_enabled and settings.config.workers > 1):
        # The process that reads the configuration is worker #1 and starts the
        # others, so it is the one that creates the table they all count into.
        # Creating it before the workers exist is what makes the allowance one
        # set of counters from the very first request.
        shared = _open_shared_counters(settings.config)

    app: Callable
    if redirect:
        # This process only redirects: the application is not imported here at
        # all, so nothing of it runs twice.
        app = _redirect_only_app
    else:
        try:
            app = resolve_app(settings.app, settings.config)
        except Exception:
            logger.exception("Could not create the application %r", settings.app)
            raise SystemExit(1) from None

    server = ASGIServer(app, settings.config, shared_counters=shared, create_shared=create_shared)
    owns_socket = False
    if sock is None and group is not None:
        # The master binds once; the workers inherit the socket.
        try:
            sock = server.create_listen_socket()
        except OSError as exc:
            logger.error("Cannot listen on %s: %s", _address(settings.config), exc)
            raise SystemExit(1) from None
        owns_socket = True

    def on_ready() -> None:
        """Runs on the serving loop, once the listening socket is bound."""
        if group is not None and sock is not None:
            group.start(settings.path, sock, shared=shared)
            counters = server.shared_counters
            if counters is not None:
                banner.info(
                    "Rate limiting is shared by all %d workers (%d client slots, %d shards)",
                    settings.config.workers,
                    counters.slots,
                    counters.shards,
                )
        if ready is not None:
            banner.info("Worker #%d ready", worker_index)
            ready.put(worker_index)

    try:
        _run(
            server.serve(
                sock=sock,
                announce=worker_index == 1,
                on_ready=on_ready,
                stop_event=stop_event,
                supervisor=supervisor,
                # One worker serves the redirect, the rest serve the
                # application: this is the one.
                redirect=redirect,
                redirect_only=redirect,
            )
        )
    except KeyboardInterrupt:
        banner.info("Stopped by KeyboardInterrupt")
    except OSError as exc:
        logger.error("Cannot serve on %s: %s", _address(settings.config), exc)
        raise SystemExit(1) from None
    finally:
        if group is not None:
            group.stop(settings.config.graceful_timeout + 5.0)
        if owns_socket and redirect and sock is not None:
            # The application listeners were never created in this process, so
            # nothing else closes the socket it bound for the workers.
            try:
                sock.close()
            except OSError:  # pragma: no cover - defensive
                pass


def _open_shared_counters(config: ServerConfig) -> SharedCounters | None:
    """
    Create the one rate limit table this server's workers count into.

    Shared memory rather than a file or a second process: a decision is one
    mutex and one slot, with no syscall, no disk and nothing to keep in sync
    behind the request.  Failing to create it is not worth refusing to serve -
    the workers then count on their own, which is what a single process does
    anyway, and the log says so.
    """
    try:
        return SharedCounters.create(config)
    except Exception as exc:
        logger.warning("Rate limit counters cannot be shared (%s); every worker will keep its own", exc)
        return None


def _worker_entry(config_path: str, index: int, ready: object, stop_event: object, sock: socket.socket | None = None, shared_name: str | None = None, shard_locks: list[object] | None = None) -> None:
    """
    Run one worker process from the same configuration file.

    ``shared_name``/``shard_locks`` are the rate limit table the master created
    before this process was started: every worker maps the same memory, so the
    allowance is one set of counters for the whole server.
    """
    try:
        settings = load_settings(config_path)
    except ConfigError as exc:
        logger.error("%s", exc)
        raise SystemExit(1) from None
    _configure_logging(settings.config.log_level, settings.config.log_color)
    _add_import_path(settings.path)

    shared: SharedCounters | None = None
    if shared_name is not None:
        try:
            shared = SharedCounters.attach(shared_name, shard_locks or [], settings.config)
        except Exception:
            # A worker that cannot map the counters counts on its own rather
            # than refusing to serve: the server stays up, the limit is per
            # process, and the log says so.
            logger.exception("Could not map the shared rate limit counters")
    try:
        _start_server(
            settings,
            worker_index=index,
            ready=ready,
            stop_event=stop_event,
            sock=sock,
            supervisor=_worker_supervisor(),
            shared=shared,
            # A table of its own is not a substitute for the one the master
            # created: this worker counts on its own instead of pretending.
            create_shared=shared_name is None,
        )
    except SystemExit:
        pass


def _address(config: ServerConfig) -> str:
    """``host:port`` as it is written in error messages."""
    return "%s:%d" % (config.host or "0.0.0.0", config.port)


USAGE = """usage: echocorn --config PATH

Serve the ASGI application named by the 'app' key of a TOML configuration
file. The path is required: every server setting, including the application,
lives in that file.

Options:
  --config PATH   configuration file to read (required)
  -h, --help      show this message
  --version       show the version
  --about         show version and author information
"""


def _config_argument(arguments: list[str]) -> str | None:
    """Return the ``--config`` path, or report the problem and return None."""
    path: str | None = None
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--config":
            index += 1
            if index >= len(arguments):
                print("echocorn: --config needs a path", file=sys.stderr)
                return None
            path = arguments[index]
        elif argument.startswith("--config="):
            path = argument[len("--config=") :]
            if not path:
                print("echocorn: --config needs a path", file=sys.stderr)
                return None
        else:
            print("echocorn: unexpected argument %r; use --config PATH" % argument, file=sys.stderr)
            return None
        index += 1
    if path is None:
        print("echocorn: no configuration file given", file=sys.stderr)
        return None
    return path


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``echocorn`` command and ``python -m echocorn``."""
    arguments = list(sys.argv[1:] if argv is None else argv)

    if any(argument in ("-h", "--help") for argument in arguments):
        print(USAGE, end="")
        return 0
    if "--version" in arguments:
        print("echocorn %s" % utils.VERSION)
        return 0
    if "--about" in arguments:
        print("echocorn %s" % utils.VERSION)
        print("An ASGI server speaking HTTP/1.1 and HTTP/2.")
        print("https://github.com/mishakorzik/echocorn")
        return 0

    path = _config_argument(arguments)
    if path is None:
        print(USAGE, end="", file=sys.stderr)
        return 2

    try:
        settings = load_settings(path)
    except ConfigError as exc:
        print("echocorn: %s" % exc, file=sys.stderr)
        return 2

    _configure_logging(settings.config.log_level, settings.config.log_color)
    _add_import_path(settings.path)
    logger.debug("Configuration loaded from %s", settings.path)
    banner.info("Using '%s' as event loop", "uvloop" if uvloop is not None else "asyncio")
    logger.debug(
        "Settings: host=%r, port=%d, workers=%d, http1=%s, http2=%s, websocket=%s, "
        "compression=%s, safe_headers=%s, ratelimit=%s, tls=%s, redirect=%s, app=%s",
        settings.config.host,
        settings.config.port,
        settings.config.workers,
        settings.config.http1_enabled,
        settings.config.http2_enabled,
        settings.config.websockets,
        settings.config.compression,
        settings.config.safe_headers,
        settings.config.ratelimit_enabled,
        bool(settings.config.certfile),
        settings.config.redirect_enabled,
        settings.app,
    )

    if settings.config.redirect_enabled and settings.config.workers < 2:
        banner.warning("redirect.enabled is skipped: it needs at least two workers, one for the redirect and the rest for the application")

    group = WorkerGroup(settings.config.workers) if settings.config.workers > 1 else None
    try:
        _start_server(settings, group=group)
    except SystemExit:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
