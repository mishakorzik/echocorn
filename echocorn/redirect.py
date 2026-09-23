"""
HTTP to HTTPS redirector (RFC 9110 section 15.4).

``[redirect] enabled = true`` opens a second, plaintext listener next to the TLS
one.  It never reaches the application: every request that arrives on it is
answered with a redirect whose ``Location`` keeps the original path and query
string, and the connection is closed right after.

The listener is stateless and answers exactly one request per connection, which
is why a single worker is enough for it even when the application runs
``workers = 4``.  The ``https://`` origin is built from the ``Host`` header (or
from ``bind_domain`` when the operator pinned one), so the redirect also works
behind a reverse proxy that rewrites the port.

The socket is owned by :mod:`echocorn.server`; this module only parses one
request head and writes the answer.
"""

from __future__ import annotations

import asyncio
import logging
import re

from . import utils
from .config import ServerConfig
from .ratelimit import RateLimiter, client_key, retry_after_seconds

__all__ = ["RedirectProtocol", "build_location"]

#: A request target is visible ASCII only: it is copied into ``Location`` and
#: must not be able to break that header open.
_ILLEGAL_TARGET_RE = re.compile(rb"[\x00-\x20\x7f]")

#: The same for the authority: an authority never holds a space or a control
#: byte (RFC 3986 section 3.2), and every one of them that reached ``Location``
#: would end the field early - or the whole response, with a bare LF, which is
#: a line terminator to a good few parsers even though it is not one here.
_ILLEGAL_AUTHORITY_RE = re.compile(rb"[\x00-\x20\x7f]")
_REQUEST_LINE_RE = re.compile(rb"^([A-Za-z]+) ([^ ]+) HTTP/([0-9]\.[0-9])$")


def _target_authority(config: ServerConfig, host: bytes, https_port: int | None = None) -> bytes:
    """
    Return the authority to use in ``Location``.

    The ``Host`` header of the redirect request wins, so a client that used
    ``http://example.com/`` is sent to ``https://example.com/`` and keeps the
    name it typed.  ``bind_domain`` is the fallback for a request without a
    ``Host`` header.  The port of the TLS listener replaces whatever port the
    request carried, and is left out for the default port 443.
    """
    name = host.strip() or config.bind_domain.encode("latin-1", "replace")
    if _ILLEGAL_AUTHORITY_RE.search(name):
        raise ValueError("the authority cannot be put in a header")
    if name.startswith(b"["):
        # An IPv6 literal keeps its brackets, only the port is dropped.
        end = name.find(b"]")
        if end == -1:
            raise ValueError("unterminated IPv6 authority")
        name = name[: end + 1]
    elif name.count(b":") == 1:
        name = name.split(b":", 1)[0]
    if not name:
        raise ValueError("no authority to redirect to")
    port = config.port if https_port is None else https_port
    if port in (0, 443):
        return name
    return name + b":" + str(port).encode("ascii")


def build_location(config: ServerConfig, target: bytes, host: bytes = b"", https_port: int | None = None) -> bytes | None:
    """
    Return the absolute ``https://`` URL a request target is redirected to.

    ``None`` means no redirect can be built, which the caller answers with
    ``400``: only the origin form (``/path``) and the absolute form
    (``http://host/path``) name a path that survives the switch to HTTPS, and
    only an authority that can be written into a header (no space, no control
    byte) can be redirected to.  ``https_port`` is the port the TLS listener is
    really bound to, which is what the redirect uses when the configuration
    asked for an ephemeral one.
    """
    if target.startswith(b"http://"):
        # Absolute form: only the scheme changes, the authority is already there.
        location = b"https://" + target[len(b"http://") :]
        return None if _ILLEGAL_AUTHORITY_RE.search(location) else location
    if not target.startswith(b"/"):
        return None
    try:
        authority = _target_authority(config, host, https_port)
    except ValueError:
        return None
    location = b"https://" + authority + target
    if _ILLEGAL_AUTHORITY_RE.search(location):
        return None
    return location


class RedirectProtocol(asyncio.Protocol):
    """
    One plaintext connection, answered with a redirect to the HTTPS origin.

    The protocol is a single shot: it reads one request head, writes one
    response and closes.  It is registered in the server's connection set, so
    ``max_connections`` also bounds it and a graceful shutdown closes it with
    everything else.
    """

    def __init__(self, config: ServerConfig, connections: set[object], logger: logging.Logger, https_port: int | None = None, on_release: object = None, rate_limiter: RateLimiter | None = None) -> None:
        self.config = config
        self.logger = logger
        self._connections = connections
        self._https_port = https_port
        self._on_release = on_release
        self.rate_limiter = rate_limiter
        self._released = False
        self.transport: asyncio.Transport | None = None
        self.peername: object = None
        self._buffer = bytearray()
        self._timer: asyncio.TimerHandle | None = None
        self._answered = False
        self._closed = False
        self._connections.add(self)

    # asyncio protocol callbacks.
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport
        self.peername = transport.get_extra_info("peername")
        utils.tune_socket(transport.get_extra_info("socket"))

        limit = self.config.max_connections
        if limit and len(self._connections) > limit:
            self._answer(503, reason="connection limit reached")
            return
        # A peer that connects and never sends a request is reset, exactly like
        # on the main listener.
        timeout = self.config.request_timeout
        if timeout > 0:
            self._timer = asyncio.get_running_loop().call_later(timeout, self._expire)

    def data_received(self, data: bytes) -> None:
        if self._answered or self._closed:
            return
        self._buffer.extend(data)
        if len(self._buffer) > self.config.max_header_size:
            self._answer(431, reason="request head too large")
            return
        index = self._buffer.find(b"\r\n\r\n")
        if index == -1:
            return
        self._handle(self._buffer[:index])

    def eof_received(self) -> bool:
        self._close()
        return False

    def connection_lost(self, exc: BaseException | None) -> None:
        self._closed = True
        self._cancel_timer()
        self._release()

    # Shutdown hooks, so the server treats this like any other connection.
    def is_idle(self) -> bool:
        return True

    def shutdown(self) -> None:
        self._close()

    def abort(self) -> None:
        self._closed = True
        self._cancel_timer()
        transport = self.transport
        if transport is not None:
            utils.force_reset(transport)
        self._release()

    # internals
    def _handle(self, head: bytes) -> None:
        """Parse one request head and answer it; the connection then closes."""
        lines = head.split(b"\r\n")
        match = _REQUEST_LINE_RE.match(lines[0])
        if match is None:
            self._answer(400, reason="malformed request line")
            return
        method, target = match.group(1), match.group(2)
        if _ILLEGAL_TARGET_RE.search(target):
            self._answer(400, reason="illegal character in request target", method=method, target=target)
            return

        if self.rate_limiter is not None:
            client = client_key(self.peername)
            wait = self.rate_limiter.check(client)
            if wait is not None:
                # The plaintext listener is the one an abusive client finds
                # first, so it is rate limited like any other request, and the
                # refusal is reported with the address that was limited.
                seconds = retry_after_seconds(wait)
                self._answer(
                    429,
                    reason="too many requests",
                    retry_after=seconds,
                    method=method,
                    target=target,
                )
                return

        host = b""
        for line in lines[1:]:
            if line[:1] in (b" ", b"\t"):
                self._answer(400, reason="obsolete line folding is not supported", method=method, target=target)
                return
            name, sep, value = line.partition(b":")
            if not sep:
                self._answer(400, reason="malformed header field", method=method, target=target)
                return
            if name.strip().lower() == b"host":
                host = value.strip()
                break

        location = build_location(self.config, target, host, self._https_port)
        if location is None:
            self._answer(
                400,
                reason="no redirect target can be built for this request",
                method=method,
                target=target,
            )
            return
        self.logger.debug("Redirecting %s to %s", target, location)
        self._answer(self.config.redirect_status, location=location, method=method, target=target)

    def _answer(self, status: int, location: bytes | None = None, reason: str = "", method: bytes = b"GET", retry_after: int | None = None, target: bytes = b"") -> None:
        """Write one response (a redirect or a refusal) and close the socket."""
        if self._answered:
            return
        self._answered = True
        self._cancel_timer()

        if status >= 400:
            # A refusal here never reaches the application, so the log is the
            # only place the address and the reason can be seen.
            utils.refusal_log(
                self.logger,
                "h11",
                self.peername,
                method.decode("latin-1", "replace") or None,
                bytes(target).decode("latin-1", "replace"),
                status,
                reason,
            )

        phrase = utils.status_phrase(status)
        lines = ["%d %s" % (status, phrase)]
        # Only a message that adds information is repeated; a reason that is
        # just the status phrase must not show up twice in the body.
        if reason and reason.strip().lower() != phrase.lower():
            lines.append(reason)
        body = ("\n".join(lines) + "\n").encode("latin-1", "replace")
        # A HEAD response announces the length it would have had, without a body.
        send_body = utils.response_has_body(method.decode("latin-1", "replace") or "GET", status)

        parts = [
            b"HTTP/1.1 ",
            str(status).encode("latin-1"),
            b" ",
            phrase.encode("latin-1"),
            b"\r\n",
            b"content-type: text/plain; charset=utf-8\r\n",
            b"content-length: " + str(len(body)).encode("ascii") + b"\r\n",
            b"date: " + utils.format_http_date().encode("latin-1") + b"\r\n",
            b"server: " + utils.SERVER_HEADER.encode("latin-1") + b"\r\n",
        ]
        if location is not None:
            parts.append(b"location: " + location + b"\r\n")
        if retry_after is not None:
            parts.append(b"retry-after: " + str(retry_after).encode("ascii") + b"\r\n")
        parts.append(b"connection: close\r\n\r\n")
        self._write(b"".join(parts) + (body if send_body else b""))
        self._close()

    def _expire(self) -> None:
        """Drop a connection that never sent a complete request head."""
        self._timer = None
        if self._answered or self._closed:
            return
        self.logger.debug("Resetting a redirect connection that sent no request")
        transport = self.transport
        if transport is not None:
            utils.force_reset(transport)
        self._release()

    def _write(self, data: bytes) -> None:
        transport = self.transport
        if transport is None:
            return
        try:
            transport.write(data)
        except Exception:
            self._release()

    def _cancel_timer(self) -> None:
        timer, self._timer = self._timer, None
        if timer is not None:
            timer.cancel()

    def _close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._cancel_timer()
        transport = self.transport
        if transport is not None:
            try:
                # close() flushes what was written above before the FIN.
                transport.close()
            except Exception:
                pass
        self._release()

    def _release(self) -> None:
        """Forget the connection once, so shutdown can wait for it to go."""
        if self._released:
            return
        self._released = True
        self._connections.discard(self)
        if self._on_release is not None:
            self._on_release()
