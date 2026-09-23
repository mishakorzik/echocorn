"""
Reverse proxy to a server running on a local address.

``app = "127.0.0.1:5000"`` puts Echocorn in front of a program that is already
listening locally - a development server, a WSGI process, an old application
that will not move to ASGI, or something on the same network as
``10.0.0.16:8080``.  Everything the server does in front of an application
keeps working: TLS with ALPN, HTTP/1.1 and HTTP/2, compression, the request
limits and timeouts, the access log and the HTTP to HTTPS redirect. Only the
request itself is forwarded, and the answer is streamed back.

The hop is a plain HTTP/1.1 connection to the upstream which is kept alive and
reused, a request body is forwarded while it arrives and a response body while
it is produced, so a proxied request does not turn into whole-body buffering.
The client-facing protocol is terminated here: an HTTP/2 request is translated
to HTTP/1.1 on the way out and its answer is framed for the client on the way
back, and a WebSocket session is an HTTP/1.1 upgrade on both sides.

The upstream connection is an :class:`asyncio.Protocol` like every other
connection this server owns - bytes are handed to it and the coroutine that
drives one exchange awaits them - so the whole server runs on one transport
model, with the same write backpressure and no stream layer in between.

The client's own ``X-Forwarded-For`` and friends are **replaced**, never
extended: the address in them is the one the connection actually came from, so
an application (or the rate limiter) that trusts them cannot be lied to.

:func:`echocorn.config.proxy_target` refuses a public address, so a
configuration file cannot turn the server into an open proxy.

A WebSocket upgrade is tunnelled as well: the handshake is repeated against the
upstream, and once both sides have accepted, messages are forwarded frame by
frame in both directions (pings are answered on the side they arrive on), so a
proxied session behaves like a direct one.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
from collections import deque
from collections.abc import Callable

from . import utils
from . import websocket
from .config import ServerConfig
from .http1 import ChunkedDecoder, _ProtocolError
from .utils import HOP_BY_HOP_HEADERS, Headers

__all__ = ["ProxyApp", "ProxyProtocolError", "UpstreamClosed"]

#: How long an idle upstream connection stays in the pool before it is dropped.
IDLE_TIMEOUT = 30.0

#: How many idle connections to the upstream are kept for reuse.
MAX_IDLE = 16

#: Read size while streaming a body in either direction.
CHUNK_SIZE = 65536

#: How much of a refused handshake body is relayed back to the client.
REFUSAL_LIMIT = 8192

#: Write buffer watermarks of the upstream transport, so a slow application
#: cannot make a streamed answer grow in memory.
WRITE_HIGH_WATERMARK = 262144
WRITE_LOW_WATERMARK = 65536

#: Methods that may be sent again on a fresh connection when the failure
#: happened before the answer started (RFC 9110 section 9.2.2).
_RETRYABLE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"})

#: Request fields that describe the client link.  The client's values are
#: dropped rather than extended: everything on this hop - the application, its
#: logs, the rate limiter - must see the address the connection really came
#: from, and a client must not be able to write them for itself.  The last five
#: are the older spellings of "this request was secure", which a framework may
#: still read to decide whether to set a secure cookie or trust its own
#: authentication: a client that could set them would be deciding that for
#: itself, so they are rebuilt here from the connection, like the rest.
_CLIENT_FIELDS = (
    b"x-forwarded-for",
    b"x-forwarded-proto",
    b"x-forwarded-host",
    b"x-forwarded-port",
    b"x-forwarded-server",
    b"x-real-ip",
    b"forwarded",
    b"x-forwarded-ssl",
    b"x-forwarded-scheme",
    b"x-url-scheme",
    b"x-https",
    b"front-end-https",
)

#: The same hop-by-hop fields as a tuple.  A header name taken from an HTTP/1.1
#: peer is a slice of the bytearray the parser reads, so it is a ``bytearray`` -
#: which is unhashable and would make a ``frozenset`` lookup raise.  ``in`` on a
#: tuple compares by value and takes either type.
_HOP_BY_HOP = tuple(HOP_BY_HOP_HEADERS)

#: Response fields that must not be repeated to the client: they either describe
#: this hop, or they are rebuilt here (the trailer announcement).
_DROP_RESPONSE_HEADERS = tuple(HOP_BY_HOP_HEADERS | {b"proxy-connection"})

#: A header field name is a token (RFC 9110 section 5.1).
_TOKEN_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class ProxyProtocolError(Exception):
    """The upstream answered with something that cannot be forwarded."""


class UpstreamClosed(OSError):
    """
    The upstream connection went away before the exchange was complete.

    An ``OSError`` so it is caught by the same handlers as a socket failure,
    but distinct from :class:`ProxyProtocolError` because a request that has
    not been written yet may still be tried on a fresh connection.
    """


class UpstreamConnection(asyncio.Protocol):
    """
    One connection to the application behind the proxy.

    Bytes are buffered as they arrive and the coroutine that drives the exchange
    awaits them; :meth:`drain` waits while the transport is over its high water
    mark, so a slow upstream cannot be made to buffer a whole answer in memory.
    """

    __slots__ = (
        "transport",
        "buffer",
        "eof",
        "error",
        "limit",
        "arrivals",
        "_readable",
        "_writable",
        "_paused",
        "_closed",
    )

    def __init__(self, limit: int) -> None:
        self.transport: asyncio.Transport | None = None
        self.buffer = bytearray()
        self.eof = False
        self.error: BaseException | None = None
        self.limit = limit
        #: How many times something arrived (data, EOF, a close). A reader that
        #: waits for *more* of a block it has already seen has to compare this
        #: against what it saw, because the buffer it is reading is not empty -
        #: waiting for "the buffer is not empty" would return at once and send
        #: the caller back round the same bytes forever, and a spin like that
        #: starves the event loop, so the EOF it is waiting for never arrives.
        self.arrivals = 0
        self._readable = asyncio.Event()
        self._writable = asyncio.Event()
        self._writable.set()
        self._paused = False
        self._closed = False

    # asyncio protocol callbacks
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport
        try:
            transport.set_write_buffer_limits(high=WRITE_HIGH_WATERMARK, low=WRITE_LOW_WATERMARK)
        except (AttributeError, NotImplementedError):  # pragma: no cover - sockets support it
            pass

    def data_received(self, data: bytes) -> None:
        if self._closed:
            return
        self.buffer.extend(data)
        self.arrivals += 1
        self._readable.set()

    def eof_received(self) -> bool:
        self.eof = True
        self.arrivals += 1
        self._readable.set()
        # False closes the transport: a half closed upstream is of no use here.
        return False

    def connection_lost(self, exc: BaseException | None) -> None:
        self.eof = True
        self._closed = True
        self.error = exc
        self.arrivals += 1
        self._readable.set()
        self._writable.set()

    def pause_writing(self) -> None:
        self._paused = True
        self._writable.clear()

    def resume_writing(self) -> None:
        self._paused = False
        self._writable.set()

    # state
    @property
    def closed(self) -> bool:
        return self._closed

    def reusable(self) -> bool:
        """Whether the connection may be handed to another request."""
        return not self._closed and not self.eof and not self.buffer

    def close(self) -> None:
        self._closed = True
        transport, self.transport = self.transport, None
        if transport is not None:
            try:
                transport.close()
            except Exception:  # pragma: no cover - close never raises in practice
                pass

    # writing
    def write(self, data: object) -> None:
        transport = self.transport
        if transport is None or self._closed:
            raise UpstreamClosed("the upstream connection is gone")
        try:
            transport.write(data)
        except Exception as exc:
            raise UpstreamClosed("cannot write to the upstream: %s" % exc) from exc

    async def drain(self) -> None:
        """Wait while the upstream transport is over its high water mark."""
        while self._paused and not self._closed:
            self._writable.clear()
            if not self._paused or self._closed:
                break
            await self._writable.wait()

    # reading
    async def _wait_for_data(self) -> None:
        """Wait until there is something buffered, or the upstream is gone."""
        while not self.buffer and not self.eof and not self._closed:
            self._readable.clear()
            if self.buffer or self.eof or self._closed:
                break
            await self._readable.wait()

    async def _wait_for_arrival(self, seen: int) -> int:
        """
        Wait until the upstream sent something new; return the new count.

        ``seen`` is the count the caller last looked at. Waiting on "there is
        data in the buffer" would not do here: the caller is looking for the
        *end* of a block whose beginning it already holds, so a wait that
        returns at once would spin on those same bytes. Nothing else runs
        between the clear and the wait, so an arrival cannot be missed.
        """
        while self.arrivals == seen:
            self._readable.clear()
            await self._readable.wait()
        return self.arrivals

    async def read_line_block(self, marker: bytes, limit: int) -> bytearray:
        """
        Read up to and including ``marker``, refusing more than ``limit`` bytes.

        Returns a slice of the read buffer, so the caller sees a ``bytearray``
        and must convert a field it hands to the ASGI layer. The limit is
        enforced on both paths: a block that arrived in one piece is measured
        against it too, so an upstream cannot dodge it by being fast.
        """
        while True:
            seen = self.arrivals
            index = self.buffer.find(marker)
            if index != -1:
                end = index + len(marker)
                if end > limit:
                    raise ProxyProtocolError("the upstream response head is too large")
                data = self.buffer[:end]
                del self.buffer[:end]
                return data
            if len(self.buffer) > limit:
                raise ProxyProtocolError("the upstream response head is too large")
            if self.eof or self._closed:
                raise UpstreamClosed("the upstream closed without answering")
            await self._wait_for_arrival(seen)

    async def read(self, size: int) -> bytearray:
        """Read at most ``size`` bytes; empty only once the upstream closed."""
        while not self.buffer:
            if self.eof or self._closed:
                return bytearray()
            await self._wait_for_data()
        take = min(size, len(self.buffer))
        data = self.buffer[:take]
        del self.buffer[:take]
        return data


def trailer_names(headers: Headers) -> list[bytes]:
    """The field names an upstream answer announced in a ``Trailer`` header."""
    names: list[bytes] = []
    for name, value in headers:
        if name != b"trailer":
            continue
        for item in value.split(b","):
            field = bytes(item.strip().lower())
            if field and _TOKEN_RE.match(field) and field not in names:
                names.append(field)
    return names


class ProxyApp:
    """
    ASGI application that forwards HTTP requests to a local server.

    One instance is built per ``app = "host:port"`` setting and shared by every
    request on the serving process, so the connection pool below is per worker.
    """

    def __init__(self, host: str, port: int, config: ServerConfig) -> None:
        self.host = host
        self.port = port
        self.config = config
        self.logger = logging.getLogger("echocorn.proxy")
        self._idle: deque[tuple[UpstreamConnection, float]] = deque()
        # An IPv6 upstream needs its brackets back in the request line.
        name = "[%s]" % host if ":" in host else host
        self.authority = "%s:%d" % (name, port)

    # ASGI application
    async def __call__(self, scope: dict[str, object], receive: Callable, send: Callable) -> None:
        scope_type = scope["type"]
        if scope_type == "lifespan":
            await self._lifespan(receive, send)
        elif scope_type == "http":
            await self._http(scope, receive, send)
        else:
            await self._websocket(scope, receive, send)

    async def _lifespan(self, receive: Callable, send: Callable) -> None:
        """Answer the handshake: a proxy has nothing to start or stop."""
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                self._close_idle()
                await send({"type": "lifespan.shutdown.complete"})
                return

    # One proxied WebSocket session
    async def _websocket(self, scope: dict[str, object], receive: Callable, send: Callable) -> None:
        """Repeat the handshake against the upstream, then tunnel the frames."""
        await receive()  # websocket.connect
        connection: UpstreamConnection | None = None
        try:
            connection, _ = await self._connect(reuse=False)
        except (OSError, asyncio.TimeoutError) as exc:
            self.logger.warning("Cannot reach %s: %s", self.authority, exc)
            await self._refuse(send, 502, "Bad Gateway", "cannot reach %s" % self.authority)
            return

        try:
            key = base64.b64encode(os.urandom(16))
            connection.write(self._build_upgrade(scope, key))
            await connection.drain()
            status, headers, _version, framing = await self._read_head(connection, "GET", allow_upgrade=True)
            if status != 101:
                # The upstream refused the upgrade: relay its own answer, so a
                # client sees the same 401/403/404 it would have seen directly.
                body = await self._read_small_body(connection, headers, framing)
                await self._relay_refusal(send, status, headers, body)
                return
            if utils.get_header(headers, b"sec-websocket-accept") != websocket.accept_key(key):
                raise ProxyProtocolError("the upstream handshake is not a valid answer")
            if utils.has_header(headers, b"sec-websocket-extensions"):
                # This hop offered no extension, so an answer naming one cannot
                # be honoured: a tunnel carrying frames the client cannot read
                # is worse than a refusal (RFC 6455 section 9.1).
                raise ProxyProtocolError("the upstream selected a WebSocket extension we did not offer")
            await send(self._accept_message(scope, headers))
            await self._tunnel(connection, receive, send)
        except websocket.WebSocketError as exc:
            self.logger.warning("Upstream %s broke the WebSocket protocol: %s", self.authority, exc)
            await self._close_client(send, websocket.CLOSE_PROTOCOL_ERROR)
        except ProxyProtocolError as exc:
            self.logger.warning("Upstream %s: %s", self.authority, exc)
            await self._refuse(send, 502, "Bad Gateway", str(exc))
        except OSError as exc:
            self.logger.warning("Upstream %s failed: %s", self.authority, exc)
            await self._refuse(send, 502, "Bad Gateway", "the upstream connection failed")
        finally:
            # A tunnel is never returned to the pool: it has no request left to
            # serve, it only carries frames.
            if connection is not None:
                connection.close()

    @staticmethod
    def _accept_message(scope: dict[str, object], headers: Headers) -> dict[str, object]:
        """The ``websocket.accept`` for a session the upstream accepted."""
        message: dict[str, object] = {"type": "websocket.accept"}
        chosen = utils.get_header(headers, b"sec-websocket-protocol")
        if chosen is not None:
            name = chosen.decode("latin-1")
            # Only a protocol the client actually offered may be chosen.
            if name in scope.get("subprotocols", []):
                message["subprotocol"] = name
        return message

    def _build_upgrade(self, scope: dict[str, object], key: bytes) -> bytes:
        """Serialise the handshake that is sent to the upstream."""
        raw_path = scope.get("raw_path") or b"/"
        query = scope.get("query_string") or b""
        target = raw_path + (b"?" + query if query else b"")

        lines = [b"GET " + target + b" HTTP/1.1"]
        for name, value in scope["headers"]:
            lowered = name.lower()
            if lowered in _HOP_BY_HOP or lowered == b"host":
                continue
            # The handshake of this hop is our own: our key, our version, and
            # no extension (an extension answer could not be forwarded anyway).
            if lowered in (b"sec-websocket-key", b"sec-websocket-version", b"sec-websocket-extensions"):
                continue
            if lowered in _CLIENT_FIELDS:
                # Replaced below with the address this connection came from.
                continue
            lines.append(name + b": " + value)
        lines.append(b"host: " + self.authority.encode("latin-1"))
        lines.append(b"upgrade: websocket")
        lines.append(b"connection: Upgrade")
        lines.append(b"sec-websocket-key: " + key)
        lines.append(b"sec-websocket-version: 13")
        lines.extend(self._client_link_headers(scope))
        return b"\r\n".join(lines) + b"\r\n\r\n"

    def _client_link_headers(self, scope: dict[str, object]) -> list[bytes]:
        """
        The forwarding fields of this hop, built from the real client address.

        ``X-Forwarded-For`` is set to the address of the connection itself, not
        appended to: a value the client sent would otherwise be the first entry
        the application sees, and everything behind this server that trusts it -
        logs, ACLs, the application's own rate limiting - would believe it.
        """
        lines: list[bytes] = []
        client = scope.get("client")
        if client:
            address = str(client[0]).encode("latin-1", "replace")
            lines.append(b"x-real-ip: " + address)
            lines.append(b"x-forwarded-for: " + address)
        scheme = str(scope.get("scheme", "http")).encode("latin-1", "replace")
        secure = b"on" if scheme == b"https" else b"off"
        lines.append(b"x-forwarded-proto: " + scheme)
        # The older ways of saying the same thing, replaced rather than passed
        # on: some frameworks and plugins still read one of these, and the
        # client is the last party that should decide whether its own request
        # was secure.
        lines.append(b"x-forwarded-scheme: " + scheme)
        lines.append(b"x-url-scheme: " + scheme)
        lines.append(b"x-forwarded-ssl: " + secure)
        lines.append(b"x-https: " + secure)
        lines.append(b"front-end-https: " + secure)
        server = scope.get("server")
        if server:
            lines.append(b"x-forwarded-port: " + str(server[1]).encode("latin-1"))
        else:
            forwarded_port = utils.get_header(scope["headers"], b"host")
            if forwarded_port is not None and b":" in forwarded_port:
                lines.append(b"x-forwarded-port: " + forwarded_port.rsplit(b":", 1)[1])
        original_host = utils.get_header(scope["headers"], b"host")
        if original_host:
            lines.append(b"x-forwarded-host: " + original_host)
        return lines

    async def _tunnel(self, connection: UpstreamConnection, receive: Callable, send: Callable) -> None:
        """Forward frames in both directions until one side closes."""
        from_upstream = asyncio.ensure_future(self._from_upstream(connection, send))
        from_client = asyncio.ensure_future(self._from_client(connection, receive, send))
        tasks = (from_upstream, from_client)
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                task.result()
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()

    async def _from_client(self, connection: UpstreamConnection, receive: Callable, send: Callable) -> None:
        """Forward the messages of the client to the upstream (masked)."""
        while True:
            message = await receive()
            kind = message["type"]
            if kind == "websocket.receive":
                text = message.get("text")
                if text is not None:
                    frame = websocket.build_frame(websocket.OPCODE_TEXT, text.encode("utf-8"), mask=os.urandom(4))
                elif message.get("bytes") is not None:
                    frame = websocket.build_frame(websocket.OPCODE_BINARY, message["bytes"], mask=os.urandom(4))
                else:
                    continue
                connection.write(frame)
                await connection.drain()
            elif kind == "websocket.disconnect":
                # 1005 and 1006 describe a missing close frame; neither may be
                # put on the wire (RFC 6455 section 7.4.1), so 1001 is sent.
                code = int(message.get("code") or websocket.CLOSE_NORMAL)
                if code in (1005, 1006):
                    code = websocket.CLOSE_GOING_AWAY
                connection.write(websocket.build_close_frame(code, mask=os.urandom(4)))
                await connection.drain()
                return
            else:
                return

    async def _from_upstream(self, connection: UpstreamConnection, send: Callable) -> None:
        """Forward the frames of the upstream to the client."""
        parser = websocket.FrameParser(self.config.max_websocket_message_size, require_mask=False)
        buffer = bytearray()
        while True:
            events = parser.feed(buffer)
            if not events:
                data = await connection.read(CHUNK_SIZE)
                if not data:
                    # The upstream vanished without a close frame.
                    await self._close_client(send, websocket.CLOSE_GOING_AWAY)
                    return
                buffer.extend(data)
                continue
            for kind, value in events:
                if kind == "text":
                    await send({"type": "websocket.send", "text": value})
                elif kind == "bytes":
                    await send({"type": "websocket.send", "bytes": value})
                elif kind == "ping":
                    connection.write(websocket.build_frame(websocket.OPCODE_PONG, value, mask=os.urandom(4)))
                    await connection.drain()
                elif kind == "close":
                    code, reason = value
                    if code == 1005:  # "no status received"
                        code = websocket.CLOSE_NORMAL
                    await self._close_client(send, code, reason)
                    return

    @staticmethod
    async def _close_client(send: Callable, code: int, reason: str = "") -> None:
        """End the client session with the close frame of the upstream."""
        message: dict[str, object] = {"type": "websocket.close", "code": code}
        if reason:
            message["reason"] = reason
        try:
            await send(message)
        except Exception:
            pass

    async def _refuse(self, send: Callable, status: int, reason: str, detail: str) -> None:
        """Answer a refused WebSocket handshake with a real HTTP response."""
        body = ("%d %s\n%s\n" % (status, reason, detail)).encode("latin-1", "replace")
        try:
            await send({"type": "websocket.http.response.start", "status": status, "headers": [(b"content-type", b"text/plain; charset=utf-8")]})
            await send({"type": "websocket.http.response.body", "body": body})
        except Exception:  # pragma: no cover - the handshake may be answered already
            pass

    async def _relay_refusal(self, send: Callable, status: int, headers: Headers, body: bytearray) -> None:
        """Relay the upstream's refusal of an upgrade to the client."""
        forwarded: Headers = [(name, value) for name, value in headers if name not in _DROP_RESPONSE_HEADERS]
        # The length is not repeated (a truncated body would not match it), so
        # the server closes the response instead of framing it.
        forwarded = [item for item in forwarded if item[0] != b"content-length"]
        try:
            await send({"type": "websocket.http.response.start", "status": status, "headers": forwarded})
            await send({"type": "websocket.http.response.body", "body": body})
        except Exception:
            pass

    async def _read_small_body(self, connection: UpstreamConnection, headers: Headers, framing: str) -> bytearray:
        """Read at most :data:`REFUSAL_LIMIT` bytes of a refusal body."""
        if framing == "none":
            return bytearray()
        out = bytearray()
        if framing == "length":
            try:
                remaining = int(utils.get_header(headers, b"content-length") or 0)
            except ValueError:
                raise ProxyProtocolError("malformed upstream content-length") from None
            while remaining > 0 and len(out) < REFUSAL_LIMIT:
                data = await connection.read(min(remaining, CHUNK_SIZE))
                if not data:
                    break
                remaining -= len(data)
                out.extend(data)
            return out
        if framing == "chunked":
            decoder = ChunkedDecoder()
            buffer = bytearray()
            while not decoder.done and len(out) < REFUSAL_LIMIT:
                if buffer:
                    before = len(buffer)
                    try:
                        chunks = decoder.feed(buffer, 0)
                    except _ProtocolError:
                        break
                    for chunk in chunks:
                        if len(out) >= REFUSAL_LIMIT:
                            break
                        out.extend(chunk)
                    if len(buffer) < before:
                        # Bytes were consumed: keep going with what is buffered.
                        continue
                data = await connection.read(CHUNK_SIZE)
                if not data:
                    break
                buffer.extend(data)
            return out
        while len(out) < REFUSAL_LIMIT:
            data = await connection.read(CHUNK_SIZE)
            if not data:
                break
            out.extend(data)
        return out

    # One proxied request
    async def _http(self, scope: dict[str, object], receive: Callable, send: Callable) -> None:
        framing = self._request_framing(scope["headers"])
        reason = "the upstream connection failed"
        # A pooled connection may have been closed by the upstream since it was
        # put back - an idle timeout on the other side, a restart - and a socket
        # only reports that when it is written to. A request that carries no
        # body can be sent again on a fresh connection; one that does cannot,
        # because its body has already been handed to the application and the
        # application is already running.
        attempts = 1
        if framing == "none" and scope["method"].upper() in _RETRYABLE_METHODS:
            attempts = 2
        for attempt in range(attempts):
            connection: UpstreamConnection | None = None
            reused = False
            reusable = False
            try:
                connection, reused = await self._connect(reuse=attempt == 0)
            except (OSError, asyncio.TimeoutError) as exc:
                self.logger.warning("Cannot reach %s: %s", self.authority, exc)
                reason = "cannot reach %s" % self.authority
                break
            try:
                connection.write(self._build_request(scope, framing))
                if framing == "none":
                    await connection.drain()
                else:
                    await self._forward_body(scope, framing, receive, connection)
                status, headers, version, body_framing = await self._read_head(connection, scope["method"])
                await self._relay(scope, connection, status, headers, body_framing, send)
                # Only an answer that made it through whole leaves the
                # connection reusable; a truncated body would desync the next
                # request on it.
                reusable = self._is_reusable(headers, version, body_framing)
                if body_framing == "none" and (utils.has_header(headers, b"content-length") or utils.has_header(headers, b"transfer-encoding")):
                    # A HEAD/204/304 answer announces the length its body would
                    # have had. An upstream that sends that body anyway would
                    # leave it in the socket, where it would be read as the
                    # answer to whatever request came next - so a connection is
                    # only pooled when the upstream said there is nothing to
                    # send, and a lying one pays the connect instead.
                    reusable = False
                reason = ""
            except utils.ResponseAborted:
                # The answer was already on its way; the writer abandons the
                # framing and the connection goes with it.
                raise
            except ProxyProtocolError as exc:
                self.logger.warning("Upstream %s: %s", self.authority, exc)
                reason = str(exc)
            except OSError as exc:
                self.logger.warning("Upstream %s failed: %s", self.authority, exc)
                reason = "the upstream connection failed (%s)" % exc
            finally:
                if connection is not None:
                    self._release(connection, reusable)
            if not reason:
                return
            if attempt + 1 < attempts and reused:
                self.logger.debug(
                    "Retrying %s %s on a fresh connection: %s",
                    scope["method"],
                    scope.get("path"),
                    reason,
                )
                continue
            break
        await self._fail(send, reason)

    def _build_request(self, scope: dict[str, object], framing: str) -> bytes:
        """Serialise the client request as a plain HTTP/1.1 request."""
        raw_path = scope.get("raw_path") or b"/"
        query = scope.get("query_string") or b""
        target = raw_path + (b"?" + query if query else b"")

        lines = [b"%s %s HTTP/1.1" % (scope["method"].encode("latin-1"), target)]
        for name, value in scope["headers"]:
            lowered = name.lower()
            # The connection to the upstream is our own, and the authority is
            # replaced below, so neither field is copied.
            if lowered in _HOP_BY_HOP or lowered == b"host":
                continue
            if lowered in _CLIENT_FIELDS:
                # Replaced below with the address this connection came from.
                continue
            lines.append(name + b": " + value)
        lines.append(b"host: " + self.authority.encode("latin-1"))
        lines.extend(self._client_link_headers(scope))
        if framing == "chunked":
            lines.append(b"transfer-encoding: chunked")
        return b"\r\n".join(lines) + b"\r\n\r\n"

    @staticmethod
    def _request_framing(headers: Headers) -> str:
        """How the client framed its request body: length, chunked or none."""
        length = utils.get_header(headers, b"content-length")
        if length is not None:
            try:
                return "length" if int(length) > 0 else "none"
            except ValueError:
                # Unreachable through the server's own parser; be defensive.
                return "none"
        if utils.has_header(headers, b"transfer-encoding"):
            return "chunked"
        return "none"

    async def _forward_body(self, scope: dict[str, object], framing: str, receive: Callable, connection: UpstreamConnection,) -> None:
        """Stream the request body to the upstream as it arrives."""
        sent = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                raise ProxyProtocolError("the client went away")
            body = message.get("body") or b""
            if framing == "chunked":
                if body:
                    connection.write(b"%x\r\n" % len(body) + body + b"\r\n")
            elif body:
                connection.write(body)
                sent += len(body)
            await connection.drain()
            if not message.get("more_body", False):
                break
        if framing == "chunked":
            connection.write(b"0\r\n\r\n")
            await connection.drain()
            return
        try:
            announced = int(utils.get_header(scope["headers"], b"content-length") or 0)
        except ValueError:
            announced = -1
        if sent != announced:
            # The announced length is what frames the upstream request: a short
            # body would leave the upstream waiting or desync the next request.
            raise ProxyProtocolError("the client sent %d of the %d announced body bytes" % (sent, announced))

    # Upstream connection pool
    async def _connect(self, reuse: bool = True) -> tuple[UpstreamConnection, bool]:
        """
        Return a live connection to the upstream and whether it was pooled.

        ``reuse=False`` forces a fresh connection: a tunnel replaces the whole
        connection with frames, so it must not take one out of the pool.

        There is no separate connect timeout: ``request_timeout`` bounds the
        whole request, and the watchdog of the client connection is what resets
        it, so a connect that a listener never answers cannot hang either side.
        The wait here only keeps a pooled connection from being held forever if
        the server somehow outlives every timeout.
        """
        loop = asyncio.get_running_loop()
        while reuse and self._idle:
            connection, stamp = self._idle.popleft()
            if not connection.reusable() or loop.time() - stamp > IDLE_TIMEOUT:
                connection.close()
                continue
            return connection, True
        timeout = self.config.request_timeout or 30.0
        try:
            transport, connection = await asyncio.wait_for(loop.create_connection(lambda: UpstreamConnection(self.config.max_header_size), self.host, self.port), timeout=timeout)
        except asyncio.TimeoutError:
            raise OSError("connecting to %s took longer than %.1fs" % (self.authority, timeout)) from None
        return connection, False

    def _release(self, connection: UpstreamConnection, reusable: bool) -> None:
        """Return a healthy connection to the pool, close anything else."""
        if reusable and connection.reusable() and len(self._idle) < MAX_IDLE:
            try:
                self._idle.append((connection, asyncio.get_running_loop().time()))
            except RuntimeError:  # pragma: no cover - the loop is running here
                connection.close()
            return
        connection.close()

    def _close_idle(self) -> None:
        while self._idle:
            connection, _ = self._idle.popleft()
            connection.close()

    # Upstream response
    async def _read_head(self, connection: UpstreamConnection, method: str, allow_upgrade: bool = False) -> tuple[int, Headers, bytes, str]:
        """
        Read the upstream response head.

        Returns ``(status, headers, version, framing)`` where *framing* is
        ``length``, ``chunked``, ``eof`` or ``none`` (a response without a
        body).  Informational responses are skipped: the client sees the final
        answer only.  ``101`` is only expected - and only returned - while a
        WebSocket handshake is being repeated.

        The head is validated as it is read: a status outside 100-599, a header
        field that is not a token, or more fields than ``max_header_count`` are
        a broken upstream, not something to pass on to a client.  Header names
        and values are copied into ``bytes`` here, once, because the ASGI layer
        requires them - the body is never copied.
        """
        while True:
            raw = await connection.read_line_block(b"\r\n\r\n", self.config.max_header_size)
            lines = raw[:-4].split(b"\r\n")
            parts = lines[0].split(b" ", 2)
            if len(parts) < 2 or not parts[0].startswith(b"HTTP/1."):
                raise ProxyProtocolError("malformed upstream status line")
            if not parts[1].isdigit() or not 100 <= int(parts[1]) <= 599:
                raise ProxyProtocolError("the upstream status code is out of range")
            status = int(parts[1])
            if len(lines) - 1 > self.config.max_header_count:
                raise ProxyProtocolError("the upstream answer has too many header fields")

            headers: Headers = []
            for line in lines[1:]:
                name, separator, value = line.partition(b":")
                if not separator:
                    raise ProxyProtocolError("malformed upstream header field")
                field = bytes(name.strip()).lower()
                if not _TOKEN_RE.match(field):
                    raise ProxyProtocolError("malformed upstream header field name")
                if field == b"content-length":
                    # Only DIGITs (RFC 9110 section 8.6): a value like "-5" or
                    # "5, 5" would be re-framed here and mis-read downstream.
                    if not bytes(value.strip()).isdigit():
                        raise ProxyProtocolError("the upstream announced a malformed content-length")
                headers.append((field, bytes(value.strip())))

            lengths = [value for field, value in headers if field == b"content-length"]
            if len(lengths) > 1:
                if len(set(lengths)) > 1:
                    raise ProxyProtocolError("the upstream answered with conflicting content-length fields")
                # Identical duplicates are collapsed: the client must not see
                # the field twice (RFC 9110 section 8.6).
                headers = [(field, value) for field, value in headers if field != b"content-length"]
                headers.append((b"content-length", lengths[0]))

            if 100 <= status < 200:
                if status == 101:
                    if allow_upgrade:
                        return status, headers, bytes(parts[0]), "none"
                    raise ProxyProtocolError("unexpected upgrade from the upstream")
                self.logger.debug("Ignoring the %d answer of %s", status, self.authority)
                continue
            return status, headers, bytes(parts[0]), self._response_framing(method, status, headers)

    @staticmethod
    def _response_framing(method: str, status: int, headers: Headers) -> str:
        """How the upstream framed its response body."""
        if not utils.response_has_body(method, status):
            return "none"
        encoding = (utils.get_header(headers, b"transfer-encoding") or b"").lower()
        if b"chunked" in encoding:
            # Transfer-Encoding wins over Content-Length (RFC 9112 section 6.3).
            return "chunked"
        if utils.get_header(headers, b"content-length") is not None:
            return "length"
        return "eof"

    @staticmethod
    def _is_reusable(headers: Headers, version: bytes, framing: str) -> bool:
        """Whether the upstream connection may serve another request."""
        if framing == "eof":
            return False
        connection = (utils.get_header(headers, b"connection") or b"").lower()
        if version == b"HTTP/1.0":
            return b"keep-alive" in connection
        return b"close" not in connection

    async def _relay(self, scope: dict[str, object], connection: UpstreamConnection, status: int, headers: Headers, framing: str, send: Callable) -> None:
        """
        Send the upstream answer to the client, streaming its body.

        Anything that goes wrong once the head is on the wire is raised as
        :class:`echocorn.utils.ResponseAborted`: the writer then drops the
        framing instead of terminating it, so the client cannot mistake a
        truncated answer for a whole one.
        """
        content_length = utils.get_header(headers, b"content-length")
        limit = self.config.max_response_size
        # A bodyless answer keeps its announced length only where the protocol
        # allows it: a HEAD or 304 response keeps it (RFC 9110 section 9.3.2),
        # while one whose framing changed on this hop may not repeat it.
        bodyless_drops = utils.bodyless_header_drops(scope["method"], status)
        # Trailers are only relayed where the client's protocol can carry them,
        # and only when the upstream announced a trailer section.
        supports_trailers = scope.get("http_version") != "1.0"
        announced = trailer_names(headers) if framing == "chunked" else []
        trailers_expected = supports_trailers and bool(announced)
        if announced and not supports_trailers:
            self.logger.debug("Dropping the trailer section of %s: HTTP/1.0 cannot carry one", self.authority)

        forwarded: Headers = []
        for name, value in headers:
            if name in _DROP_RESPONSE_HEADERS:
                # Rebuilt below from the trailer fields that actually arrive.
                continue
            if name == b"content-length" and framing != "length" and b"content-length" in bodyless_drops:
                continue
            forwarded.append((name, value))
        if trailers_expected:
            forwarded.append((b"trailer", b", ".join(announced)))

        # The answer is refused before it starts when it is bigger than the
        # configured limit, so the client gets a reason instead of a cut body.
        remaining = 0
        if framing == "length":
            try:
                remaining = max(0, int(content_length or b"0"))
            except ValueError:
                raise ProxyProtocolError("malformed upstream content-length") from None
            if limit and remaining > limit:
                raise ProxyProtocolError("the upstream answer announces %d bytes, over max_response_size (%d)" % (remaining, limit))

        await send({"type": "http.response.start", "status": status, "headers": forwarded, "trailers": trailers_expected})

        trailers: list[tuple[bytes, bytes]] = []
        try:
            if framing == "none":
                await send({"type": "http.response.body", "body": b"", "more_body": False})
                return
            if framing == "length":
                await self._stream_length(connection, remaining, send, limit)
            elif framing == "chunked":
                trailers = await self._stream_chunked(connection, send, limit)
            else:
                await self._stream_until_eof(connection, send, limit)
        except ProxyProtocolError as exc:
            # The head is out, so a 502 is no longer possible: the framing is
            # abandoned and the client sees the answer was cut short.
            raise utils.ResponseAborted(str(exc)) from exc
        except OSError as exc:
            raise utils.ResponseAborted("the upstream connection failed mid-answer (%s)" % exc) from exc

        # The terminal body message comes first, then the trailer block: that
        # is the order the writers expect (an announced trailer section is
        # opened by ending the body) and what an application would send.
        await send({"type": "http.response.body", "body": b"", "more_body": False})
        if trailers_expected:
            await send({"type": "http.response.trailers", "headers": trailers, "more_trailers": False})

    async def _stream_length(self, connection: UpstreamConnection, remaining: int, send: Callable, limit: int) -> None:
        sent = 0
        while remaining > 0:
            data = await connection.read(min(remaining, CHUNK_SIZE))
            if not data:
                raise ProxyProtocolError("the upstream closed in the middle of its body")
            remaining -= len(data)
            sent += len(data)
            if limit and sent > limit:
                raise ProxyProtocolError("the upstream answer passed max_response_size (%d bytes)" % limit)
            await send({"type": "http.response.body", "body": data, "more_body": True})

    async def _stream_chunked(self, connection: UpstreamConnection, send: Callable, limit: int) -> list[tuple[bytes, bytes]]:
        """Relay a chunked body and return the trailer fields it ended with."""
        decoder = ChunkedDecoder()
        buffer = bytearray()
        sent = 0
        # Either the decoder consumes part of the buffer (and the rest of it is
        # looked at again) or more bytes are read. A partial chunk-size or
        # trailer line must never leave the loop spinning on the same bytes:
        # that would freeze the whole event loop, which is a denial of service
        # a broken upstream could trigger on purpose.
        while not decoder.done:
            if buffer:
                before = len(buffer)
                try:
                    chunks = decoder.feed(buffer, 0)
                except _ProtocolError as exc:
                    raise ProxyProtocolError("malformed chunked body from the upstream: %s" % exc) from None
                for chunk in chunks:
                    sent += len(chunk)
                    if limit and sent > limit:
                        raise ProxyProtocolError("the upstream answer passed max_response_size (%d bytes)" % limit)
                    await send({"type": "http.response.body", "body": chunk, "more_body": True})
                if len(buffer) < before:
                    continue
            data = await connection.read(CHUNK_SIZE)
            if not data:
                raise ProxyProtocolError("the upstream closed in the middle of its body")
            buffer.extend(data)
        return [(bytes(name), bytes(value)) for name, value in decoder.trailers]

    async def _stream_until_eof(self, connection: UpstreamConnection, send: Callable, limit: int) -> None:
        sent = 0
        while True:
            data = await connection.read(CHUNK_SIZE)
            if not data:
                return
            sent += len(data)
            if limit and sent > limit:
                raise ProxyProtocolError("the upstream answer passed max_response_size (%d bytes)" % limit)
            await send({"type": "http.response.body", "body": data, "more_body": True})

    async def _fail(self, send: Callable, reason: str) -> None:
        """Answer with ``502`` when the upstream could not be reached or answered."""
        body = ("502 Bad Gateway\n%s\n" % reason).encode("latin-1", "replace")
        try:
            await send({"type": "http.response.start", "status": 502, "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode("ascii"))]})
            await send({"type": "http.response.body", "body": body, "more_body": False})
        except Exception:
            # The response had already started: the server closes the client
            # connection because the announced length can no longer be met.
            pass
