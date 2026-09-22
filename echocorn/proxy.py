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
from collections import deque
from typing import Any, Callable, Deque, Dict, Tuple

from . import utils
from . import websocket
from .config import ServerConfig
from .http1 import ChunkedDecoder, _ProtocolError
from .utils import HOP_BY_HOP_HEADERS, Headers

__all__ = ["ProxyApp", "ProxyProtocolError"]

#: How long an idle upstream connection stays in the pool before it is dropped.
IDLE_TIMEOUT = 30.0

#: How many idle connections to the upstream are kept for reuse.
MAX_IDLE = 16

#: Read size while streaming a body in either direction.
CHUNK_SIZE = 64 * 1024

#: How much of a refused handshake body is relayed back to the client.
REFUSAL_LIMIT = 8192

#: Response header fields that must not be repeated to the client: they either
#: describe this hop (``connection``, framing) or belong to the upstream link.
_DROP_RESPONSE_HEADERS = HOP_BY_HOP_HEADERS | frozenset({b"proxy-connection"})


class ProxyProtocolError(Exception):
    """The upstream answered with something that cannot be forwarded."""


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
        self._idle: Deque[Tuple[Any, Any, float]] = deque()
        # An IPv6 upstream needs its brackets back in the request line.
        name = "[%s]" % host if ":" in host else host
        self.authority = "%s:%d" % (name, port)

    # ASGI application
    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
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
    async def _websocket(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        """Repeat the handshake against the upstream, then tunnel the frames."""
        await receive()  # websocket.connect
        try:
            reader, writer = await self._connect(reuse=False)
        except (OSError, asyncio.TimeoutError) as exc:
            self.logger.warning("Cannot reach %s: %s", self.authority, exc)
            await self._refuse(send, 502, "Bad Gateway", "cannot reach %s" % self.authority)
            return

        try:
            key = base64.b64encode(os.urandom(16))
            writer.write(self._build_upgrade(scope, key))
            await writer.drain()
            status, headers, _version, framing = await self._read_head(reader, "GET", allow_upgrade=True)
            if status != 101:
                # The upstream refused the upgrade: relay its own answer, so a
                # client sees the same 401/403/404 it would have seen directly.
                body = await self._read_small_body(reader, headers, framing)
                await self._relay_refusal(send, status, headers, body)
                return
            if utils.get_header(headers, b"sec-websocket-accept") != websocket.accept_key(key):
                raise ProxyProtocolError("the upstream handshake is not a valid answer")
            await send(self._accept_message(scope, headers))
            await self._tunnel(reader, writer, receive, send)
        except websocket.WebSocketError as exc:
            self.logger.warning("Upstream %s broke the WebSocket protocol: %s", self.authority, exc)
            await self._close_client(send, websocket.CLOSE_PROTOCOL_ERROR)
        except ProxyProtocolError as exc:
            self.logger.warning("Upstream %s: %s", self.authority, exc)
            await self._refuse(send, 502, "Bad Gateway", str(exc))
        except (OSError, asyncio.IncompleteReadError) as exc:
            self.logger.warning("Upstream %s failed: %s", self.authority, exc)
            await self._refuse(send, 502, "Bad Gateway", "the upstream connection failed")
        finally:
            # A tunnel is never returned to the pool: it has no request left to
            # serve, it only carries frames.
            writer.close()

    @staticmethod
    def _accept_message(scope: Dict[str, Any], headers: Headers) -> Dict[str, Any]:
        """The ``websocket.accept`` for a session the upstream accepted."""
        message: Dict[str, Any] = {"type": "websocket.accept"}
        chosen = utils.get_header(headers, b"sec-websocket-protocol")
        if chosen is not None:
            name = chosen.decode("latin-1")
            # Only a protocol the client actually offered may be chosen.
            if name in scope.get("subprotocols", []):
                message["subprotocol"] = name
        return message

    def _build_upgrade(self, scope: Dict[str, Any], key: bytes) -> bytes:
        """Serialise the handshake that is sent to the upstream."""
        raw_path = scope.get("raw_path") or b"/"
        query = scope.get("query_string") or b""
        target = raw_path + (b"?" + query if query else b"")

        lines = [b"GET " + target + b" HTTP/1.1"]
        for name, value in scope["headers"]:
            lowered = name.lower()
            if lowered in HOP_BY_HOP_HEADERS or lowered == b"host":
                continue
            # The handshake of this hop is our own: our key, our version, and
            # no extension (an extension answer could not be forwarded anyway).
            if lowered in (b"sec-websocket-key", b"sec-websocket-version", b"sec-websocket-extensions"):
                continue
            lines.append(name + b": " + value)
        lines.append(b"host: " + self.authority.encode("latin-1"))
        lines.append(b"upgrade: websocket")
        lines.append(b"connection: Upgrade")
        lines.append(b"sec-websocket-key: " + key)
        lines.append(b"sec-websocket-version: 13")
        original_host = utils.get_header(scope["headers"], b"host")
        client = scope.get("client")
        if client:
            lines.append(b"x-forwarded-for: " + str(client[0]).encode("latin-1"))
        lines.append(b"x-forwarded-proto: " + str(scope.get("scheme", "ws")).encode("latin-1"))
        if original_host:
            lines.append(b"x-forwarded-host: " + original_host)
        return b"\r\n".join(lines) + b"\r\n\r\n"

    async def _tunnel(self, reader: Any, writer: Any, receive: Callable, send: Callable) -> None:
        """Forward frames in both directions until one side closes."""
        from_upstream = asyncio.ensure_future(self._from_upstream(reader, writer, send))
        from_client = asyncio.ensure_future(self._from_client(writer, receive, send))
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

    async def _from_client(self, writer: Any, receive: Callable, send: Callable) -> None:
        """Forward the messages of the client to the upstream (masked)."""
        while True:
            message = await receive()
            kind = message["type"]
            if kind == "websocket.receive":
                text = message.get("text")
                if text is not None:
                    frame = websocket.build_frame(websocket.OPCODE_TEXT, text.encode("utf-8"), mask=os.urandom(4))
                elif message.get("bytes") is not None:
                    frame = websocket.build_frame(websocket.OPCODE_BINARY, bytes(message["bytes"]), mask=os.urandom(4))
                else:
                    continue
                writer.write(frame)
                await writer.drain()
            elif kind == "websocket.disconnect":
                # 1005 and 1006 describe a missing close frame; neither may be
                # put on the wire (RFC 6455 section 7.4.1), so 1001 is sent.
                code = int(message.get("code") or websocket.CLOSE_NORMAL)
                if code in (1005, 1006):
                    code = websocket.CLOSE_GOING_AWAY
                writer.write(websocket.build_close_frame(code, mask=os.urandom(4)))
                await writer.drain()
                return
            else:
                return

    async def _from_upstream(self, reader: Any, writer: Any, send: Callable) -> None:
        """Forward the frames of the upstream to the client."""
        parser = websocket.FrameParser(self.config.max_websocket_message_size, require_mask=False)
        buffer = bytearray()
        while True:
            events = parser.feed(buffer)
            if not events:
                data = await reader.read(CHUNK_SIZE)
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
                    writer.write(websocket.build_frame(websocket.OPCODE_PONG, value, mask=os.urandom(4)))
                    await writer.drain()
                elif kind == "close":
                    code, reason = value
                    if code == 1005:  # "no status received"
                        code = websocket.CLOSE_NORMAL
                    await self._close_client(send, code, reason)
                    return

    @staticmethod
    async def _close_client(send: Callable, code: int, reason: str = "") -> None:
        """End the client session with the close frame of the upstream."""
        message: Dict[str, Any] = {"type": "websocket.close", "code": code}
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
            await send(
                {
                    "type": "websocket.http.response.start",
                    "status": status,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8")],
                }
            )
            await send({"type": "websocket.http.response.body", "body": body})
        except Exception:  # pragma: no cover - the handshake may be answered already
            pass

    async def _relay_refusal(self, send: Callable, status: int, headers: Headers, body: bytes) -> None:
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

    async def _read_small_body(self, reader: Any, headers: Headers, framing: str) -> bytes:
        """Read at most :data:`REFUSAL_LIMIT` bytes of a refusal body."""
        if framing == "none":
            return b""
        out = bytearray()
        if framing == "length":
            remaining = int(utils.get_header(headers, b"content-length") or 0)
            while remaining > 0 and len(out) < REFUSAL_LIMIT:
                data = await reader.read(min(remaining, CHUNK_SIZE))
                if not data:
                    break
                remaining -= len(data)
                out.extend(data)
            return bytes(out)
        if framing == "chunked":
            decoder = ChunkedDecoder()
            buffer = bytearray()
            while not decoder.done and len(out) < REFUSAL_LIMIT:
                if not buffer:
                    data = await reader.read(CHUNK_SIZE)
                    if not data:
                        break
                    buffer.extend(data)
                try:
                    chunks = decoder.feed(buffer, 0)
                except _ProtocolError:
                    break
                for chunk in chunks:
                    if len(out) >= REFUSAL_LIMIT:
                        break
                    out.extend(chunk)
            return bytes(out)
        while len(out) < REFUSAL_LIMIT:
            data = await reader.read(CHUNK_SIZE)
            if not data:
                break
            out.extend(data)
        return bytes(out)

    # One proxied request
    async def _http(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        try:
            reader, writer = await self._connect()
        except (OSError, asyncio.TimeoutError) as exc:
            self.logger.warning("Cannot reach %s: %s", self.authority, exc)
            await self._fail(send, "cannot reach %s" % self.authority)
            return

        reusable = False
        try:
            framing = self._request_framing(scope["headers"])
            writer.write(self._build_request(scope, framing))
            if framing == "none":
                await writer.drain()
            else:
                await self._forward_body(scope, framing, receive, writer)
            status, headers, version, body_framing = await self._read_head(reader, scope["method"])
            await self._relay(scope, reader, status, headers, body_framing, send)
            # Only a response that made it through whole leaves the connection
            # reusable; a truncated body would desync the next request on it.
            reusable = self._is_reusable(headers, version, body_framing)
        except ProxyProtocolError as exc:
            self.logger.warning("Upstream %s: %s", self.authority, exc)
            await self._fail(send, str(exc))
        except (OSError, asyncio.IncompleteReadError) as exc:
            self.logger.warning("Upstream %s failed: %s", self.authority, exc)
            await self._fail(send, "the upstream connection failed")
        finally:
            self._release(reader, writer, reusable)

    def _build_request(self, scope: Dict[str, Any], framing: str) -> bytes:
        """Serialise the client request as a plain HTTP/1.1 request."""
        raw_path = scope.get("raw_path") or b"/"
        query = scope.get("query_string") or b""
        target = raw_path + (b"?" + query if query else b"")

        lines = [b"%s %s HTTP/1.1" % (scope["method"].encode("latin-1"), target)]
        for name, value in scope["headers"]:
            lowered = name.lower()
            # The connection to the upstream is our own, and the authority is
            # replaced below, so neither field is copied.
            if lowered in HOP_BY_HOP_HEADERS or lowered == b"host":
                continue
            lines.append(name + b": " + value)
        lines.append(b"host: " + self.authority.encode("latin-1"))

        original_host = utils.get_header(scope["headers"], b"host")
        client = scope.get("client")
        if client:
            address = str(client[0]).encode("latin-1")
            lines.append(b"x-real-ip: " + address)
            lines.append(b"x-forwarded-for: " + address)
        lines.append(b"x-forwarded-proto: " + str(scope.get("scheme", "http")).encode("latin-1"))
        if original_host:
            lines.append(b"x-forwarded-host: " + original_host)
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

    async def _forward_body(self, scope: Dict[str, Any], framing: str, receive: Callable, writer: Any) -> None:
        """Stream the request body to the upstream as it arrives."""
        sent = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                raise ProxyProtocolError("the client went away")
            body = message.get("body") or b""
            if framing == "chunked":
                if body:
                    writer.write(b"%x\r\n" % len(body) + body + b"\r\n")
            elif body:
                writer.write(body)
                sent += len(body)
            await writer.drain()
            if not message.get("more_body", False):
                break
        if framing == "chunked":
            writer.write(b"0\r\n\r\n")
            await writer.drain()
            return
        announced = int(utils.get_header(scope["headers"], b"content-length") or 0)
        if sent != announced:
            # The announced length is what frames the upstream request: a short
            # body would leave the upstream waiting or desync the next request.
            raise ProxyProtocolError("the client sent %d of the %d announced body bytes" % (sent, announced))

    # Upstream connection pool
    async def _connect(self, reuse: bool = True) -> Tuple[Any, Any]:
        """
        Return a live connection to the upstream, reusing an idle one.

        ``reuse=False`` forces a fresh connection: a tunnel replaces the whole
        connection with frames, so it must not take one out of the pool.
        """
        loop = asyncio.get_running_loop()
        while reuse and self._idle:
            reader, writer, stamp = self._idle.popleft()
            if writer.is_closing() or reader.at_eof() or loop.time() - stamp > IDLE_TIMEOUT:
                writer.close()
                continue
            return reader, writer
        timeout = self.config.request_timeout or 30.0
        limit = max(CHUNK_SIZE, self.config.max_header_size)
        return await asyncio.wait_for(asyncio.open_connection(self.host, self.port, limit=limit), timeout=timeout)

    def _release(self, reader: Any, writer: Any, reusable: bool) -> None:
        """Return a healthy connection to the pool, close anything else."""
        if reusable and not writer.is_closing() and not reader.at_eof() and len(self._idle) < MAX_IDLE:
            self._idle.append((reader, writer, asyncio.get_running_loop().time()))
            return
        writer.close()

    def _close_idle(self) -> None:
        while self._idle:
            _, writer, _ = self._idle.popleft()
            writer.close()

    # Upstream response
    async def _read_head(self, reader: Any, method: str, allow_upgrade: bool = False) -> Tuple[int, Headers, bytes, str]:
        """
        Read the upstream response head.

        Returns ``(status, headers, version, framing)`` where *framing* is
        ``length``, ``chunked``, ``eof`` or ``none`` (a response without a
        body).  Informational responses are skipped: the client sees the final
        answer only.  ``101`` is only expected - and only returned - while a
        WebSocket handshake is being repeated.
        """
        while True:
            try:
                raw = await reader.readuntil(b"\r\n\r\n")
            except asyncio.LimitOverrunError:
                raise ProxyProtocolError("the upstream response head is too large") from None
            except asyncio.IncompleteReadError:
                raise ProxyProtocolError("the upstream closed without answering") from None
            if len(raw) - 4 > self.config.max_header_size:
                raise ProxyProtocolError("the upstream response head is too large")

            lines = raw[:-4].split(b"\r\n")
            parts = lines[0].split(b" ", 2)
            if len(parts) < 2 or not parts[0].startswith(b"HTTP/1."):
                raise ProxyProtocolError("malformed upstream status line")
            try:
                status = int(parts[1])
            except ValueError:
                raise ProxyProtocolError("malformed upstream status code") from None

            headers: Headers = []
            for line in lines[1:]:
                name, separator, value = line.partition(b":")
                if not separator:
                    raise ProxyProtocolError("malformed upstream header field")
                headers.append((name.strip().lower(), value.strip()))

            if 100 <= status < 200:
                if status == 101:
                    if allow_upgrade:
                        return status, headers, parts[0], "none"
                    raise ProxyProtocolError("unexpected upgrade from the upstream")
                self.logger.debug("Ignoring the %d answer of %s", status, self.authority)
                continue
            return status, headers, parts[0], self._response_framing(method, status, headers)

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

    async def _relay(self, scope: Dict[str, Any], reader: Any, status: int, headers: Headers, framing: str, send: Callable) -> None:
        """Send the upstream answer to the client, streaming its body."""
        content_length = utils.get_header(headers, b"content-length")
        # A bodyless answer keeps its announced length only where the protocol
        # allows it: a HEAD or 304 response keeps it (RFC 9110 section 9.3.2),
        # while one whose framing changed on this hop may not repeat it.
        bodyless_drops = utils.bodyless_header_drops(scope["method"], status)
        forwarded: Headers = []
        for name, value in headers:
            if name in _DROP_RESPONSE_HEADERS:
                continue
            if name == b"content-length" and framing != "length" and b"content-length" in bodyless_drops:
                continue
            forwarded.append((name, value))
        await send({"type": "http.response.start", "status": status, "headers": forwarded})

        if framing == "none":
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            return
        if framing == "length":
            try:
                remaining = max(0, int(content_length or b"0"))
            except ValueError:
                raise ProxyProtocolError("malformed upstream content-length") from None
            await self._stream_length(reader, remaining, send)
        elif framing == "chunked":
            await self._stream_chunked(reader, send)
        else:
            await self._stream_until_eof(reader, send)
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    async def _stream_length(self, reader: Any, remaining: int, send: Callable) -> None:
        while remaining > 0:
            data = await reader.read(min(remaining, CHUNK_SIZE))
            if not data:
                raise ProxyProtocolError("the upstream closed in the middle of its body")
            remaining -= len(data)
            await send({"type": "http.response.body", "body": data, "more_body": True})

    async def _stream_chunked(self, reader: Any, send: Callable) -> None:
        decoder = ChunkedDecoder()
        buffer = bytearray()
        while not decoder.done:
            if not buffer:
                data = await reader.read(CHUNK_SIZE)
                if not data:
                    raise ProxyProtocolError("the upstream closed in the middle of its body")
                buffer.extend(data)
            try:
                chunks = decoder.feed(buffer, 0)
            except _ProtocolError:
                raise ProxyProtocolError("malformed chunked body from the upstream") from None
            for chunk in chunks:
                await send({"type": "http.response.body", "body": chunk, "more_body": True})

    async def _stream_until_eof(self, reader: Any, send: Callable) -> None:
        while True:
            data = await reader.read(CHUNK_SIZE)
            if not data:
                return
            await send({"type": "http.response.body", "body": data, "more_body": True})

    async def _fail(self, send: Callable, reason: str) -> None:
        """Answer with ``502`` when the upstream could not be reached or answered."""
        body = ("502 Bad Gateway\n%s\n" % reason).encode("latin-1", "replace")
        try:
            await send(
                {
                    "type": "http.response.start",
                    "status": 502,
                    "headers": [
                        (b"content-type", b"text/plain; charset=utf-8"),
                        (b"content-length", str(len(body)).encode("ascii")),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body, "more_body": False})
        except Exception:
            # The response had already started: the server closes the client
            # connection because the announced length can no longer be met.
            pass
