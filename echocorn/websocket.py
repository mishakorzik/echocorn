"""
WebSocket support (RFC 6455) for HTTP/1.1 connections.

:mod:`echocorn.http1` detects the upgrade request and hands the connection over
to :class:`WebSocketSession`, which owns it from the ``101 Switching Protocols``
response until the close handshake finishes. The session implements the ASGI
``websocket`` protocol: the application receives ``websocket.connect``, accepts
(or rejects) the handshake, then exchanges ``websocket.receive`` /
``websocket.send`` messages until either side closes.

Frames are validated strictly: reserved bits and non-minimal length encodings
are protocol errors, client frames must be masked, control frames must be
unfragmented and short, payloads are unmasked in bulk, a completed text message
is validated as UTF-8 and messages are capped by
:attr:`~echocorn.config.ServerConfig.max_websocket_message_size`.

Because the server does not advertise ``SETTINGS_ENABLE_CONNECT_PROTOCOL``
(RFC 8441, WebSocket over HTTP/2), clients negotiating ``h2`` with ALPN still
open a separate HTTP/1.1 connection for WebSocket upgrades, which is the
behaviour every browser implements.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import logging
from collections.abc import Callable, Iterable

from . import utils
from .config import ServerConfig

__all__ = [
    "FrameParser",
    "WebSocketError",
    "WebSocketSession",
    "accept_key",
    "build_close_frame",
    "build_frame",
    "subprotocols",
    "valid_key",
    "wants_websocket",
]

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OPCODE_CONTINUATION = 0x0
OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA

_FIN = 0x80
_MASK = 0x80
_MAX_CONTROL_PAYLOAD = 125

CLOSE_NORMAL = 1000
CLOSE_GOING_AWAY = 1001
#: Reported when the connection went away without a close handshake.
CLOSE_ABNORMAL = 1006
CLOSE_PROTOCOL_ERROR = 1002
CLOSE_INVALID_PAYLOAD = 1007
CLOSE_TOO_BIG = 1009
CLOSE_INTERNAL_ERROR = 1011

#: Codes a peer may legitimately send in a close frame (RFC 6455 section 7.4).
_ACCEPTED_CLOSE_CODES = frozenset(
    {
        1000,
        1001,
        1002,
        1003,
        1007,
        1008,
        1009,
        1010,
        1011,
        1012,
        1013,
        1014
    }
)


class WebSocketError(Exception):
    """A protocol violation; carries the close code to reply with."""

    def __init__(self, code: int, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


def accept_key(key: bytes) -> bytes:
    """Return the ``Sec-WebSocket-Accept`` value for a client key."""
    return base64.b64encode(hashlib.sha1(key + GUID).digest())


def valid_key(key: bytes) -> bool:
    """True when ``key`` is a base64 encoded 16 byte nonce (RFC 6455 section 4.2)."""
    try:
        return len(base64.b64decode(key, validate=True)) == 16
    except (binascii.Error, ValueError):
        return False


def build_close_frame(code: int, reason: str = "", mask: bytes | None = None) -> bytes:
    """Serialise a close frame, with or without a mask key."""
    return build_frame(OPCODE_CLOSE, _close_payload(code, reason), mask=mask)


def build_frame(opcode: int, payload: bytes = b"", fin: bool = True, mask: bytes | None = None) -> bytes:
    """Serialise one frame. Server frames are not masked (RFC 6455 section 5.3)."""
    header = bytearray()
    header.append((_FIN if fin else 0) | opcode)
    length = len(payload)
    mask_bit = _MASK if mask else 0
    if length < 126:
        header.append(mask_bit | length)
    elif length < 65536:
        header.append(mask_bit | 126)
        header.extend(length.to_bytes(2, "big"))
    else:
        header.append(mask_bit | 127)
        header.extend(length.to_bytes(8, "big"))
    if mask:
        header.extend(mask)
        payload = _mask_payload(payload, mask)
    return header + payload


def _mask_payload(payload: bytes, mask: bytes) -> bytes:
    """XOR ``payload`` with the repeated 4 byte ``mask`` in one pass."""
    length = len(payload)
    if not length:
        return payload
    repeated = mask * (length // 4) + mask[: length % 4]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(repeated, "big")).to_bytes(length, "big")


def wants_websocket(headers: Iterable[tuple[bytes, bytes]]) -> bool:
    """True when the request asks for an ``Upgrade: websocket`` handshake."""
    upgrade = False
    connection_upgrade = False
    for name, value in headers:
        lowered = name.lower()
        if lowered == b"upgrade":
            if any(token.strip().lower() == b"websocket" for token in value.split(b",")):
                upgrade = True
        elif lowered == b"connection":
            if any(token.strip().lower() == b"upgrade" for token in value.split(b",")):
                connection_upgrade = True
    return upgrade and connection_upgrade


def subprotocols(headers: Iterable[tuple[bytes, bytes]]) -> list[str]:
    """Return the ``Sec-WebSocket-Protocol`` offers in client preference order."""
    offers: list[str] = []
    for name, value in headers:
        if name.lower() != b"sec-websocket-protocol":
            continue
        for token in value.split(b","):
            token = token.strip()
            if token:
                offers.append(token.decode("latin-1"))
    return offers


def _close_payload(code: int, reason: str = "") -> bytes:
    return code.to_bytes(2, "big") + reason.encode("utf-8", "replace")


def _parse_close(payload: bytes) -> tuple[int, str]:
    if not payload:
        return 1005, ""  # "no status received" (RFC 6455 section 7.1.5)
    if len(payload) == 1:
        raise WebSocketError(CLOSE_PROTOCOL_ERROR, "close frame with a 1 byte payload")
    code = int.from_bytes(payload[:2], "big")
    if not (code in _ACCEPTED_CLOSE_CODES or 3000 <= code <= 4999):
        raise WebSocketError(CLOSE_PROTOCOL_ERROR, "invalid close code %d" % code)
    try:
        reason = payload[2:].decode("utf-8")
    except UnicodeDecodeError:
        raise WebSocketError(CLOSE_INVALID_PAYLOAD, "close reason is not UTF-8") from None
    return code, reason


def _parse_frame(buffer: bytearray, max_payload: int, require_mask: bool = True) -> tuple[bool, int, bytes] | None:
    """
    Parse one frame out of ``buffer``; ``None`` when it is incomplete.

    ``require_mask`` says which side of the connection the frames come from:
    a client must mask (and is rejected when it does not), a server must not
    (the reverse proxy reads those frames when it forwards a session).
    """
    if len(buffer) < 2:
        return None
    first, second = buffer[0], buffer[1]
    if first & 0x70:
        raise WebSocketError(CLOSE_PROTOCOL_ERROR, "reserved bits must be zero")
    fin = bool(first & _FIN)
    opcode = first & 0x0F
    masked = bool(second & _MASK)
    length = second & 0x7F
    offset = 2

    if length == 126:
        if len(buffer) < 4:
            return None
        length = int.from_bytes(buffer[2:4], "big")
        if length < 126:
            raise WebSocketError(CLOSE_PROTOCOL_ERROR, "non-minimal length encoding")
        offset = 4
    elif length == 127:
        if len(buffer) < 10:
            return None
        length = int.from_bytes(buffer[2:10], "big")
        if length < 65536 or length > 2**63 - 1:
            raise WebSocketError(CLOSE_PROTOCOL_ERROR, "invalid 64 bit length")
        offset = 10

    if opcode >= 0x8:
        if not fin:
            raise WebSocketError(CLOSE_PROTOCOL_ERROR, "fragmented control frame")
        if length > _MAX_CONTROL_PAYLOAD:
            raise WebSocketError(CLOSE_PROTOCOL_ERROR, "oversized control frame")
    elif length > max_payload:
        # Reject before allocating: a peer must not be able to make us buffer a
        # huge frame just by declaring its size.
        raise WebSocketError(CLOSE_TOO_BIG, "message too large")

    if require_mask:
        if not masked:
            raise WebSocketError(CLOSE_PROTOCOL_ERROR, "client frames must be masked")
    elif masked:
        raise WebSocketError(CLOSE_PROTOCOL_ERROR, "server frames must not be masked")
    if opcode not in (OPCODE_CONTINUATION, OPCODE_TEXT, OPCODE_BINARY, OPCODE_CLOSE, OPCODE_PING, OPCODE_PONG):
        raise WebSocketError(CLOSE_PROTOCOL_ERROR, "unknown opcode 0x%x" % opcode)

    mask_size = 4 if masked else 0
    end = offset + mask_size + length
    if len(buffer) < end:
        return None
    payload = buffer[offset + mask_size : end]
    if masked:
        payload = _mask_payload(payload, buffer[offset : offset + 4])
    del buffer[:end]
    return fin, opcode, payload


class FrameParser:
    """Turns a byte buffer into messages and control events."""

    __slots__ = ("_max", "_masked", "_opcode", "_payload")

    def __init__(self, max_message_size: int, require_mask: bool = True) -> None:
        self._max = max_message_size
        self._masked = require_mask
        self._opcode: int | None = None
        self._payload = bytearray()

    def feed(self, buffer: bytearray) -> list[tuple[str, object]]:
        """
        Consume every complete frame in ``buffer`` and return its events.

        Returns a list of ``(kind, value)`` pairs where *kind* is one of
        ``text``, ``bytes``, ``ping``, ``pong`` or ``close``.
        """
        events: list[tuple[str, object]] = []
        while True:
            frame = _parse_frame(buffer, self._max, self._masked)
            if frame is None:
                return events
            fin, opcode, payload = frame

            if opcode == OPCODE_CLOSE:
                events.append(("close", _parse_close(payload)))
                continue
            if opcode == OPCODE_PING:
                events.append(("ping", payload))
                continue
            if opcode == OPCODE_PONG:
                events.append(("pong", payload))
                continue
            if opcode == OPCODE_CONTINUATION:
                if self._opcode is None:
                    raise WebSocketError(CLOSE_PROTOCOL_ERROR, "continuation without a data frame")
            else:
                if self._opcode is not None:
                    raise WebSocketError(CLOSE_PROTOCOL_ERROR, "new data frame inside a fragmented message")
                self._opcode = opcode
                self._payload = bytearray()

            if len(self._payload) + len(payload) > self._max:
                raise WebSocketError(CLOSE_TOO_BIG, "message too large")
            self._payload.extend(payload)

            if not fin:
                continue

            text = self._opcode == OPCODE_TEXT
            self._opcode = None
            if text:
                try:
                    events.append(("text", self._payload.decode("utf-8")))
                except UnicodeDecodeError:
                    raise WebSocketError(CLOSE_INVALID_PAYLOAD, "text message is not valid UTF-8") from None
            else:
                events.append(("bytes", self._payload))


class WebSocketSession:
    """Drives one WebSocket connection until the close handshake completes."""

    def __init__(self, app: Callable, config: ServerConfig, logger: logging.Logger, transport: asyncio.Transport, buffer: bytearray, data_event: asyncio.Event, scope: dict[str, object], key: bytes, write: Callable[[bytes], object], pause_reading: Callable[[], None], resume_reading: Callable[[], None]) -> None:
        self.app = app
        self.config = config
        self.logger = logger
        self.transport = transport
        self.scope = scope
        self._buffer = buffer
        self._data_event = data_event
        self._key = key
        self._write = write
        self._pause = pause_reading
        self._resume = resume_reading

        self._parser = FrameParser(config.max_websocket_message_size)
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=16)
        self._queue.put_nowait({"type": "websocket.connect"})
        self._accepted = asyncio.Event()
        self._finished = asyncio.Event()
        self._app_task: asyncio.Task | None = None
        self._reader_task: asyncio.Task | None = None
        self._read_paused = False
        self._closed = False
        self._closing = asyncio.Event()
        self._accepted_handshake = False
        self._close_sent = False
        self._rejecting = False
        self._rejected = False
        self._reject_started = False
        self._close_code = CLOSE_ABNORMAL
        self._reject_status = 403
        self._messages = 0

    @property
    def tasks(self) -> tuple[asyncio.Task | None, ...]:
        """The tasks this session owns, so the connection can cancel them."""
        return (self._app_task, self._reader_task)

    @property
    def closed(self) -> bool:
        """True once the close handshake finished or the session was torn down."""
        return self._closed

    @property
    def accepted(self) -> bool:
        """True once the ``101 Switching Protocols`` handshake went out."""
        return self._accepted_handshake

    @property
    def messages(self) -> int:
        """How many messages the peer sent during this session."""
        return self._messages

    @property
    def status(self) -> int | None:
        """
        What to report in the access log.

        The WebSocket close code once the handshake was accepted, the HTTP
        status when the application refused the handshake, or ``None`` when the
        connection was dropped before the server answered anything.
        """
        if self._rejected:
            return self._reject_status
        if self._accepted_handshake:
            return self._close_code
        return None

    def _mark_closed(self) -> None:
        """Record that the connection is over, waking :meth:`run`."""
        self._closed = True
        self._closing.set()

    async def run(self) -> None:
        """Serve the connection: handshake, then messages until close."""
        self._app_task = asyncio.ensure_future(self._guard_app())
        if not await self._await_handshake():
            await self._cleanup()
            return
        self._reader_task = asyncio.ensure_future(self._read_loop())
        try:
            await self._wait_for_app()
        finally:
            await self._cleanup()

    async def _wait_for_app(self) -> None:
        """
        Wait for the application, bounded once the close handshake is over.

        A well behaved application returns as soon as it is told the connection
        is gone. One that keeps running anyway must not hold the socket (and
        the connection slot) forever, so once the connection has closed it only
        gets :attr:`graceful_timeout` to notice before it is cancelled.
        """
        finished = asyncio.ensure_future(self._finished.wait())
        closing = asyncio.ensure_future(self._closing.wait())
        try:
            await asyncio.wait({finished, closing}, return_when=asyncio.FIRST_COMPLETED)
            if finished.done():
                return
            try:
                await asyncio.wait_for(finished, timeout=self.config.graceful_timeout)
            except asyncio.TimeoutError:
                self.logger.warning("Dropping a WebSocket application that ignored the close")
        finally:
            finished.cancel()
            closing.cancel()

    async def close_with(self, code: int, reason: str = "") -> None:
        """
        Tell the peer to go away and end the session.

        Used by the server on shutdown, so clients see a close frame
        (``1001``) instead of a socket that simply disappears.
        """
        if self._closed:
            return
        await self._send_close(code, reason)
        self._mark_closed()
        await self._deliver({"type": "websocket.disconnect", "code": code})

    async def _await_handshake(self) -> bool:
        """Wait for ``websocket.accept`` (or a rejection) from the application."""
        timeout = self.config.request_timeout
        try:
            if timeout > 0:
                await asyncio.wait_for(self._accepted.wait(), timeout=timeout)
            else:
                await self._accepted.wait()
        except asyncio.TimeoutError:
            self.logger.warning("WebSocket application did not answer the handshake within %.1fs", timeout)
            self._mark_closed()
            self.transport.abort()
            return False
        return self._accepted_handshake

    async def _guard_app(self) -> None:
        try:
            await self.app(self.scope, self._receive, self._send)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("Unhandled error in the WebSocket application")
            if self._accepted_handshake and not self._close_sent:
                await self._send_close(CLOSE_INTERNAL_ERROR, "application error")
        finally:
            if self._reject_started and not self._closed:
                # The application began an error response but never finished it;
                # end it here so the peer is not left waiting for the body.
                self._mark_closed()
                self._accepted.set()
            self._finished.set()

    async def _read_loop(self) -> None:
        try:
            while not self._closed:
                # Cleared before parsing, so bytes that arrive while the
                # application is being served set the event again instead of
                # being lost. A partial frame leaves the buffer untouched, so
                # the loop must wait here rather than spin on it.
                self._data_event.clear()
                try:
                    events = self._parser.feed(self._buffer)
                except WebSocketError as exc:
                    await self._fail(exc.code, exc.reason)
                    return
                if not events:
                    await self._data_event.wait()
                    continue
                for kind, value in events:
                    await self._dispatch(kind, value)
                    if self._closed:
                        return
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("WebSocket reader failed")
            await self._fail(CLOSE_INTERNAL_ERROR, "internal error")

    async def _dispatch(self, kind: str, value: object) -> None:
        if kind == "ping":
            await self._write(build_frame(OPCODE_PONG, value))
            return
        if kind == "pong":
            return
        if kind == "close":
            code, reason = value
            self.logger.debug("WebSocket peer closed with code %d (%s)", code, reason)
            # Answer the close frame before anything else: the peer is waiting
            # for it (RFC 6455 section 5.5.1) and must not wait on the app.
            if not self._close_sent:
                await self._send_close(code if code != 1005 else CLOSE_NORMAL)
            # The peer's own code is what the access log should show.
            self._close_code = code
            self._mark_closed()
            await self._deliver({"type": "websocket.disconnect", "code": code})
            return
        self._messages += 1
        if kind == "text":
            await self._deliver({"type": "websocket.receive", "text": value})
        else:
            await self._deliver({"type": "websocket.receive", "bytes": value})

    async def _deliver(self, message: dict[str, object]) -> None:
        """Hand a message to the application, pausing the socket when it lags."""
        if self._queue.full() and not self._read_paused:
            self._read_paused = True
            self._pause()
        await self._queue.put(message)

    async def _receive(self) -> dict[str, object]:
        message = await self._queue.get()
        if self._read_paused and not self._queue.full():
            self._read_paused = False
            self._resume()
        return message

    async def _send(self, message: dict[str, object]) -> None:
        if not isinstance(message, dict):
            raise TypeError("ASGI message must be a dict, got %r" % type(message))
        message_type = message.get("type")
        if message_type == "websocket.accept":
            await self._accept(message)
        elif message_type == "websocket.send":
            await self._send_data(message)
        elif message_type == "websocket.close":
            await self._close(message)
        elif message_type == "websocket.http.response.start":
            await self._reject_start(message)
        elif message_type == "websocket.http.response.body":
            await self._reject_body(message)
        else:
            self.logger.warning("Ignoring unknown ASGI message %r", message_type)

    async def _accept(self, message: dict[str, object]) -> None:
        if self._accepted_handshake:
            raise RuntimeError("websocket.accept has already been sent")
        headers = bytearray()
        headers.extend(b"HTTP/1.1 101 Switching Protocols\r\n")
        headers.extend(b"upgrade: websocket\r\n")
        headers.extend(b"connection: Upgrade\r\n")
        headers.extend(b"sec-websocket-accept: " + accept_key(self._key) + b"\r\n")
        headers.extend(b"server: " + utils.SERVER_HEADER.encode("latin-1") + b"\r\n")
        headers.extend(b"date: " + utils.format_http_date().encode("latin-1") + b"\r\n")
        chosen = message.get("subprotocol")
        if chosen:
            if chosen not in self.scope.get("subprotocols", []):
                raise RuntimeError("subprotocol %r was not offered by the client" % (chosen,))
            headers.extend(b"sec-websocket-protocol: " + chosen.encode("latin-1") + b"\r\n")
        headers.extend(b"\r\n")
        self._accepted_handshake = True
        await self._write(headers)
        self._accepted.set()

    async def _send_data(self, message: dict[str, object]) -> None:
        if not self._accepted_handshake:
            raise RuntimeError("websocket.send before websocket.accept")
        if self._closed:
            self.logger.debug("Dropping websocket.send after the connection closed")
            return
        data = message.get("bytes")
        if data is not None:
            if not isinstance(data, (bytes, bytearray)):
                raise TypeError("websocket.send 'bytes' must be bytes-like")
            await self._write(build_frame(OPCODE_BINARY, data))
            return
        text = message.get("text")
        if text is None:
            raise RuntimeError("websocket.send needs 'text' or 'bytes'")
        if not isinstance(text, str):
            raise TypeError("websocket.send 'text' must be str")
        await self._write(build_frame(OPCODE_TEXT, text.encode("utf-8")))

    async def _close(self, message: dict[str, object]) -> None:
        code = int(message.get("code", CLOSE_NORMAL))
        reason = str(message.get("reason", "") or "")
        if not self._accepted_handshake:
            # The application refused the handshake: answer with HTTP (ASGI spec).
            await self._reject()
            return
        if not self._close_sent:
            await self._send_close(code, reason)
        self._mark_closed()

    async def _reject(self) -> None:
        """Answer a refused handshake with ``403 Forbidden`` (ASGI spec)."""
        self._accepted_handshake = False
        self._rejected = True
        body = b"Forbidden"
        head = (
            b"HTTP/1.1 403 Forbidden\r\n"
            b"content-type: text/plain; charset=utf-8\r\n"
            b"content-length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"server: " + utils.SERVER_HEADER.encode("latin-1") + b"\r\n"
            b"date: " + utils.format_http_date().encode("latin-1") + b"\r\n"
            b"connection: close\r\n\r\n"
        )
        await self._write(head + body)
        self._accepted.set()

    async def _reject_start(self, message: dict[str, object]) -> None:
        """
        Begin an HTTP response to a refused handshake.

        This is the ``websocket.http.response`` ASGI extension, which lets a
        framework answer with something more useful than the fixed 403, for
        example a ``401`` with ``WWW-Authenticate`` or a JSON error page.
        """
        if self._accepted_handshake:
            raise RuntimeError("websocket.http.response.start after websocket.accept")
        if self._reject_started:
            raise RuntimeError("websocket.http.response.start has already been sent")
        status = int(message["status"])
        if not 200 <= status <= 599:
            raise ValueError("websocket.http.response.start needs a valid status")
        self._reject_started = True
        self._rejecting = True
        self._rejected = True
        self._reject_status = status
        headers = utils.normalize_response_headers(message.get("headers"), lowercase=False)
        has_length = any(name == b"content-length" for name, _ in headers)
        parts = [
            b"HTTP/1.1 ",
            str(status).encode("ascii"),
            b" ",
            utils.status_phrase(status).encode("latin-1"),
            b"\r\n",
        ]
        for name, value in headers:
            parts.append(name + b": " + value + b"\r\n")
        parts.append(b"server: " + utils.SERVER_HEADER.encode("latin-1") + b"\r\n")
        parts.append(b"date: " + utils.format_http_date().encode("latin-1") + b"\r\n")
        if not has_length:
            # The connection is closed after the error, so the body ends at the
            # close (RFC 9112 section 6.3) instead of being buffered or chunked.
            parts.append(b"connection: close\r\n")
        parts.append(b"\r\n")
        await self._write(b"".join(parts))

    async def _reject_body(self, message: dict[str, object]) -> None:
        """Send one chunk of the rejection body; the last one ends the session."""
        if not self._rejecting:
            raise RuntimeError("websocket.http.response.body before websocket.http.response.start")
        body = message.get("body", b"") or b""
        if not isinstance(body, (bytes, bytearray)):
            raise TypeError("websocket.http.response.body must be bytes-like")
        if body:
            await self._write(body)
        if message.get("more_body"):
            return
        self._accepted_handshake = False
        self._mark_closed()
        self._accepted.set()
        await self._deliver({"type": "websocket.disconnect", "code": 1006})

    async def _send_close(self, code: int, reason: str = "") -> None:
        if self._close_sent:
            return
        self._close_sent = True
        self._close_code = code
        try:
            await self._write(build_close_frame(code, reason))
        except Exception:
            pass

    async def _fail(self, code: int, reason: str) -> None:
        self.logger.debug("Closing WebSocket: %d %s", code, reason or "")
        await self._send_close(code, reason)
        self._mark_closed()
        await self._deliver({"type": "websocket.disconnect", "code": code})

    async def _cleanup(self) -> None:
        self._mark_closed()
        reader_task = self._reader_task
        if reader_task is not None and not reader_task.done():
            reader_task.cancel()
        app_task = self._app_task
        if app_task is not None and not app_task.done():
            # Give the application a moment to observe the disconnect.
            try:
                await asyncio.wait_for(asyncio.shield(app_task), timeout=self.config.graceful_timeout)
            except asyncio.TimeoutError:
                if not app_task.done():
                    app_task.cancel()
            except Exception:
                pass
        if not self._close_sent and self._accepted_handshake:
            # The application returned without closing, or the session was torn
            # down by the server: end the handshake with a normal closure.
            await self._send_close(CLOSE_NORMAL)
        self._buffer.clear()
