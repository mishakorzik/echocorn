"""
HTTP/1.1 protocol handler implementing RFC 9110 and RFC 9112.

Design notes
------------
* One reader task per connection walks the receive buffer sequentially, so
  responses are always written in request order (RFC 9112 section 9.3.1).
* Request framing is validated strictly, which makes request smuggling
  impossible: ``Content-Length`` together with ``Transfer-Encoding``,
  conflicting duplicate lengths, unsupported transfer codings and obs-fold are
  all rejected.
* Bodies are streamed to the application with queue based backpressure, and the
  socket is paused whenever too much unread data is buffered.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import Callable
from urllib.parse import urlsplit

from . import utils
from . import websocket as ws
from .config import ServerConfig
from .ratelimit import RateLimiter, client_key, retry_after_seconds
from .utils import ASGIRequest, BodyAbandoned, Compressor, Headers

__all__ = ["CONNECTION_PREFACE", "HTTP11Handler", "ChunkedDecoder", "parse_request_head"]

#: RFC 9113 section 3.2 HTTP/2 connection preface (used for h2c detection).
CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

ALLOWED_METHODS = utils.ALLOWED_METHODS

_TOKEN_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_REQUEST_LINE_RE = re.compile(rb"^([!#$%&'*+\-.^_`|~0-9A-Za-z]+) ([^ ]+) HTTP/(1\.[01])$")

# The method alone, used to keep error responses HEAD safe.
_METHOD_RE = re.compile(rb"^([A-Za-z]+)[ \t]")

# RFC 9110 section 5.5: field values may not carry NUL, CR, LF or any other
# C0 control byte except horizontal tab. Rejecting them removes a whole class
# of log and header injection tricks.
_ILLEGAL_VALUE_RE = re.compile(rb"[\x00-\x08\x0a-\x1f\x7f]")

# A request target is a sequence of visible ASCII characters only.
_ILLEGAL_TARGET_RE = re.compile(rb"[\x00-\x20\x7f]")

# Framing numbers are digits and nothing else: RFC 9110 section 8.6 defines
# ``Content-Length`` as 1*DIGIT and RFC 9112 section 7.1 a chunk size as
# 1*HEXDIG. ``int()`` on its own is far more forgiving than the grammar - it
# accepts ``+5`` and even ``5_0`` - and every value it reads differently to a
# peer in front of us is a disagreement about where the body ends.
_CONTENT_LENGTH_RE = re.compile(rb"^[0-9]+$")
_CHUNK_SIZE_RE = re.compile(rb"^[0-9A-Fa-f]+$")

#: Pause reading from the socket above this many buffered bytes.
READ_HIGH_WATERMARK = 262144
#: Resume reading once the buffer drops below this.
READ_LOW_WATERMARK = 65536

#: Maximum number of unread body bytes we are willing to discard after the app
#: responded early. Beyond this the connection is closed instead of drained.
MAX_DRAIN_BYTES = 65536

MAX_CHUNK_LINE = 1024
MAX_TARGET_LENGTH = utils.MAX_TARGET_LENGTH

#: Trailer fields kept from a decoded body.  They belong to the message and are
#: handed to the caller that wants them (the proxy relays them); a request body
#: simply ignores them.  The cap is what keeps a peer from filling memory with
#: trailer fields nobody reads.
MAX_TRAILER_FIELDS = 64


class _ProtocolError(Exception):
    """A request could not be parsed; carries the status code to respond with."""

    def __init__(self, status: int, message: str = "", allow: str | None = None):
        super().__init__(message or str(status))
        self.status = status
        self.message = message
        self.allow = allow


class _ParsedHead:
    __slots__ = (
        "method",
        "target",
        "version",
        "headers",
        "content_length",
        "chunked",
        "keep_alive",
        "expect_continue",
        "host",
    )

    def __init__(self) -> None:
        self.method = b"GET"
        self.target = b"/"
        self.version = "1.1"
        self.headers: Headers = []
        self.content_length: int | None = None
        self.chunked = False
        self.keep_alive = True
        self.expect_continue = False
        self.host = b""


class ChunkedDecoder:
    """Incremental ``chunked`` transfer coding decoder (RFC 9112 section 7.1)."""

    __slots__ = ("state", "remaining", "done", "trailers")

    def __init__(self) -> None:
        self.state = "size"
        self.remaining = 0
        self.done = False
        #: Fields of the trailer section the body ended with (RFC 9110 section
        #: 6.5), lower cased, at most :data:`MAX_TRAILER_FIELDS` of them.
        self.trailers: list[tuple[bytes, bytes]] = []

    def feed(self, buffer: bytearray, max_size: int) -> list[bytes]:
        """Consume ``buffer`` in place and return the decoded body chunks."""
        chunks: list[bytes] = []
        while True:
            if self.state == "size":
                index = buffer.find(b"\r\n")
                if index == -1:
                    if len(buffer) > MAX_CHUNK_LINE:
                        raise _ProtocolError(400, "chunk size line too long")
                    return chunks
                line = buffer[:index]
                del buffer[: index + 2]
                line = line.split(b";", 1)[0].strip()
                if not line:
                    raise _ProtocolError(400, "empty chunk size")
                if _CHUNK_SIZE_RE.match(line) is None:
                    raise _ProtocolError(400, "invalid chunk size")
                size = int(line, 16)
                if max_size and size > max_size:
                    raise _ProtocolError(413, "payload too large")
                if size == 0:
                    self.state = "trailer"
                else:
                    self.remaining = size
                    self.state = "data"
            elif self.state == "data":
                take = min(len(buffer), self.remaining)
                if take:
                    chunks.append(buffer[:take])
                    del buffer[:take]
                    self.remaining -= take
                if self.remaining:
                    return chunks
                if len(buffer) < 2:
                    return chunks
                if buffer[:2] != b"\r\n":
                    raise _ProtocolError(400, "malformed chunk terminator")
                del buffer[:2]
                self.state = "size"
            else:  # trailer
                while True:
                    index = buffer.find(b"\r\n")
                    if index == -1:
                        if len(buffer) > MAX_CHUNK_LINE:
                            raise _ProtocolError(400, "trailer line too long")
                        return chunks
                    line = buffer[:index]
                    del buffer[: index + 2]
                    if not line:
                        self.done = True
                        return chunks
                    if line[0] in (0x20, 0x09) or b":" not in line:
                        raise _ProtocolError(400, "malformed trailer field")
                    if len(self.trailers) < MAX_TRAILER_FIELDS:
                        name, _, value = line.partition(b":")
                        self.trailers.append((bytes(name.strip().lower()), bytes(value.strip())))


def parse_request_head(buffer: bytearray, config: ServerConfig) -> _ParsedHead | None:
    """
    Parse a complete request head out of ``buffer``.

    Returns ``None`` when more data is required, otherwise consumes the head
    and returns the parsed result. Raises :class:`_ProtocolError` for anything
    that must be rejected.

    The head is read straight out of ``buffer``, so the header names and values
    it hands out are slices of that ``bytearray`` - no copy is made for a
    request that is going to be parsed once. They compare like ``bytes`` but a
    ``bytearray`` is unhashable, so they must be matched with ``in`` on a tuple
    (or with :func:`echocorn.utils.has_header`) and never looked up in a set.
    """
    index = buffer.find(b"\r\n\r\n")
    if index == -1:
        if len(buffer) > config.max_header_size:
            raise _ProtocolError(431, "request head too large")
        return None
    if index + 4 > config.max_header_size:
        raise _ProtocolError(431, "request head too large")

    lines = buffer[:index].split(b"\r\n")

    match = _REQUEST_LINE_RE.match(lines[0])
    if match is None:
        raise _ProtocolError(400, "malformed request line")
    method, target, version = match.groups()
    if len(target) > MAX_TARGET_LENGTH:
        raise _ProtocolError(414, "URI too long")
    if _ILLEGAL_TARGET_RE.search(target):
        raise _ProtocolError(400, "illegal character in request target")
    if method not in ALLOWED_METHODS:
        allow = ", ".join(sorted(m.decode("ascii") for m in ALLOWED_METHODS))
        raise _ProtocolError(405, "method not allowed", allow=allow)

    head = _ParsedHead()
    head.method = method
    head.target = target
    head.version = version.decode("ascii")
    head.keep_alive = head.version == "1.1"
    # HTTP/1.0 may only be reused when the authority is known, otherwise the
    # next request on the connection could be meant for another host.
    authority_known = bool(target.startswith((b"http://", b"https://")))

    content_lengths: list[int] = []
    transfer_encodings: list[bytes] = []
    connection_tokens: list[bytes] = []
    host_values: list[bytes] = []
    for header_count, line in enumerate(lines[1:], start=1):
        if not line:
            raise _ProtocolError(400, "empty header field")
        if line[0] in (0x20, 0x09):
            raise _ProtocolError(400, "obsolete line folding is not supported")
        name, sep, value = line.partition(b":")
        if not sep or _TOKEN_RE.match(name) is None:
            raise _ProtocolError(400, "malformed header field")
        value = value.strip(b" \t")
        if _ILLEGAL_VALUE_RE.search(value):
            raise _ProtocolError(400, "illegal character in header value")
        if header_count > config.max_header_count:
            raise _ProtocolError(431, "too many header fields")

        lowered = name.lower()
        head.headers.append((lowered, value))
        if lowered == b"content-length":
            if _CONTENT_LENGTH_RE.match(value) is None:
                raise _ProtocolError(400, "invalid content-length")
            content_lengths.append(int(value))
        elif lowered == b"transfer-encoding":
            transfer_encodings.extend(token.strip().lower() for token in value.split(b",") if token.strip())
        elif lowered == b"connection":
            connection_tokens.extend(token.strip().lower() for token in value.split(b",") if token.strip())
        elif lowered == b"host":
            host_values.append(value)
        elif lowered == b"expect":
            if value.lower() == b"100-continue":
                head.expect_continue = True
            else:
                raise _ProtocolError(417, "unsupported expectation")

    if len(host_values) > 1:
        raise _ProtocolError(400, "duplicate host header")
    if host_values:
        if not utils.valid_authority(host_values[0]):
            # RFC 9112 section 3.2: a Host field value that is not an authority
            # must be refused, not passed on to be routed (or cached, or logged)
            # by something that reads it differently.
            raise _ProtocolError(400, "invalid host header")
        head.host = host_values[0]
        authority_known = True
    elif head.version == "1.1":
        raise _ProtocolError(400, "missing host header")

    if target.startswith((b"http://", b"https://")):
        # RFC 9112 section 3.2.2: with an absolute-form request-target an origin
        # server MUST ignore the received Host field and use the authority of
        # the target instead.  Following that rule keeps this server and the hop
        # in front of it - which may well have routed on the target - agreeing
        # about the site the request is for, and the application must see the
        # same authority the routing used.  An absolute target without an
        # authority (``http:///path``) says nothing, so the Host field stands.
        authority = _target_authority(target)
        if authority is None:
            raise _ProtocolError(400, "malformed authority in request target")
        if authority:
            if not utils.valid_authority(authority):
                raise _ProtocolError(400, "invalid authority in request target")
            head.host = authority
            authority_known = True
            rewritten: Headers = []
            seen = False
            for name, value in head.headers:
                if name == b"host":
                    if seen:
                        continue
                    rewritten.append((b"host", authority))
                    seen = True
                else:
                    rewritten.append((name, value))
            if not seen:
                rewritten.append((b"host", authority))
            head.headers = rewritten

    if transfer_encodings:
        if head.version == "1.0":
            raise _ProtocolError(400, "transfer-encoding is not valid in h10")
        if content_lengths:
            # RFC 9112 section 6.1: the classic request smuggling vector.
            raise _ProtocolError(400, "both transfer-encoding and content-length present")
        if transfer_encodings.count(b"chunked") > 1:
            raise _ProtocolError(400, "chunked applied more than once")
        if transfer_encodings[-1] != b"chunked":
            raise _ProtocolError(400, "chunked must be the final transfer coding")
        if any(token != b"chunked" for token in transfer_encodings):
            raise _ProtocolError(501, "unsupported transfer coding")
        head.chunked = True
    elif content_lengths:
        if len(set(content_lengths)) > 1:
            raise _ProtocolError(400, "conflicting content-length values")
        length = content_lengths[0]
        if length < 0:
            raise _ProtocolError(400, "invalid content-length")
        if config.max_request_size and length > config.max_request_size:
            raise _ProtocolError(413, "payload too large")
        head.content_length = length

    if b"close" in connection_tokens:
        head.keep_alive = False
    elif b"keep-alive" in connection_tokens and (head.version == "1.1" or authority_known):
        head.keep_alive = True

    # Everything validated: only now is the head taken off the buffer, so a
    # rejection can still read the method back out of it.
    del buffer[: index + 4]
    return head


def _peek_method(buffer: bytes) -> bytes:
    """
    Best effort method extraction for error responses on a rejected head.

    :func:`parse_request_head` leaves the head in the buffer when it rejects a
    request, so a ``HEAD`` that was refused is still answered without a body.
    """
    end = buffer.find(b"\r\n")
    match = _METHOD_RE.match(buffer if end == -1 else buffer[:end])
    return match.group(1).upper() if match else b""


def _peek_target(buffer: bytes) -> str:
    """Best effort request target for the log of a rejected head."""
    end = buffer.find(b"\r\n")
    line = buffer if end == -1 else buffer[:end]
    parts = bytes(line).split(b" ")
    if len(parts) < 2:
        return ""
    return parts[1].decode("latin-1", "replace")


def _target_authority(target: bytes) -> bytes | None:
    """
    Return the authority (``host[:port]``) of an absolute-form request target.

    The authority is returned exactly as written, userinfo included: RFC 9112
    section 3.2.2 makes a target that carries userinfo invalid, so the caller
    refuses it through :func:`echocorn.utils.valid_authority` rather than
    quietly dropping the credentials and routing the request anyway.

    ``None`` means the authority cannot even be read - ``http://[::1/x`` and
    friends make the standard parser raise - which is a request to refuse, not
    one to fall back to the ``Host`` field for.  That raise used to escape the
    parser and end the connection with no answer at all.
    """
    try:
        return urlsplit(target.decode("latin-1")).netloc.encode("latin-1")
    except ValueError:
        return None


def _split_target(target: bytes) -> tuple[bytes, bytes]:
    """Return ``(raw_path_without_query, query_string)`` for a request target."""
    if target == b"*":
        return b"*", b""
    if target.startswith(b"/"):
        path, _, query = target.partition(b"?")
        return path, query
    if target.startswith((b"http://", b"https://")):
        try:
            split = urlsplit(target.decode("latin-1"))
        except ValueError:
            # The same bracketed authority the parser already refused; reaching
            # here means a form it let through, so refuse it rather than let a
            # parse error end the connection.
            raise _ProtocolError(400, "malformed authority in request target") from None
        path = (split.path or "/").encode("latin-1")
        query = (split.query or "").encode("latin-1")
        return path, query
    raise _ProtocolError(400, "unsupported request target form")


class HTTP11Handler:
    """Protocol handler for a single plaintext or TLS HTTP/1.1 connection."""

    def __init__(self, app: Callable, config: ServerConfig, transport: asyncio.Transport, peername: object, server_addr: object, ssl_object: object, logger: logging.Logger, on_close: Callable[[], None] | None = None, rate_limiter: RateLimiter | None = None) -> None:
        self.app = app
        self.config = config
        self.transport = transport
        self.peername = peername
        self.server_addr = server_addr
        self.ssl_object = ssl_object
        self.logger = logger
        self.access_logger = logging.getLogger("echocorn.access")
        self._on_close = on_close
        self.rate_limiter = rate_limiter

        self._buffer = bytearray()
        self._data_event = asyncio.Event()
        self._reader_task: asyncio.Task | None = None
        self._request: ASGIRequest | None = None
        self._writer_task: asyncio.Task | None = None
        self._state = "idle"
        self._closed = False
        self._read_paused = False
        self._write_paused = False
        self._resume_event = asyncio.Event()
        self._resume_event.set()
        self._body_remaining = 0
        self._chunked_decoder: ChunkedDecoder | None = None
        self._body_bytes = 0
        self._expect_continue = False
        self._continue_sent = False
        self._requests_served = 0
        self._deadline: float | None = None
        self._watchdog_task: asyncio.Task | None = None
        self._websocket: ws.WebSocketSession | None = None
        self._websocket_close_task: asyncio.Task | None = None

    # asyncio protocol callbacks.
    def connection_made(self) -> None:
        try:
            self.transport.set_write_buffer_limits(high=262144, low=65536)
        except (AttributeError, NotImplementedError):
            pass
        # The clock starts with the connection itself, so a peer that connects
        # and never finishes a request is dropped even before TLS finishes.
        self._arm_deadline()
        self._reader_task = asyncio.ensure_future(self._reader_loop())
        if self.config.request_timeout > 0:
            self._watchdog_task = asyncio.ensure_future(self._watchdog())

    def data_received(self, data: bytes) -> None:
        if self._closed:
            return
        self._buffer.extend(data)
        if self._websocket is None and len(self._buffer) > READ_HIGH_WATERMARK:
            # Once a WebSocket session owns the connection it applies its own
            # backpressure, and only its reader would ever resume the socket.
            self.pause_reading()
        self._data_event.set()

    def eof_received(self) -> bool:
        # Half-close: no further requests can arrive, so shut down cleanly.
        self._close()
        return False

    def pause_writing(self) -> None:
        self._write_paused = True
        self._resume_event.clear()

    def resume_writing(self) -> None:
        self._write_paused = False
        self._resume_event.set()

    def connection_lost(self, exc: BaseException | None) -> None:
        self._closed = True
        if self._request is not None:
            self._request.notify_disconnect()
        self._cancel_tasks()
        # The socket is gone, so a half sent close frame has nowhere to go.
        close_task = self._websocket_close_task
        if close_task is not None and not close_task.done():
            close_task.cancel()
        self._buffer.clear()
        self._release()

    def shutdown(self) -> None:
        """End the connection during server shutdown."""
        session = self._websocket
        if session is not None and not session.closed:
            # Tell the peer the server is going away (RFC 6455 section 7.4.1)
            # instead of vanishing without a close frame. The task is kept so
            # nothing can collect it while the frame is still in flight.
            self._websocket_close_task = asyncio.ensure_future(session.close_with(ws.CLOSE_GOING_AWAY))
            return
        self._close()

    # internals
    def _release(self) -> None:
        if self._on_close is not None:
            callback, self._on_close = self._on_close, None
            callback()

    def _cancel_tasks(self) -> None:
        current = asyncio.current_task()
        tasks = [self._reader_task, self._writer_task, self._watchdog_task]
        if self._request is not None:
            tasks.append(self._request.app_task)
        session = self._websocket
        if session is not None:
            tasks.extend(session.tasks)
        for task in tasks:
            if task is not None and task is not current and not task.done():
                task.cancel()

    def _close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._cancel_tasks()
        try:
            self.transport.close()
        except Exception:
            pass
        self._release()

    def pause_reading(self) -> None:
        """Stop reading from the socket (used for WebSocket backpressure)."""
        if self._read_paused or self._closed:
            return
        self._read_paused = True
        try:
            self.transport.pause_reading()
        except (AttributeError, NotImplementedError):
            pass

    def resume_reading(self) -> None:
        """Resume reading from the socket."""
        if not self._read_paused or self._closed:
            return
        self._read_paused = False
        try:
            self.transport.resume_reading()
        except (AttributeError, NotImplementedError):
            pass

    def _cancel_watchdog(self) -> None:
        task, self._watchdog_task = self._watchdog_task, None
        if task is not None and not task.done():
            task.cancel()

    def _maybe_resume_reading(self) -> None:
        if len(self._buffer) < READ_LOW_WATERMARK:
            self.resume_reading()

    def _arm_deadline(self) -> None:
        """
        (Re)start the single request deadline that guards the connection.

        Called when a request starts and again on every write of response bytes:
        receiving must fit into one window, while a response only has to keep
        making progress. Re-arming always moves the deadline further away, so the
        watchdog never has to be woken up and simply re-reads it when it fires.
        """
        timeout = self.config.request_timeout
        self._deadline = (asyncio.get_running_loop().time() + timeout if timeout > 0 else None)

    async def _watchdog(self) -> None:
        """Reset the connection when a request stops making progress."""
        loop = asyncio.get_running_loop()
        try:
            while not self._closed:
                deadline = self._deadline
                if deadline is None:
                    return
                delay = deadline - loop.time()
                if delay > 0:
                    await asyncio.sleep(delay)
                    if self._closed:
                        return
                current = self._deadline
                if current is not None and loop.time() >= current:
                    self._abort_request_timeout()
                    return
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("unhandled error in h11 watchdog")

    def _abort_request_timeout(self) -> None:
        """Drop a connection that stalled: send RST, never a half response."""
        if self._closed:
            return
        self._closed = True
        self.logger.debug("Resetting connection: request not completed within %.1fs", self.config.request_timeout)
        request = self._request
        if request is not None:
            request.keep_alive = False
            request.notify_disconnect()
        self._cancel_tasks()
        utils.force_reset(self.transport)
        self._release()

    async def _reader_loop(self) -> None:
        try:
            while not self._closed:
                progressed = await self._process()
                self._maybe_resume_reading()
                if self._closed:
                    return
                if progressed:
                    continue
                # Nothing more can be done with the bytes we have: wait for
                # more input (a partial head/body is the normal case here).
                self._data_event.clear()
                # Stalled requests are the watchdog's job; here we only retire
                # keep-alive connections that went idle after a response.
                timeout = self.config.keep_alive_timeout
                if self._request is not None or not (0 < timeout):
                    timeout = None
                try:
                    if timeout is None:
                        await self._data_event.wait()
                    else:
                        await asyncio.wait_for(self._data_event.wait(), timeout=timeout)
                except asyncio.TimeoutError:
                    self.logger.debug("closing idle keep-alive connection after %.1fs", self.config.keep_alive_timeout)
                    self._close()
                    return
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("unhandled error in h11 reader")
            self._close()

    async def _process(self) -> bool:
        if self._closed:
            return False
        if self._state == "idle":
            if not self._buffer:
                return False
            return await self._start_request()
        if self._state == "body":
            return await self._read_content_length_body()
        if self._state == "chunked":
            return await self._read_chunked_body()
        if self._state == "waiting":
            await self._await_response()
            return True
        return False

    async def _start_request(self) -> bool:
        try:
            head = parse_request_head(self._buffer, self.config)
        except _ProtocolError as exc:
            # The head is still in the buffer, so the method is recoverable.
            await self._send_error(
                exc.status,
                exc.message,
                allow=exc.allow,
                method=_peek_method(self._buffer),
                target=_peek_target(self._buffer),
            )
            return False
        if head is None:
            return False

        # Each request gets a fresh window: the deadline that was armed when the
        # connection went idle covered the wait for this head, and must not eat
        # into the time the request itself is allowed to take.
        self._arm_deadline()
        target = head.target.decode("latin-1", "replace")

        if self.rate_limiter is not None and not await self._allow_request(head.method, target):
            return False

        try:
            raw_path, query = _split_target(head.target)
        except _ProtocolError as exc:
            await self._send_error(exc.status, exc.message, method=head.method, target=target)
            return False

        if self.config.bind_domain:
            if utils.authority_host(head.host) != utils.authority_host(self.config.bind_domain.encode("latin-1", "replace")):
                await self._send_error(421, "misdirected request", method=head.method, target=target)
                return False

        if (self.config.websockets and head.version == "1.1" and head.method == b"GET" and ws.wants_websocket(head.headers)):
            await self._serve_websocket(head, raw_path, query)
            return False

        scope = self._http_scope(head, raw_path, query)

        request = ASGIRequest(scope, self.logger, recv_maxsize=16)
        request.keep_alive = head.keep_alive
        self._request = request
        self._body_bytes = 0
        self._continue_sent = False
        self._expect_continue = head.expect_continue

        if head.chunked:
            self._chunked_decoder = ChunkedDecoder()
            self._state = "chunked"
        elif head.content_length:
            self._body_remaining = head.content_length
            self._state = "body"
        else:
            self._state = "waiting"
            request.feed_request({"type": "http.request", "body": b"", "more_body": False})

        if self._expect_continue and self._state != "waiting":
            request.on_first_receive = self._send_continue

        request.app_task = asyncio.ensure_future(request.run_app(self.app))
        self._writer_task = asyncio.ensure_future(self._write_response(request))
        return True

    async def _allow_request(self, method: bytes, target: str = "") -> bool:
        """Count one request; answer ``429`` when the client is over its limit."""
        assert self.rate_limiter is not None
        client = client_key(self.peername)
        wait = self.rate_limiter.check(client)
        if wait is None:
            return True
        seconds = retry_after_seconds(wait)
        # The connection is closed with the refusal: the body of a request that
        # was never dispatched has not been read, and leaving it on the wire
        # would be read as the next request on a reused connection. The line is
        # logged as a warning, naming the address that was limited.
        await self._send_error(
            429,
            "too many requests",
            extra=[(b"retry-after", str(seconds).encode("ascii"))],
            method=method,
            target=target,
        )
        return False

    def _send_continue(self) -> None:
        if self._continue_sent or self._closed:
            return
        self._continue_sent = True
        request = self._request
        if request is not None and request.response_started:
            return
        try:
            self.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        except Exception:
            pass

    async def _emit_body(self, data: bytes) -> None:
        request = self._request
        assert request is not None
        message = {"type": "http.request", "body": data, "more_body": True}
        while True:
            outcome = request.feed_request(message)
            if outcome == utils.FEED_OK:
                return
            if outcome == utils.FEED_GONE:
                raise BodyAbandoned()
            await request.wait_for_space()

    async def _finish_request(self) -> None:
        request = self._request
        if request is None:
            return
        message = {"type": "http.request", "body": b"", "more_body": False}
        while request.feed_request(message) == utils.FEED_FULL:
            await request.wait_for_space()
        self._state = "waiting"

    async def _read_content_length_body(self) -> bool:
        request = self._request
        if request is None:
            return False
        if not self._buffer:
            return False
        progressed = False
        try:
            while self._buffer and self._body_remaining > 0:
                take = min(len(self._buffer), self._body_remaining)
                chunk = self._buffer[:take]
                del self._buffer[:take]
                self._body_remaining -= take
                self._body_bytes += take
                if (self.config.max_request_size and self._body_bytes > self.config.max_request_size):
                    raise _ProtocolError(413, "payload too large")
                await self._emit_body(chunk)
                progressed = True
            if self._body_remaining == 0:
                await self._finish_request()
                progressed = True
        except BodyAbandoned:
            self._abandon_body()
            return True
        except _ProtocolError as exc:
            self._fail_request()
            await self._send_error(exc.status, exc.message)
            return False
        return progressed

    async def _read_chunked_body(self) -> bool:
        request = self._request
        decoder = self._chunked_decoder
        if request is None or decoder is None:
            return False
        if not self._buffer and not decoder.done:
            return False
        try:
            limit = self.config.max_request_size or 0
            before = len(self._buffer)
            chunks = decoder.feed(self._buffer, limit)
            consumed = before - len(self._buffer)
            for chunk in chunks:
                self._body_bytes += len(chunk)
                if limit and self._body_bytes > limit:
                    raise _ProtocolError(413, "payload too large")
                await self._emit_body(chunk)
            if decoder.done:
                await self._finish_request()
            # Only report progress when bytes were actually consumed or the
            # request became complete; otherwise the reader would spin.
            return consumed > 0 or self._state != "chunked"
        except BodyAbandoned:
            self._abandon_body()
            return True
        except _ProtocolError as exc:
            self._fail_request()
            await self._send_error(exc.status, exc.message)
            return False

    def _fail_request(self) -> None:
        """
        Stop a request whose body could not be accepted.

        The application may already be waiting for input - it is often the case
        that it answered early and the framing error only turns up afterwards -
        so it is woken with ``http.disconnect``.  The reference is deliberately
        kept in place: dropping it here would leave the application task with
        nothing that can ever cancel it, so it would sit on ``receive()`` for the
        lifetime of the process (and the connection teardown would not find it
        either).
        """
        request = self._request
        if request is None:
            return
        request.keep_alive = False
        request.notify_disconnect()

    def _on_response_finished(self, request: ASGIRequest) -> None:
        """
        Called by the writer once the response has been fully sent.

        When the application answered without consuming the whole request body
        (an error response to a large upload, for example) the reader must stop
        waiting for data and either drain what is buffered or close.
        """
        if self._request is not request or self._closed:
            return
        if self._state not in ("body", "chunked"):
            return
        if not self._try_drain_buffered():
            request.keep_alive = False
        else:
            self._body_remaining = 0
            self._chunked_decoder = None
        self._state = "waiting"
        self._data_event.set()

    def _abandon_body(self) -> None:
        """
        The app responded without reading the rest of the body.

        Discard what is already buffered when that completes the message so the
        connection can be reused; otherwise close it rather than draining a
        potentially huge (or malicious) upload.
        """
        if self._try_drain_buffered():
            self._state = "waiting"
            return
        if self._request is not None:
            self._request.keep_alive = False
            self._state = "waiting"
        else:
            self._close()

    def _try_drain_buffered(self) -> bool:
        """Consume the remaining buffered body; ``True`` when it is complete."""
        if self._state == "chunked":
            decoder = self._chunked_decoder
            if decoder is None:
                return False
            budget = MAX_DRAIN_BYTES
            try:
                while not decoder.done:
                    if not self._buffer:
                        return False
                    before = len(self._buffer)
                    decoder.feed(self._buffer, 0)
                    consumed = before - len(self._buffer)
                    if consumed == 0:
                        return False
                    budget -= consumed
                    if budget < 0:
                        return False
            except _ProtocolError:
                return False
            return True

        remaining = self._body_remaining
        if remaining == 0:
            return True
        if remaining > MAX_DRAIN_BYTES or remaining > len(self._buffer):
            return False
        del self._buffer[:remaining]
        self._body_remaining = 0
        return True

    def is_idle(self) -> bool:
        """
        True when nothing in flight is waiting for the application.

        An active WebSocket session counts as idle: it is long lived by design
        and must not delay a graceful shutdown by the whole grace period.
        """
        if self._websocket is not None:
            return True
        return self._request is None and self._state == "idle"

    async def _await_response(self) -> None:
        request = self._request
        if request is None:
            self._state = "idle"
            return
        await request.response_complete.wait()
        self._chunked_decoder = None
        self._body_remaining = 0
        self._expect_continue = False
        if self._closed:
            return
        self._request = None
        self._requests_served += 1
        if not request.keep_alive:
            self._close()
            return
        self._state = "idle"
        self._arm_deadline()

    # response writing
    async def _wait_writable(self) -> None:
        while self._write_paused and not self._closed:
            self._resume_event.clear()
            if not self._write_paused or self._closed:
                break
            await self._resume_event.wait()

    async def _write(self, data: bytes) -> None:
        if self._closed or not data:
            return
        await self._wait_writable()
        if self._closed:
            return
        try:
            self.transport.write(data)
        except Exception:
            self._close()

    async def _write_chunk(self, data: bytes, chunked: bool, request: ASGIRequest) -> None:
        if not data:
            return
        if chunked:
            await self._write(format(len(data), "x").encode("ascii") + b"\r\n" + data + b"\r\n")
        else:
            await self._write(data)
        request.bytes_sent += len(data)
        # Writing counts as progress: a response may take as long as it keeps
        # producing output, while one that stalls is reset by the watchdog.
        self._arm_deadline()

    def _build_head(self, request: ASGIRequest, status: int, headers: Headers) -> bytes:
        parts: list[bytes] = [
            b"HTTP/1.1 ",
            str(status).encode("latin-1"),
            b" ",
            utils.status_phrase(status).encode("latin-1"),
            b"\r\n",
        ]
        if not utils.has_header(headers, b"date"):
            parts.append(b"date: " + utils.format_http_date().encode("latin-1") + b"\r\n")
        if not utils.has_header(headers, b"server"):
            parts.append(b"server: " + utils.SERVER_HEADER.encode("latin-1") + b"\r\n")
        for name, value in headers:
            parts.append(name + b": " + value + b"\r\n")
        if self.config.safe_headers:
            for name, value in utils.SAFE_HEADERS:
                if not utils.has_header(headers, name):
                    parts.append(name + b": " + value + b"\r\n")
        if not request.keep_alive:
            parts.append(b"connection: close\r\n")
        elif request.scope["http_version"] == "1.0":
            parts.append(b"connection: keep-alive\r\n")
        parts.append(b"\r\n")
        return b"".join(parts)

    async def _write_response(self, request: ASGIRequest) -> None:
        try:
            headers: Headers = []
            compressor: Compressor | None = None
            chunked = False
            started = False
            aborted = False
            trailers_expected = False
            awaiting_trailers = False
            discard_body = False
            # What the application announced, and what actually reached the
            # wire: a mismatch must close the connection, or the next response
            # on it would be read as part of this body.
            declared_length: int | None = None
            body_bytes = 0

            # The single request deadline (enforced by the watchdog) covers a
            # response that never starts as well as one that stalls, so the
            # writer only has to wait for the next ASGI message.
            while True:
                message = await request.next_response_message()
                message_type = message.get("type")
                if message_type == "http.response.start":
                    raw_status = int(message["status"])
                    if raw_status < 200:
                        # 1xx informational response (RFC 9110 section 15.2).
                        interim = utils.normalize_response_headers(message.get("headers"))
                        parts: list[bytes] = [
                            b"HTTP/1.1 ",
                            str(raw_status).encode("latin-1"),
                            b" ",
                            utils.status_phrase(raw_status).encode("latin-1"),
                            b"\r\n",
                        ]
                        parts.extend(name + b": " + value + b"\r\n" for name, value in interim)
                        parts.append(b"\r\n")
                        await self._write(b"".join(parts))
                        continue

                    status = raw_status
                    request.status = status
                    headers = utils.normalize_response_headers(message.get("headers"))
                    has_body = utils.response_has_body(request.scope["method"], status)
                    trailers_expected = bool(message.get("trailers")) and has_body

                    if has_body and self.config.compression:
                        if utils.compressible_response(request.scope["method"], status, headers):
                            # The coding of the answer was negotiated from the
                            # request, so a shared cache has to be told about it
                            # (RFC 9110 section 12.5.5).
                            headers = utils.add_vary(headers)
                        encoding = utils.should_compress(
                            request.scope["method"],
                            status,
                            headers,
                            request.scope["headers"],
                        )
                        if encoding is not None:
                            compressor = Compressor(encoding)
                            headers = [
                                (name, value)
                                for name, value in headers
                                if name.lower() != b"content-length"
                            ]
                            headers.append((b"content-encoding", encoding.encode("latin-1")))
                    if not has_body:
                        drop = utils.bodyless_header_drops(request.scope["method"], status)
                        headers = [
                            (name, value)
                            for name, value in headers
                            if name.lower() not in drop
                        ]
                        chunked = False
                    elif compressor is not None or not utils.has_header(headers, b"content-length"):
                        if request.scope["http_version"] == "1.1":
                            chunked = True
                            headers.append((b"transfer-encoding", b"chunked"))
                        else:
                            # Close-delimited body for HTTP/1.0 peers.
                            chunked = False
                            request.keep_alive = False
                    else:
                        chunked = False
                    if not chunked and has_body:
                        raw_length = utils.get_header(headers, b"content-length")
                        declared_length = int(raw_length) if raw_length is not None else None

                    await self._write(self._build_head(request, status, headers))
                    self._arm_deadline()
                    started = True
                    # A HEAD, 1xx, 204 or 304 response has no payload, but the
                    # application still finishes its body messages: drain them
                    # instead of aborting the exchange in the middle.
                    discard_body = not has_body
                    if discard_body and not message.get("more_body", True):
                        break

                elif message_type == "http.response.body":
                    if not started:
                        self.logger.warning("Ignoring http.response.body before start")
                        continue
                    body = message["body"]
                    more = message["more_body"]
                    if discard_body:
                        if not more:
                            break
                        continue
                    if not more and message.get("aborted"):
                        # The application gave up on an answer it had already
                        # started (see utils.ResponseAborted). The framing is
                        # left unterminated on purpose: a truncated body that
                        # ends with a chunk terminator would look complete, and
                        # a deflate tail would look like a whole stream.
                        aborted = True
                        break
                    if compressor is not None:
                        if body:
                            compressed = compressor.compress(body)
                            body_bytes += len(compressed)
                            await self._write_chunk(compressed, chunked, request)
                        if not more:
                            await self._write_chunk(compressor.flush(), chunked, request)
                    elif body:
                        body_bytes += len(body)
                        await self._write_chunk(body, chunked, request)

                    if not more:
                        if chunked and trailers_expected:
                            await self._write(b"0\r\n")
                            awaiting_trailers = True
                            continue
                        if chunked:
                            await self._write(b"0\r\n\r\n")
                        break

                elif message_type == "http.response.trailers":
                    if not awaiting_trailers:
                        # No trailer section was opened (a bodyless response, a
                        # close-delimited body, or trailers arriving late): the
                        # message still ends the exchange, so the response must
                        # not wait for another one.
                        if not message.get("more_trailers"):
                            break
                        continue
                    trailer_headers = utils.normalize_response_headers(message.get("headers"))
                    payload = b"".join(name + b": " + value + b"\r\n" for name, value in trailer_headers)
                    if message.get("more_trailers"):
                        await self._write(payload)
                        continue
                    await self._write(payload + b"\r\n")
                    break

            if aborted:
                # Never a clean end: the connection is closed with the framing
                # where it stopped, so the client sees the answer was cut.
                self.logger.warning("Closing the connection on an abandoned response")
                request.keep_alive = False
                self._close()

            if declared_length is not None and body_bytes != declared_length:
                # The application lied about the body it was going to send (or
                # stopped early); the framing on the wire no longer matches the
                # announced length, so this connection cannot be reused.
                self.logger.warning("Response sent %d body bytes but content-length announced %d", body_bytes, declared_length)
                request.keep_alive = False

            if not started:
                await self._write_error_response(request, 500)
        except asyncio.CancelledError:
            raise
        except Exception:
            # The response may be half written, so the connection cannot be
            # reused: drop it instead of corrupting the next exchange.
            self.logger.exception("error while writing h11 response")
            request.keep_alive = False
            self._close()
        finally:
            request.mark_finished()
            self._on_response_finished(request)
            request.response_complete.set()
            if self.config.access_log and request.status is not None:
                utils.access_log(
                    self.access_logger,
                    "h11",
                    request.scope.get("client"),
                    request.scope.get("method", "-"),
                    request.target,
                    request.status,
                    time.monotonic() - request.start_time,
                )

    async def _write_error_response(self, request: ASGIRequest, status: int) -> None:
        body = b"Internal Server Error"
        headers: Headers = [
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"content-length", str(len(body)).encode("latin-1")),
        ]
        request.status = status
        request.keep_alive = False
        await self._write(self._build_head(request, status, headers))
        await self._write(body)
        request.bytes_sent += len(body)

    def _http_scope(self, head: _ParsedHead, raw_path: bytes, query: bytes) -> dict[str, object]:
        return {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": head.version,
            "server": self.server_addr,
            "client": self.peername,
            "scheme": "https" if self.ssl_object is not None else "http",
            "method": head.method.decode("ascii"),
            "root_path": "",
            "path": utils.decode_path(raw_path),
            "raw_path": raw_path,
            "query_string": query,
            "headers": head.headers,
        }

    async def _serve_websocket(self, head: _ParsedHead, raw_path: bytes, query: bytes) -> None:
        """Run the RFC 6455 handshake and session, then close the connection."""
        started = time.monotonic()
        scheme = "wss" if self.ssl_object is not None else "ws"

        def report(status: int, messages: int | None = None) -> None:
            """Log the whole session on one line, like an HTTP request."""
            if not self.config.access_log:
                return
            target = utils.decode_path(raw_path)
            if query:
                target = "%s?%s" % (target, query.decode("latin-1"))
            utils.access_log(
                self.access_logger,
                scheme,
                self.peername,
                None,
                target,
                status,
                time.monotonic() - started,
                messages,
            )

        target = head.target.decode("latin-1", "replace")
        key = utils.get_header(head.headers, b"sec-websocket-key")
        if key is None or not ws.valid_key(key.strip()):
            await self._send_error(400, "invalid sec-websocket-key", method=head.method, target=target)
            report(400)
            return
        version = utils.get_header(head.headers, b"sec-websocket-version")
        if version is None or version.strip() != b"13":
            await self._send_error(426, "unsupported websocket version", extra=[(b"sec-websocket-version", b"13")], method=head.method, target=target)
            report(426)
            return
        if head.chunked or head.content_length:
            await self._send_error(400, "websocket upgrade with a request body", method=head.method, target=target)
            report(400)
            return

        scope: dict[str, object] = {
            "type": "websocket",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": head.version,
            "server": self.server_addr,
            "client": self.peername,
            "scheme": "wss" if self.ssl_object is not None else "ws",
            "root_path": "",
            "path": utils.decode_path(raw_path),
            "raw_path": raw_path,
            "query_string": query,
            "headers": head.headers,
            "subprotocols": ws.subprotocols(head.headers),
            # Advertised so a framework can answer a refused handshake with a
            # real HTTP response instead of the default 403 (ASGI extension).
            "extensions": {"websocket.http.response": {}},
        }

        # A WebSocket session is long lived by design, so the request deadline
        # stops applying; the session bounds its own handshake instead.
        self._cancel_watchdog()
        self._state = "websocket"
        session = ws.WebSocketSession(
            app=self.app,
            config=self.config,
            logger=self.logger,
            transport=self.transport,
            buffer=self._buffer,
            data_event=self._data_event,
            scope=scope,
            key=key.strip(),
            write=self._write,
            pause_reading=self.pause_reading,
            resume_reading=self.resume_reading,
        )
        self._websocket = session
        # The HTTP/1.1 buffer is the session's buffer from here on, so a pause
        # taken while the handshake was being read would never be lifted.
        self.resume_reading()
        try:
            await session.run()
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("websocket session failed")
        finally:
            self._websocket = None
            status = session.status
            if status is not None:
                # A refused handshake is reported with its HTTP status, an
                # accepted one with the WebSocket close code it ended with.
                report(status, session.messages if session.accepted else None)
            self._close()

    async def _send_error(self, status: int, message: str = "", allow: str | None = None, extra: Headers | None = None, method: bytes = b"", target: str = "") -> None:
        """
        Respond to a request the server refuses itself, and log who sent it.

        These answers never reach the application, so the operator only learns
        about a misdirected request, a refused method, a head that was too large
        or a rate limited client from here.
        """
        utils.refusal_log(
            self.logger,
            "h11",
            self.peername,
            method.decode("latin-1", "replace") or None,
            target,
            status,
            message,
        )
        request = self._request
        if request is not None and request.response_started:
            # The application already put a response head on this connection, so
            # a second one would be read as part of that body: a chunked body
            # would suddenly contain a status line (response splitting), and a
            # client or cache in front of the server would desynchronise.  The
            # exchange is abandoned instead - the connection is closed with the
            # framing exactly where it stopped, which is how a peer tells a
            # truncated answer from a complete one.
            self.logger.warning("Abandoning a started response after a refusal: %s", message or status)
            request.keep_alive = False
            request.notify_disconnect()
            self._close()
            return
        phrase = utils.status_phrase(status)
        lines = ["%d %s" % (status, phrase)]
        # Only a message that adds information is repeated: an error whose text
        # is the reason phrase itself would otherwise appear twice.
        if message and message.strip().lower() != phrase.lower():
            lines.append(message)
        body = ("\n".join(lines) + "\n").encode("latin-1", "replace")
        # A HEAD response keeps the length it would have had but no body.
        send_body = utils.response_has_body(method.decode("latin-1", "replace") or "GET", status)
        parts: list[bytes] = [
            b"HTTP/1.1 ",
            str(status).encode("latin-1"),
            b" ",
            utils.status_phrase(status).encode("latin-1"),
            b"\r\n",
            b"content-type: text/plain; charset=utf-8\r\n",
            b"content-length: " + str(len(body)).encode("latin-1") + b"\r\n",
            b"date: " + utils.format_http_date().encode("latin-1") + b"\r\n",
            b"server: " + utils.SERVER_HEADER.encode("latin-1") + b"\r\n",
        ]
        if allow is not None:
            parts.append(b"allow: " + allow.encode("latin-1") + b"\r\n")
        for name, value in extra or ():
            parts.append(name + b": " + value + b"\r\n")
        parts.append(b"connection: close\r\n\r\n")
        await self._write(b"".join(parts) + (body if send_body else b""))
        self._close()
