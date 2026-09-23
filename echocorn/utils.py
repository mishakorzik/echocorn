"""
Shared helpers used by the HTTP/1.1 and HTTP/2 protocol handlers.

Everything in here is transport agnostic: header hygiene, content coding
negotiation (RFC 9110 section 12.5.3), the streaming compressor and the ASGI
request object that both protocol implementations drive.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import struct
import time
import zlib
from collections.abc import Callable, Iterable, Sequence
from http import HTTPStatus
from urllib.parse import unquote

__all__ = [
    "HeaderPair",
    "Headers",
    "SERVER_HEADER",
    "SAFE_HEADERS",
    "FORBIDDEN_RESPONSE_HEADERS",
    "HOP_BY_HOP_HEADERS",
    "H2_FORBIDDEN_HEADERS",
    "ALLOWED_METHODS",
    "MAX_TARGET_LENGTH",
    "FEED_GONE",
    "FEED_OK",
    "FEED_FULL",
    "ASGIRequest",
    "BodyAbandoned",
    "Compressor",
    "ResponseAborted",
    "access_log",
    "add_vary",
    "authority_host",
    "valid_authority",
    "compressible_content_type",
    "compressible_response",
    "decode_path",
    "force_reset",
    "tune_socket",
    "format_http_date",
    "get_header",
    "has_header",
    "bodyless_header_drops",
    "negotiate_content_encoding",
    "normalize_response_headers",
    "refusal_log",
    "response_has_body",
    "should_compress",
    "status_phrase",
]

HeaderPair = tuple[bytes, bytes]
Headers = list[HeaderPair]

VERSION = "1.0.3"
SERVER_HEADER = "echocorn/" + VERSION

#: Methods both protocol handlers accept (RFC 9110 section 9).
ALLOWED_METHODS = frozenset(
    {
        b"GET",
        b"HEAD",
        b"POST",
        b"PUT",
        b"DELETE",
        b"OPTIONS",
        b"PATCH",
        b"TRACE"
    }
)

#: Longest request target / ``:path`` value we are willing to process.
MAX_TARGET_LENGTH = 8192

# Outcome of ASGIRequest.feed_request().
FEED_OK = 0
FEED_FULL = 1
FEED_GONE = 2

# Headers that only apply to a single hop and must never be forwarded or
# synthesised by an application (RFC 9110 section 7.6.1).
HOP_BY_HOP_HEADERS = frozenset(
    {
        b"connection",
        b"keep-alive",
        b"proxy-authenticate",
        b"proxy-authorization",
        b"proxy-connection",
        b"te",
        b"trailer",
        b"transfer-encoding",
        b"upgrade",
    }
)

# Connection specific header fields that RFC 9113 section 8.2.2 forbids in
# HTTP/2 messages. ``te`` is allowed but only with the value ``trailers``.
H2_FORBIDDEN_HEADERS = frozenset(
    {b"connection", b"keep-alive", b"proxy-connection", b"transfer-encoding", b"upgrade"}
)

# Fields an application must not set on a response. ``Trailer`` is allowed
# through because it announces a trailer section (RFC 9110 section 6.5.1).
FORBIDDEN_RESPONSE_HEADERS = HOP_BY_HOP_HEADERS - {b"trailer"}

SAFE_HEADERS: Sequence[HeaderPair] = (
    (b"strict-transport-security", b"max-age=31536000; includeSubDomains; preload"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-embedder-policy", b"require-corp"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"x-frame-options", b"SAMEORIGIN"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    (b"permissions-policy", b"geolocation=(), camera=(), microphone=()"),
)

# Minimum response size worth compressing. Bodies below this threshold usually
# grow when compressed and always waste CPU.
MIN_COMPRESS_SIZE = 1228

_COMPRESSIBLE_EXACT = frozenset(
    {
        b"application/json",
        b"application/ld+json",
        b"application/manifest+json",
        b"application/x-ndjson",
        b"application/javascript",
        b"application/x-javascript",
        b"application/ecmascript",
        b"application/xml",
        b"application/xhtml+xml",
        b"application/rss+xml",
        b"application/atom+xml",
        b"application/x-www-form-urlencoded",
        b"application/graphql",
        b"image/svg+xml",
        b"image/x-icon",
    }
)

# Content types that are already compressed on the wire.
_PRECOMPRESSED = (
    b"image/jpeg",
    b"image/png",
    b"image/gif",
    b"image/webp",
    b"image/avif",
    b"image/jxl",
    b"image/heic",
    b"image/heif",
    b"video/",
    b"audio/",
    b"application/zip",
    b"application/x-zip-compressed",
    b"application/gzip",
    b"application/x-gzip",
    b"application/zstd",
    b"application/x-zstd",
    b"application/bzip2",
    b"application/x-bzip2",
    b"application/x-7z-compressed",
    b"application/x-rar",
    b"application/vnd.rar",
    b"application/x-rar-compressed",
    b"application/x-xz",
    b"application/x-lzip",
    b"application/x-lzma",
    b"application/x-compress",
    b"font/woff",
    b"font/woff2",
    b"application/font-woff",
    b"application/font-woff2",
    b"application/epub+zip",
)


def status_phrase(status: int) -> str:
    """Return the RFC 9110 reason phrase for ``status``."""
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return "Unknown Status"


#: Cache for :func:`format_http_date`: the value only changes once a second,
#: and building it with ``strftime`` is far from free at high request rates.
_DATE_CACHE: tuple[str, int] = ("", 0)


def format_http_date() -> str:
    """Return the current time formatted as an IMF-fixdate (RFC 9110 5.6.7)."""
    global _DATE_CACHE
    now = int(time.time())
    cached, cached_at = _DATE_CACHE
    if cached_at == now:
        return cached
    stamp = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now))
    _DATE_CACHE = (stamp, now)
    return stamp


def decode_path(raw_path: bytes) -> str:
    """Percent-decode a request target path into the ASGI ``path`` string."""
    try:
        return unquote(raw_path.decode("ascii"))
    except UnicodeDecodeError:
        return unquote(raw_path.decode("latin-1"))


def tune_socket(sock: object) -> None:
    """
    Set the latency and liveness options of an accepted socket.

    ``TCP_NODELAY`` keeps small responses from waiting on Nagle, and
    ``SO_KEEPALIVE`` lets the kernel notice a peer that vanished without
    closing the connection.  Both are best effort: a platform that does not
    provide an option simply keeps its default.
    """
    if sock is None:
        return
    for level, option in ((socket.IPPROTO_TCP, getattr(socket, "TCP_NODELAY", None)), (socket.SOL_SOCKET, getattr(socket, "SO_KEEPALIVE", None))):
        if option is None:
            continue
        try:
            sock.setsockopt(level, option, 1)
        except OSError:
            pass


def force_reset(transport: object) -> None:
    """
    Close ``transport`` with a TCP reset (RST) instead of a FIN handshake.

    Used to drop connections that stalled or abused the server. ``SO_LINGER``
    set to zero makes the kernel emit RST instead of a graceful FIN when the
    socket is closed, so a stalling peer sees the failure at once rather than a
    half-closed connection that still looks usable.

    On Windows asyncio's proactor transport calls ``shutdown(SHUT_RDWR)``
    before closing, which downgrades the reset to a FIN; the connection is
    still dropped immediately there, and every POSIX platform gets a real RST.
    """
    try:
        sock = transport.get_extra_info("socket")
    except Exception:
        sock = None
    if sock is not None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        except (OSError, AttributeError, struct.error):
            pass
    abort = getattr(transport, "abort", None)
    try:
        if abort is not None:
            abort()
        else:
            transport.close()
    except Exception:
        pass


#: A URI authority, ``uri-host [ ":" port ]`` (RFC 3986 section 3.2), with the
#: percent-encoding spelled out so a broken escape is not read as a name.  An
#: empty host is allowed: a client with no authority to name sends ``Host:``
#: with an empty field value (RFC 9110 section 7.2).
_AUTHORITY_RE = re.compile(rb"^(?:\[[0-9A-Za-z:.v]+\]|(?:[A-Za-z0-9._~!$&'()*+,;=-]|%[0-9A-Fa-f]{2})*)(?::[0-9]*)?$")


def valid_authority(value: bytes) -> bool:
    """
    True when ``value`` is a well formed ``host[:port]`` authority.

    RFC 9112 section 3.2 requires a server to answer ``400`` to a request whose
    ``Host`` field value is invalid, and section 3.2.2 does the same for a
    request target that carries userinfo, so every authority taken from a peer
    goes through here first.  What gets through is what a routing or caching
    hop in front of this server would also accept, which is what keeps two hops
    from disagreeing about the site a request is for.
    """
    return _AUTHORITY_RE.match(value) is not None


def authority_host(authority: bytes) -> str:
    """
    Return the host part of a ``Host``/``:authority`` value, lower-cased.

    Used by ``bind_domain``, so the comparison must not be fooled by a port or
    by the brackets around an IPv6 literal (``[::1]:8000`` -> ``::1``).
    """
    text = authority.decode("latin-1", "replace").strip()
    if text.startswith("["):
        end = text.find("]")
        if end != -1:
            return text[1:end].lower()
    if text.count(":") == 1:
        return text.split(":", 1)[0].lower()
    # A bare IPv6 literal has no port to strip and no brackets to remove.
    return text.lower()


def has_header(headers: Iterable[HeaderPair], name: bytes) -> bool:
    """Case-insensitive membership test for a header field name."""
    name_lower = name.lower()
    return any(key.lower() == name_lower for key, _ in headers)


def get_header(headers: Iterable[HeaderPair], name: bytes) -> bytes | None:
    """Return the first value of ``name`` (case-insensitive) or ``None``."""
    name_lower = name.lower()
    for key, value in headers:
        if key.lower() == name_lower:
            return value
    return None


def compressible_content_type(content_type: bytes) -> bool:
    """Return ``True`` when a body of ``content_type`` benefits from compression."""
    media_type = content_type.split(b";", 1)[0].strip().lower()
    if not media_type:
        return False
    if media_type.startswith(_PRECOMPRESSED):
        return False
    if media_type.startswith(b"text/"):
        return True
    if media_type in _COMPRESSIBLE_EXACT:
        return True
    # Structured suffixes such as application/vnd.api+json.
    return media_type.endswith((b"+json", b"+xml"))


def _parse_quality(value: str) -> float:
    try:
        quality = float(value)
    except ValueError:
        return 0.0
    return min(1.0, max(0.0, quality))


def negotiate_content_encoding(headers: Iterable[HeaderPair], supported: Sequence[str] = ("gzip", "deflate")) -> str | None:
    """
    Pick the best supported content coding for ``Accept-Encoding``.

    Implements the weighted, ordered preference selection from RFC 9110
    section 12.5.3, including ``q=0`` (explicit rejection) and the ``*``
    wildcard. ``supported`` is ordered by server preference.
    """
    entries: list[tuple[str, float]] = []
    for name, value in headers:
        if name.lower() != b"accept-encoding":
            continue
        for raw in value.decode("latin-1").split(","):
            item = raw.strip()
            if not item:
                continue
            token, _, params = item.partition(";")
            token = token.strip().lower()
            if not token:
                continue
            quality = 1.0
            for param in params.split(";"):
                param = param.strip()
                if param[:2].lower() == "q=":
                    quality = _parse_quality(param[2:])
            entries.append((token, quality))

    if not entries:
        return None

    best: dict[str, tuple[float, int]] = {}
    wildcard: float | None = None
    for index, (token, quality) in enumerate(entries):
        if token == "*":
            wildcard = quality if wildcard is None else max(wildcard, quality)
        elif token in supported:
            previous = best.get(token)
            if previous is None or quality > previous[0]:
                best[token] = (quality, index)

    if wildcard is not None:
        for encoding in supported:
            best.setdefault(encoding, (wildcard, len(entries)))

    preference = {encoding: position for position, encoding in enumerate(supported)}
    candidates = [(quality, preference[encoding], index, encoding) for encoding, (quality, index) in best.items() if quality > 0.0]
    if not candidates:
        return None
    # Highest quality first, then server preference, then client order.
    candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
    return candidates[0][3]


def response_has_body(method: str, status: int) -> bool:
    """Whether a response may carry a body (RFC 9110 section 6.4.1)."""
    if method.upper() == "HEAD":
        return False
    if 100 <= status < 200:
        return False
    return status not in (204, 304)


def bodyless_header_drops(method: str, status: int) -> tuple[bytes, ...]:
    """
    Framing headers to remove from a response that cannot carry a body.

    RFC 9110 section 8.6 forbids ``Content-Length`` on 1xx and 204 responses,
    while a HEAD response SHOULD keep the header it would have sent for GET
    (RFC 9110 section 9.3.2). ``Transfer-Encoding`` is never useful here.
    """
    if method.upper() == "HEAD":
        return (b"transfer-encoding",)
    if status == 304:
        return (b"transfer-encoding",)
    return (b"content-length", b"transfer-encoding")


def compressible_response(method: str, status: int, response_headers: Headers) -> bool:
    """
    Whether a response body is one that compression may rewrite (RFC 9110 8.4).

    Body-less responses, partial responses, responses that are already
    content-encoded and bodies that are too small to benefit are all left
    alone.  This is the part of the decision that depends on the response
    alone, which is what a ``Vary`` header has to be derived from.
    """
    if not response_has_body(method, status):
        return False
    if status == 206:
        return False
    if has_header(response_headers, b"content-encoding"):
        return False
    if has_header(response_headers, b"content-range"):
        return False
    content_type = get_header(response_headers, b"content-type")
    if content_type is None or not compressible_content_type(content_type):
        return False
    content_length = get_header(response_headers, b"content-length")
    if content_length is not None:
        try:
            if int(content_length) < MIN_COMPRESS_SIZE:
                return False
        except ValueError:
            return False
    return True


def should_compress(method: str, status: int, response_headers: Headers, request_headers: Headers) -> str | None:
    """
    Return the content coding to use for this response, if any.

    Applies RFC 9110 section 8.4: never compress a body-less response, a
    partial response, or a response that is already content-encoded.
    """
    if not compressible_response(method, status, response_headers):
        return None
    return negotiate_content_encoding(request_headers)


def add_vary(headers: Headers, field: bytes = b"Accept-Encoding") -> Headers:
    """
    Add ``field`` to the ``Vary`` response header (RFC 9110 section 12.5.5).

    A response whose content coding was negotiated from the request has to say
    so, or a shared cache could hand the compressed body to a client that
    cannot decode it.  An existing ``Vary`` is extended instead of replaced,
    and the ``*`` wildcard already covers every field, so it is left alone.

    Returns a new list; the header the application sent is never modified.
    """
    result = list(headers)
    for index, (name, value) in enumerate(result):
        if name.lower() != b"vary":
            continue
        tokens = [token.strip().lower() for token in value.split(b",") if token.strip()]
        if b"*" in tokens or field.lower() in tokens:
            return result
        result[index] = (name, value + b", " + field)
        return result
    result.append((b"vary", field))
    return result


class Compressor:
    """
    Incremental gzip/deflate compressor.

    ``zlib`` is CPU bound but extremely fast; running it inline avoids the
    executor round-trip (and thread pool exhaustion) of ``asyncio.to_thread``.
    The ``deflate`` coding intentionally emits the zlib wrapper, which is what
    RFC 9110 section 8.4.1.2 specifies.
    """

    __slots__ = ("encoding", "_obj")

    def __init__(self, encoding: str, level: int = 6) -> None:
        self.encoding = encoding
        if encoding == "gzip":
            # 16 | MAX_WBITS selects the gzip framing.
            self._obj = zlib.compressobj(level, zlib.DEFLATED, zlib.MAX_WBITS | 16, 8)
        elif encoding == "deflate":
            self._obj = zlib.compressobj(level, zlib.DEFLATED, zlib.MAX_WBITS, 8)
        else:
            raise ValueError("Unsupported content coding: %r" % (encoding,))

    def compress(self, data: bytes) -> bytes:
        return self._obj.compress(data)

    def flush(self) -> bytes:
        return self._obj.flush(zlib.Z_FINISH)


def normalize_response_headers(headers: Iterable[object] | None, *, lowercase: bool = False, forbidden: Iterable[bytes] = ()) -> Headers:
    """
    Validate and clean up response headers produced by an ASGI application.

    Drops fields that would corrupt the framing, fields that are illegal in the
    target protocol version, and anything containing characters that could be
    used for response splitting.  A header name is only accepted when it is a
    real token, so a name carrying whitespace or CRLF cannot inject a field of
    its own (RFC 9110 section 5.1).
    """
    result: Headers = []
    if not headers:
        return result
    forbidden_set = frozenset(forbidden) | FORBIDDEN_RESPONSE_HEADERS
    for item in headers:
        try:
            name, value = item
        except (TypeError, ValueError):
            continue
        if isinstance(name, str):
            name = name.encode("latin-1", "replace")
        if isinstance(value, str):
            value = value.encode("latin-1", "replace")
        if not isinstance(name, (bytes, bytearray)) or not isinstance(value, (bytes, bytearray)):
            continue
        # ``bytes()`` returns the very same object for a ``bytes`` input, so the
        # usual case copies nothing at all; it only normalises the rarer
        # ``bytearray`` an application may hand us into the bytes the framing
        # code and hyper-h2 expect.
        name = bytes(name).strip()
        value = bytes(value).strip()
        if not _HEADER_NAME_RE.match(name):
            continue
        lowered = name.lower()
        if lowered in forbidden_set:
            continue
        if lowered == b"content-length":
            # Only DIGITs (RFC 9110 section 8.6). An application that sends
            # ``+5`` or ``5_0`` means well, but the value it would put on the
            # wire is not the value this server frames the body with, and a
            # peer reading it differently (or refusing it) would desynchronise.
            # The field is dropped instead: the body is then framed by chunking,
            # which no peer has to interpret.
            if _CONTENT_LENGTH_RE.match(value) is None:
                continue
        # RFC 9110 section 5.5: a field value holds VCHAR, SP, HTAB and
        # obs-text - no other C0 control. A bare LF is a line terminator to a
        # good many parsers even though it is not one here, and an application
        # that reflects something a client sent (a query parameter into a
        # header, say) must not be able to hand it a field of its own.
        if _ILLEGAL_VALUE_RE.search(value):
            continue
        result.append((lowered if lowercase else name, value))
    return result


#: A header field name is a token (RFC 9110 section 5.1); anything else - a
#: space, a colon, CRLF - is refused instead of being written to the wire.
_HEADER_NAME_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

#: ``Content-Length`` is 1*DIGIT (RFC 9110 section 8.6): no sign, no
#: underscores, nothing ``int()`` would quietly read as a number.
_CONTENT_LENGTH_RE = re.compile(rb"^[0-9]+$")

#: Every C0 control byte except horizontal tab, plus DEL (RFC 9110 section 5.5).
_ILLEGAL_VALUE_RE = re.compile(rb"[\x00-\x08\x0a-\x1f\x7f]")

#: Control characters are escaped in log fields, so a hostile request line
#: cannot forge extra log entries.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _log_field(value: str) -> str:
    """Escape control characters that could break a log file open."""
    if _CONTROL_RE.search(value) is None:
        return value
    return _CONTROL_RE.sub(lambda match: "\\x%02x" % ord(match.group()), value)


def access_log(logger: logging.Logger, protocol: str, client: tuple[object, ...] | None, method: str | None, target: str, status: int, elapsed: float, messages: int | None = None) -> None:
    """
    Emit one access log line, in the same shape for every protocol::

        h11, ip=127.0.0.1, method=GET, path=/, code=200, time=1.732s
        h20, ip=127.0.0.1, method=GET, path=/test.html, code=404, time=0.971s
        wss, ip=127.0.0.1, path=/ws, code=1000, time=12.480s, msgs=4

    ``protocol`` is ``h11``, ``h20``, ``ws`` or ``wss``.  ``method`` is left out
    for a WebSocket session, where the handshake is always a GET, and
    ``messages`` (how many messages the peer sent) is only reported for one.
    """
    if not logger.isEnabledFor(logging.INFO):
        return
    host = str(client[0]) if client else "-"
    parts = ["%s, ip=%s" % (protocol, _log_field(host))]
    if method:
        parts.append("method=%s" % _log_field(method))
    parts.append("path=%s" % _log_field(target))
    parts.append("code=%d" % status)
    parts.append("time=%.3fs" % elapsed)
    if messages is not None:
        parts.append("msgs=%d" % messages)
    logger.info(", ".join(parts))


def refusal_log(logger: logging.Logger, protocol: str, client: tuple[object, ...] | None, method: str | None, target: str, status: int, reason: str = "") -> None:
    """
    Report a request the server refused itself, at WARN, naming the client.

    These are the answers the application never sees - a misdirected request, a
    method that is not allowed, a head that was too large, a rate limited
    client - so the operator needs the address and the reason in the log to
    know who is doing it and why.  The line follows the shape of an access log
    line, with the reason (when there is one) at the end::

        h11, ip=127.0.0.1, method=GET, path=/x, code=421, reason=misdirected request
    """
    if not logger.isEnabledFor(logging.WARNING):
        return
    host = str(client[0]) if client else "-"
    parts = ["%s, ip=%s" % (protocol, _log_field(host))]
    if method:
        parts.append("method=%s" % _log_field(method))
    parts.append("path=%s" % _log_field(target or "-"))
    parts.append("code=%d" % status)
    if reason:
        parts.append("reason=%s" % _log_field(reason))
    logger.warning(", ".join(parts))


class BodyAbandoned(Exception):
    """Raised internally when the app responded before reading the body."""


class ResponseAborted(Exception):
    """
    Raised by an application that cannot finish the response it started.

    The writers must then abandon the framing instead of terminating it: a
    truncated body that ends with a chunk terminator, or an END_STREAM frame,
    is indistinguishable from a complete one, so a client would treat a half
    written answer - a proxied file whose upstream died, say - as whole.
    """


class ASGIRequest:
    """
    Transport independent ASGI scope plus message plumbing.

    The protocol handler pushes ``http.request`` messages in and drains
    ``http.response.*`` messages out; the application only ever sees this object.
    """

    __slots__ = (
        "scope",
        "recv_q",
        "send_q",
        "recv_space",
        "send_space",
        "response_started",
        "response_complete",
        "disconnected",
        "finished",
        "app_task",
        "ack_fn",
        "on_first_receive",
        "logger",
        "keep_alive",
        "start_time",
        "bytes_sent",
        "status",
        "target",
        "trailers_announced",
        "trailers_sent",
        "body_ended",
        "aborted",
    )

    def __init__(self, scope: dict[str, object], logger: logging.Logger, *, recv_maxsize: int = 16, send_maxsize: int = 32, ack_fn: Callable[[int], None] | None = None, on_first_receive: Callable[[], object] | None = None) -> None:
        self.scope = scope
        self.logger = logger
        self.recv_q: asyncio.Queue = asyncio.Queue(maxsize=recv_maxsize)
        self.send_q: asyncio.Queue = asyncio.Queue(maxsize=send_maxsize)
        self.recv_space = asyncio.Event()
        self.recv_space.set()
        self.send_space = asyncio.Event()
        self.send_space.set()
        self.response_started = False
        self.response_complete = asyncio.Event()
        self.finished = False
        self.disconnected = False
        self.app_task: asyncio.Task | None = None
        self.ack_fn = ack_fn
        self.on_first_receive = on_first_receive
        # Response bookkeeping shared with the protocol writers.
        self.keep_alive = True
        self.start_time = time.monotonic()
        self.bytes_sent = 0
        self.status: int | None = None
        self.trailers_announced = False
        self.trailers_sent = False
        #: Whether the application sent a terminal response message, so the
        #: framing is already complete.  A framework that answers an error and
        #: then re-raises it (Starlette does) must not lose the answer it sent.
        self.body_ended = False
        #: Set when the application gave up on a response it had started, so
        #: the framing is dropped instead of terminated (see ResponseAborted).
        self.aborted = False
        self.target = scope.get("path", "/")
        if scope.get("query_string"):
            self.target = "%s?%s" % (self.target, scope["query_string"].decode("latin-1"))

    # Producer side, called by the protocol handler.
    def feed_request(self, message: dict[str, object], flow_size: int = 0) -> int:
        """
        Queue an ``http.request`` message without blocking.

        Returns :data:`FEED_OK`, :data:`FEED_FULL` (call :meth:`wait_for_space`)
        or :data:`FEED_GONE` when the application is no longer reading input.
        """
        if self.finished or self.disconnected:
            return FEED_GONE
        try:
            self.recv_q.put_nowait((message, flow_size))
        except asyncio.QueueFull:
            return FEED_FULL
        return FEED_OK

    async def wait_for_space(self) -> None:
        """Block until the application drains one queued request message."""
        while self.recv_q.full() and not self.finished and not self.disconnected:
            self.recv_space.clear()
            if not self.recv_q.full() or self.finished or self.disconnected:
                break
            await self.recv_space.wait()

    def notify_disconnect(self) -> None:
        """Wake the application with ``http.disconnect`` (peer went away)."""
        self.disconnected = True
        self.finished = True
        self.recv_space.set()
        try:
            self.recv_q.put_nowait(({"type": "http.disconnect"}, 0))
        except asyncio.QueueFull:
            pass

    def mark_finished(self) -> None:
        """
        Called by the protocol writer once the response is fully sent.

        Per the ASGI HTTP specification further ``receive()`` calls must then
        return ``http.disconnect`` instead of blocking on a peer that has
        nothing left to send.
        """
        self.finished = True
        self.send_space.set()
        if not self.disconnected:
            self.disconnected = True
            try:
                self.recv_q.put_nowait(({"type": "http.disconnect"}, 0))
            except asyncio.QueueFull:
                pass
        self.recv_space.set()

    async def next_response_message(self) -> dict[str, object]:
        """Await the next ASGI response message, releasing send backpressure."""
        message = await self.send_q.get()
        self.send_space.set()
        return message

    # ASGI callables.
    async def receive(self) -> dict[str, object]:
        callback, self.on_first_receive = self.on_first_receive, None
        if callback is not None:
            result = callback()
            if asyncio.iscoroutine(result):
                await result
        if self.disconnected and self.recv_q.empty():
            return {"type": "http.disconnect"}
        message, flow_size = await self.recv_q.get()
        self.recv_space.set()
        if flow_size and self.ack_fn is not None:
            self.ack_fn(flow_size)
        return message

    async def send(self, message: dict[str, object]) -> None:
        if not isinstance(message, dict):
            raise TypeError("ASGI message must be a dict, got %r" % type(message))
        message_type = message.get("type")
        if message_type == "http.response.start":
            status = message.get("status", 200)
            if not isinstance(status, int) or not 100 <= status <= 999:
                raise ValueError("invalid http.response.start status: %r" % (status,))
            if status >= 200:
                if self.response_started:
                    raise RuntimeError("http.response.start sent more than once")
                self.response_started = True
                self.trailers_announced = bool(message.get("trailers"))
            # 1xx informational responses may be repeated and do not start the
            # final response (RFC 9110 section 15.2).
            normalized: Headers = []
            for item in message.get("headers") or []:
                try:
                    name, value = item
                except (TypeError, ValueError):
                    raise ValueError("invalid header entry: %r" % (item,)) from None
                if not isinstance(name, bytes) or not isinstance(value, bytes):
                    raise ValueError("ASGI header names and values must be bytes")
                normalized.append((name, value))
            message = dict(message)
            message["headers"] = normalized
            message.setdefault("trailers", False)
        elif message_type == "http.response.body":
            if not self.response_started:
                raise RuntimeError("http.response.body sent before http.response.start")
            body = message.get("body") or b""
            if not isinstance(body, (bytes, bytearray, memoryview)):
                raise ValueError("http.response.body body must be bytes")
            if not isinstance(body, (bytes, bytearray)):
                # Anything else that exposes the buffer protocol - a memoryview
                # an application still holds, say - is normalised once, here.
                # The bytes and bytearray that applications normally send are
                # passed on untouched: ``zlib.compress``, ``transport.write``,
                # ``h2.send_data`` and the chunked framing all take a bytearray,
                # so copying them would duplicate a payload that can be
                # megabytes long.
                body = bytes(body)
            message = dict(message)
            message["body"] = body
            message["more_body"] = bool(message.get("more_body", False))
            if not message["more_body"] and not message.get("aborted"):
                self.body_ended = True
        elif message_type == "http.response.trailers":
            if not self.response_started:
                raise RuntimeError("http.response.trailers sent before http.response.start")
            message = dict(message)
            message["headers"] = list(message.get("headers") or [])
            message["more_trailers"] = bool(message.get("more_trailers", False))
            self.trailers_sent = True
            if not message["more_trailers"]:
                self.body_ended = True
        else:
            self.logger.debug("Ignoring unsupported ASGI message type %r", message_type)
            return

        # ``send`` may block on backpressure but must never hang once the
        # response is finished, which is what happens when an application keeps
        # sending after the final body.
        if not await self._enqueue(message):
            self.logger.warning("Application sent after the response completed")

    async def _enqueue(self, message: dict[str, object]) -> bool:
        """Queue a response message, waiting for the writer to catch up."""
        while not self.finished:
            try:
                self.send_q.put_nowait(message)
                return True
            except asyncio.QueueFull:
                pass
            self.send_space.clear()
            if not self.send_q.full() or self.finished:
                continue
            await self.send_space.wait()
        return False

    async def run_app(self, app: Callable) -> None:
        """Execute the application, guaranteeing a terminal response message."""
        try:
            await app(self.scope, self.receive, self.send)
        except asyncio.CancelledError:
            raise
        except ResponseAborted as exc:
            # A response the application cannot finish (a proxy whose upstream
            # died mid-answer). The client must be able to tell, so the framing
            # is abandoned rather than terminated.
            if self.response_started and not self.body_ended:
                self.logger.warning("Abandoning an incomplete response: %s", exc)
                self.aborted = True
                await self._put_end(aborted=True)
            elif self.response_started:
                # The answer was already complete: the abort came too late to
                # change anything, so it is only reported.
                self.logger.warning("Ignoring an abort of a completed response: %s", exc)
            else:
                self.logger.warning("The application aborted before answering: %s", exc)
                self.response_started = True
                await self._put({"type": "http.response.start", "status": 502, "headers": []})
                await self._put({"type": "http.response.body", "body": b"Bad Gateway", "more_body": False})
            return
        except Exception:
            self.logger.exception("Exception in ASGI application")
            if not self.response_started:
                self.response_started = True
                await self._put({"type": "http.response.start", "status": 500, "headers": []})
                await self._put({"type": "http.response.body", "body": b"Internal Server Error", "more_body": False})
            elif not self.body_ended:
                # The headers are already on the wire, so the answer cannot be
                # replaced; it is abandoned rather than terminated, because an
                # application that blew up halfway through its body must not
                # produce something that looks complete.
                self.logger.warning("Abandoning a response after an exception")
                self.aborted = True
                await self._put_end(aborted=True)
            elif self.trailers_announced and not self.trailers_sent:
                # The framework answered and then re-raised (Starlette does):
                # its answer is on the wire, only the trailer block is missing.
                await self._finish()
            return
        if not self.response_complete.is_set():
            # The app returned without finishing the response (e.g. it forgot
            # ``more_body=False``); terminate it so the writer cannot hang.
            if not self.response_started:
                self.response_started = True
                await self._put({"type": "http.response.start", "status": 204, "headers": []})
            await self._finish()

    async def _put(self, message: dict[str, object]) -> None:
        await self._enqueue(message)

    async def _finish(self) -> None:
        """
        Terminate the response, honouring an announced trailer section.

        An application that announced trailers but never sent them would leave
        the writer waiting for a message that can no longer arrive, so the empty
        trailer block is sent on its behalf.
        """
        if self.trailers_announced and not self.trailers_sent:
            self.trailers_sent = True
            await self._put({"type": "http.response.trailers", "headers": [], "more_trailers": False})
            return
        if self.body_ended:
            # The application already terminated the response: sending another
            # terminal message would only race the writer's own completion.
            return
        await self._put_end()

    async def _put_end(self, aborted: bool = False) -> None:
        """
        Queue the terminal body message.

        ``aborted`` marks it as the end of a response that could not be
        finished.  The mark travels with the message - not in a flag on the
        request - so the writer knows exactly where the answer stops: every
        body message queued before it was produced while the exchange was
        still healthy and is written out normally.
        """
        message: dict[str, object] = {"type": "http.response.body", "body": b"", "more_body": False}
        if aborted:
            message["aborted"] = True
        await self._put(message)
