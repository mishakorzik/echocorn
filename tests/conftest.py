"""
Shared pytest fixtures and helpers for the Echocorn test-suite.

The server is started on an ephemeral port in a background thread, and tests
talk to it over plain sockets. HTTP/2 is exercised with hyper-h2's client state
machine, including full flow-control accounting so large bodies really do
stress the server's window management.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import socket
import threading
import time
from collections.abc import Callable

import pytest

import h2.connection
import h2.events
import h2.settings

from echocorn import ASGIServer, ServerConfig
from echocorn import websocket as ws

#: Shared state the WebSocket test application records for assertions.
WS_STATE: dict[str, object] = {}

# Reference ASGI application


async def websocket_app(scope, receive, send):
    """A small WebSocket router covering accept, echo, close and rejection."""
    path = scope["path"]
    query = scope["query_string"].decode("latin-1")
    first = await receive()
    assert first["type"] == "websocket.connect", first
    WS_STATE["subprotocols"] = scope.get("subprotocols")
    WS_STATE["scheme"] = scope.get("scheme")

    if path == "/ws/deny":
        await send({"type": "websocket.close", "code": 403})
        return
    if path == "/ws/deny-json":
        # The "websocket.http.response" extension: a real HTTP answer.
        await send(
            {
                "type": "websocket.http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", b"Bearer"),
                ],
            }
        )
        await send(
            {
                "type": "websocket.http.response.body",
                "body": b'{"error": "authenticate first"}',
            }
        )
        return
    if path == "/ws/deny-empty":
        # Starts an error response and returns without ever sending a body.
        await send(
            {
                "type": "websocket.http.response.start",
                "status": 403,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        return
    if path == "/ws/deny-streaming":
        await send(
            {
                "type": "websocket.http.response.start",
                "status": 429,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        for part in (b"slow", b" down"):
            await send(
                {"type": "websocket.http.response.body", "body": part, "more_body": True}
            )
        await send(
            {"type": "websocket.http.response.body", "body": b"!", "more_body": False}
        )
        return
    if path == "/ws/silent":
        # Never answers the handshake: the server must time it out.
        await asyncio.sleep(30)
        return

    if path == "/ws/subprotocol":
        await send({"type": "websocket.accept", "subprotocol": "chat"})
    else:
        await send({"type": "websocket.accept"})

    if path == "/ws/close":
        code = int(query.split("=")[-1]) if query else 1000
        await send({"type": "websocket.close", "code": code})
        return

    while True:
        message = await receive()
        if message["type"] == "websocket.disconnect":
            WS_STATE["disconnect_code"] = message["code"]
            return
        if "text" in message:
            await send({"type": "websocket.send", "text": "echo:" + message["text"]})
        else:
            await send(
                {"type": "websocket.send", "bytes": b"echo:" + message["bytes"]}
            )


async def app(scope, receive, send):
    """A small router exercising the interesting parts of the ASGI surface."""
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    if scope["type"] == "websocket":
        await websocket_app(scope, receive, send)
        return

    assert scope["type"] == "http"
    path = scope["path"]
    query = scope["query_string"].decode("latin-1")

    if path == "/":
        body = b"Hello, World!"
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                            (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})
        return

    if path == "/echo":
        chunks: list[bytes] = []
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/octet-stream"),
                            (b"content-length", str(len(body)).encode()),
                            (b"x-received-bytes", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})
        return

    if path == "/forgotten-trailers":
        # Announces trailers and never sends them: the response still has to end.
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
                "trailers": True,
            }
        )
        await send(
            {"type": "http.response.body", "body": b"no trailers", "more_body": False}
        )
        return

    if path == "/bodyless-trailers":
        # A bodyless response that announces trailers and sends no body at all.
        await send(
            {
                "type": "http.response.start",
                "status": 204,
                "headers": [],
                "trailers": True,
            }
        )
        return

    if path == "/late-trailers":
        # Trailers sent after the response already ended must not stall it.
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-length", b"2")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})
        await send(
            {
                "type": "http.response.trailers",
                "headers": [(b"x-late", b"1")],
                "more_trailers": False,
            }
        )
        return

    if path == "/big":
        total = int(query.split("=")[-1]) if query else 1024
        chunk = b"x" * 16384
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/octet-stream")],
            }
        )
        remaining = total
        while remaining > 0:
            size = min(remaining, len(chunk))
            remaining -= size
            await send(
                {
                    "type": "http.response.body",
                    "body": chunk[:size],
                    "more_body": remaining > 0,
                }
            )
        return

    if path == "/stream":
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        for part in (b"one", b"two", b"three"):
            await send({"type": "http.response.body", "body": part, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})
        return

    if path == "/compressible":
        body = (b"compression test payload " * 200)
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                            (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})
        return

    if path in ("/bytearray-body", "/memoryview-body"):
        # Applications hand the server a mutable buffer, or a view of one that
        # they still own; either way the server has to frame it on the wire.
        raw = b"buffered body " * 200
        body: object = bytearray(raw) if path == "/bytearray-body" else memoryview(raw)
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/octet-stream")],
            }
        )
        await send({"type": "http.response.body", "body": body})
        return

    if path == "/vary":
        # A compressible body that already carries a Vary of its own, so the
        # negotiated coding has to extend it rather than replace it.
        body = b"compression test payload " * 200
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                            (b"content-length", str(len(body)).encode()),
                            (b"vary", b"Accept-Language")],
            }
        )
        await send({"type": "http.response.body", "body": body})
        return

    if path == "/headers":
        body = json.dumps(
            {"headers": [[k.decode(), v.decode()] for k, v in scope["headers"]]}
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})
        return

    if path == "/badheaders":
        # Illegal in HTTP/2 and managed by the server in HTTP/1.1: these must be
        # dropped, never forwarded, otherwise h2 raises a ProtocolError.
        body = b"ok"
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/plain"),
                    (b"Connection", b"keep-alive"),
                    (b"Transfer-Encoding", b"chunked"),
                    (b"Keep-Alive", b"timeout=5"),
                    (b"Content-Length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
        return

    if path.startswith("/status/"):
        status = int(path.rsplit("/", 1)[1])
        body = b"status"
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"text/plain"),
                            (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})
        return

    if path == "/empty":
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})
        return

    if path == "/early-hints":
        await send(
            {
                "type": "http.response.start",
                "status": 103,
                "headers": [(b"link", b"</style.css>; rel=preload; as=style")],
            }
        )
        body = b"hinted"
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain"),
                            (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})
        return

    if path == "/trailers":
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain"),
                            (b"trailer", b"x-checksum")],
                "trailers": True,
            }
        )
        await send({"type": "http.response.body", "body": b"body", "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})
        await send(
            {
                "type": "http.response.trailers",
                "headers": [(b"x-checksum", b"abc123")],
                "more_trailers": False,
            }
        )
        return

    if path == "/ignores-body":
        # Responds without ever reading the request body.
        body = b"ignored"
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain"),
                            (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})
        return

    if path == "/never":
        # Never produces a response: the request deadline must reset the socket.
        await asyncio.sleep(30)
        return

    if path == "/slow-start":
        delay = float(query.split("=")[-1]) if query else 1.0
        await asyncio.sleep(delay)
        body = b"late"
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain"),
                            (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})
        return

    if path == "/slow-stream":
        # Streams slowly but never stops: progress must keep it alive.
        parts = int(query.split("=")[-1]) if query else 5
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        for index in range(parts):
            await asyncio.sleep(0.2)
            await send(
                {
                    "type": "http.response.body",
                    "body": b"part%d" % index,
                    "more_body": index + 1 < parts,
                }
            )
        return

    if path == "/boom":
        raise RuntimeError("boom")

    if path == "/crash-mid-body":
        # Starts an answer, sends part of it, then blows up: the framing must
        # not end as though the response were whole.
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"half", "more_body": True})
        raise RuntimeError("half way")

    if path == "/no-more-body":
        # Forgets ``more_body=False`` and returns.
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"partial", "more_body": True})
        return

    body = b"not found"
    await send(
        {
            "type": "http.response.start",
            "status": 404,
            "headers": [(b"content-type", b"text/plain"),
                        (b"content-length", str(len(body)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": body})


# Server fixture


def new_test_loop() -> asyncio.AbstractEventLoop:
    """The event loop the in-process test server runs on.

    Set ``ECHOCORN_TEST_UVLOOP=1`` to run the whole suite on uvloop instead of
    the default event loop, which is how the server runs in production when
    uvloop is installed.
    """
    if os.environ.get("ECHOCORN_TEST_UVLOOP") == "1":
        import uvloop

        return uvloop.new_event_loop()
    return asyncio.new_event_loop()


class ServerThread:
    """Runs :class:`ASGIServer` in a daemon thread on an ephemeral port."""

    def __init__(self, application: Callable = app, **options: object) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(128)
        self.host, self.port = self.sock.getsockname()
        # Tests are quiet by default; a test that checks log output re-enables it.
        options.setdefault("access_log", False)
        config = ServerConfig(host="127.0.0.1", port=0, **options)
        self.server = ASGIServer(application, config)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self.error: BaseException | None = None

    def __enter__(self) -> "ServerThread":
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                probe = socket.create_connection((self.host, self.port), timeout=0.5)
            except OSError:
                time.sleep(0.01)
            else:
                probe.close()
                return self
        raise RuntimeError("server did not start in time")

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _run(self) -> None:
        loop = new_test_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            loop.run_until_complete(self.server.serve(sock=self.sock))
        except BaseException as exc:
            self.error = exc
        finally:
            try:
                loop.close()
            except Exception:
                pass

    def stop(self) -> None:
        loop = self._loop
        if loop is not None and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(self.server.request_stop)
            except RuntimeError:  # the server thread already finished
                pass
        if self._thread is not None:
            self._thread.join(timeout=10)
        try:
            self.sock.close()
        except OSError:
            pass

    def connect(self, timeout: float = 5.0) -> socket.socket:
        connection = socket.create_connection((self.host, self.port), timeout=timeout)
        connection.settimeout(timeout)
        return connection


@pytest.fixture()
def server():
    with ServerThread() as instance:
        yield instance


@pytest.fixture()
def compression_server():
    with ServerThread(compression=True) as instance:
        yield instance


# HTTP/1.1 helpers


class Response:
    """A parsed HTTP/1.1 response."""

    def __init__(self, status: int, headers: dict[bytes, list[bytes]], body: bytes, raw: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body
        self.raw = raw

    def header(self, name: bytes) -> bytes | None:
        values = self.headers.get(name.lower())
        return values[0] if values else None

    def header_all(self, name: bytes) -> list[bytes]:
        return self.headers.get(name.lower(), [])


def _parse_head(head: bytes) -> tuple[int, dict[bytes, list[bytes]]]:
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ")[1])
    headers: dict[bytes, list[bytes]] = {}
    for line in lines[1:]:
        if not line:
            continue
        name, _, value = line.partition(b":")
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return status, headers


def complete_chunked_length(data: bytes) -> int | None:
    """Return the total length of a complete chunked body, or ``None``.

    Handles trailer sections, which terminate with an empty line after the
    zero-length chunk rather than immediately.
    """
    index = 0
    while True:
        end = data.find(b"\r\n", index)
        if end == -1:
            return None
        try:
            size = int(data[index:end].split(b";")[0], 16)
        except ValueError:
            return None
        index = end + 2
        if size == 0:
            while True:
                trailer_end = data.find(b"\r\n", index)
                if trailer_end == -1:
                    return None
                if trailer_end == index:
                    return trailer_end + 2
                index = trailer_end + 2
        if len(data) < index + size + 2:
            return None
        index += size + 2


def decode_chunked(data: bytes) -> bytes:
    total = complete_chunked_length(data)
    if total is None:
        raise AssertionError("incomplete chunked body")
    data = data[:total]
    out = bytearray()
    index = 0
    while True:
        end = data.index(b"\r\n", index)
        size = int(data[index:end].split(b";")[0], 16)
        index = end + 2
        if size == 0:
            break
        out.extend(data[index : index + size])
        index += size + 2
    return bytes(out)


class H1Reader:
    """Reads successive HTTP/1.1 responses from one socket.

    Keeps whatever was read past the current response, so pipelined responses
    and keep-alive reuse can be asserted reliably.
    """

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buffer = bytearray()

    def _read_more(self) -> None:
        chunk = self.sock.recv(65536)
        if not chunk:
            raise AssertionError("connection closed by server")
        self.buffer.extend(chunk)

    def read(self, expect_body: bool = True) -> Response:
        while b"\r\n\r\n" not in self.buffer:
            self._read_more()
        head_end = self.buffer.index(b"\r\n\r\n") + 4
        head = bytes(self.buffer[:head_end])
        del self.buffer[:head_end]
        status, headers = _parse_head(head)

        if not expect_body or status == 204 or 100 <= status < 200 or status == 304:
            return Response(status, headers, b"", head)

        if b"content-length" in headers:
            length = int(headers[b"content-length"][0])
            while len(self.buffer) < length:
                self._read_more()
            body = bytes(self.buffer[:length])
            del self.buffer[:length]
            return Response(status, headers, body, head + body)

        if headers.get(b"transfer-encoding", [b""])[0].lower() == b"chunked":
            while complete_chunked_length(bytes(self.buffer)) is None:
                self._read_more()
            total = complete_chunked_length(bytes(self.buffer))
            raw_body = bytes(self.buffer[:total])
            del self.buffer[:total]
            return Response(
                status, headers, decode_chunked(raw_body), head + raw_body
            )

        # Close-delimited body.
        while True:
            try:
                self._read_more()
            except AssertionError:
                break
        body = bytes(self.buffer)
        self.buffer.clear()
        return Response(status, headers, body, head + body)


def read_response(sock: socket.socket, expect_body: bool = True) -> Response:
    """Read exactly one HTTP/1.1 response from ``sock``."""
    return H1Reader(sock).read(expect_body)


def http1_request(
    server: ServerThread,
    raw: bytes,
    *,
    timeout: float = 5.0,
    expect_body: bool = True,
) -> bytes:
    """Send ``raw`` on a fresh connection and return the raw response bytes."""
    connection = server.connect(timeout=timeout)
    try:
        connection.sendall(raw)
        return read_response(connection, expect_body=expect_body).raw
    finally:
        connection.close()


def build_request(
    method: str = "GET",
    target: str = "/",
    headers: list[tuple[str, str]] | None = None,
    body: bytes = b"",
    version: str = "1.1",
    host: str | None = None,
) -> bytes:
    lines = ["%s %s HTTP/%s" % (method, target, version)]
    if host is not None:
        lines.append("Host: %s" % host)
    for name, value in headers or []:
        lines.append("%s: %s" % (name, value))
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + body


# HTTP/2 client


class H2Response:
    def __init__(self) -> None:
        self.headers: list[tuple[bytes, bytes]] = []
        self.body = bytearray()
        self.ended = False
        self.reset: int | None = None
        self.trailers: list[tuple[bytes, bytes]] = []

    @property
    def status(self) -> int:
        for name, value in self.headers:
            if name == b":status":
                return int(value)
        raise AssertionError("no :status in response")

    def header(self, name: bytes) -> bytes | None:
        for key, value in self.headers:
            if key == name:
                return value
        return None


class H2Client:
    """Minimal blocking HTTP/2 client with real flow-control accounting."""

    def __init__(
        self,
        server: ServerThread,
        timeout: float = 10.0,
        initial_window_size: int | None = None,
        sock: socket.socket | None = None,
    ) -> None:
        self.server = server
        self.sock = sock if sock is not None else server.connect(timeout=timeout)
        self.conn = h2.connection.H2Connection()
        self.conn.initiate_connection()
        if initial_window_size is not None:
            # A small receive window forces the server to wait for WINDOW_UPDATE
            # frames instead of pushing the whole body at once.
            self.conn.update_settings(
                {h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: initial_window_size}
            )
        self.sock.sendall(self.conn.data_to_send())
        self.responses: dict[int, H2Response] = {}
        self.informational: list[list[tuple[bytes, bytes]]] = []
        self.ping_acks: list[bytes] = []
        self.goaway: int | None = None
        self.resets: list[int] = []

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "H2Client":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _pump(self, predicate: Callable[[], bool], timeout: float = 10.0) -> None:
        deadline = time.time() + timeout
        while not predicate():
            remaining = deadline - time.time()
            if remaining <= 0:
                raise AssertionError("timed out waiting for HTTP/2 frames")
            self.sock.settimeout(remaining)
            try:
                data = self.sock.recv(65535)
            except socket.timeout:
                raise AssertionError("timed out waiting for HTTP/2 frames") from None
            if not data:
                raise AssertionError("connection closed by server")
            for event in self.conn.receive_data(data):
                self._handle(event)
            outgoing = self.conn.data_to_send()
            if outgoing:
                self.sock.sendall(outgoing)

    def _handle(self, event: object) -> None:
        if isinstance(event, h2.events.ResponseReceived):
            response = self.responses.setdefault(event.stream_id, H2Response())
            response.headers = list(event.headers)
        elif isinstance(event, h2.events.DataReceived):
            response = self.responses.setdefault(event.stream_id, H2Response())
            response.body.extend(event.data)
            # Immediately return the credit so large bodies can flow.
            self.conn.acknowledge_received_data(
                event.flow_controlled_length, event.stream_id
            )
        elif isinstance(event, h2.events.TrailersReceived):
            response = self.responses.setdefault(event.stream_id, H2Response())
            response.trailers = list(event.headers)
        elif isinstance(event, h2.events.StreamReset):
            self.resets.append(event.stream_id)
            self.responses.setdefault(event.stream_id, H2Response()).reset = (
                event.error_code
            )
        elif isinstance(event, h2.events.StreamEnded):
            self.responses.setdefault(event.stream_id, H2Response()).ended = True
        elif isinstance(event, h2.events.InformationalResponseReceived):
            self.informational.append(list(event.headers))
        elif isinstance(event, h2.events.PingAckReceived):
            self.ping_acks.append(event.ping_data)
        elif isinstance(event, h2.events.ConnectionTerminated):
            self.goaway = event.error_code

    def _wait_for_window(self, stream_id: int, timeout: float = 10.0) -> None:
        """Process incoming frames until the server grants us more credit."""
        deadline = time.time() + timeout
        while self.conn.local_flow_control_window(stream_id) <= 0:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise AssertionError("timed out waiting for a window update")
            self.sock.settimeout(min(remaining, 1.0))
            try:
                data = self.sock.recv(65535)
            except socket.timeout:
                continue
            if not data:
                raise AssertionError("connection closed while waiting for a window")
            for event in self.conn.receive_data(data):
                self._handle(event)
            outgoing = self.conn.data_to_send()
            if outgoing:
                self.sock.sendall(outgoing)

    def send_body(self, stream_id: int, data: bytes, end_stream: bool = True) -> None:
        offset = 0
        while offset < len(data):
            window = self.conn.local_flow_control_window(stream_id)
            if window <= 0:
                self._wait_for_window(stream_id)
                continue
            size = min(window, self.conn.max_outbound_frame_size, len(data) - offset)
            self.conn.send_data(
                stream_id,
                data[offset : offset + size],
                end_stream=end_stream and offset + size >= len(data),
            )
            offset += size
            self.sock.sendall(self.conn.data_to_send())

    def request(
        self,
        path: str = "/",
        method: str = "GET",
        body: bytes = b"",
        headers: list[tuple[bytes, bytes]] | None = None,
        stream_id: int | None = None,
        end_stream: bool | None = None,
    ) -> int:
        if stream_id is None:
            stream_id = self.conn.get_next_available_stream_id()
        authority = ("%s:%d" % (self.server.host, self.server.port)).encode()
        request_headers = [
            (b":method", method.encode()),
            (b":path", path.encode()),
            (b":scheme", b"http"),
            (b":authority", authority),
        ]
        request_headers.extend(headers or [])
        if end_stream is None:
            end_stream = not body
        self.conn.send_headers(stream_id, request_headers, end_stream=end_stream)
        self.sock.sendall(self.conn.data_to_send())
        if body:
            self.send_body(stream_id, body, end_stream=True)
        return stream_id

    def wait(self, stream_id: int, timeout: float = 10.0) -> H2Response:
        self._pump(
            lambda: stream_id in self.responses and self.responses[stream_id].ended,
            timeout=timeout,
        )
        return self.responses[stream_id]


# WebSocket client


class WSClient:
    """A minimal blocking RFC 6455 client (it masks, the server does not)."""

    def __init__(
        self,
        server: ServerThread,
        path: str = "/ws",
        headers: list[tuple[bytes, bytes]] | None = None,
        timeout: float = 5.0,
        extra_lines: list[bytes] | None = None,
        sock: socket.socket | None = None,
    ) -> None:
        self.sock = sock if sock is not None else server.connect(timeout=timeout)
        self.sock.settimeout(timeout)
        self.key = base64.b64encode(bytes(range(16)))
        request = [
            b"GET " + path.encode("latin-1") + b" HTTP/1.1",
            b"Host: " + ("%s:%d" % (server.host, server.port)).encode("latin-1"),
            b"Upgrade: websocket",
            b"Connection: Upgrade",
            b"Sec-WebSocket-Key: " + self.key,
            b"Sec-WebSocket-Version: 13",
        ]
        for name, value in headers or ():
            request.append(name + b": " + value)
        request.extend(extra_lines or ())
        self.sock.sendall(b"\r\n".join(request) + b"\r\n\r\n")
        self.buffer = bytearray()
        self.status: int | None = None
        self.response_headers: dict[bytes, bytes] = {}
        self._read_head()

    def _read_head(self) -> None:
        while b"\r\n\r\n" not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise AssertionError("connection closed during the handshake")
            self.buffer.extend(chunk)
        head, _, rest = bytes(self.buffer).partition(b"\r\n\r\n")
        self.buffer = bytearray(rest)
        lines = head.split(b"\r\n")
        self.status = int(lines[0].split(b" ")[1])
        for line in lines[1:]:
            name, _, value = line.partition(b":")
            self.response_headers[name.strip().lower()] = value.strip()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "WSClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # client -> server
    def send_frame(
        self, opcode: int, payload: bytes = b"", fin: bool = True, mask: bool = True
    ) -> None:
        self.sock.sendall(
            ws.build_frame(
                opcode, payload, fin=fin, mask=os.urandom(4) if mask else None
            )
        )

    def send_text(self, text: str) -> None:
        self.send_frame(ws.OPCODE_TEXT, text.encode("utf-8"))

    def send_bytes(self, data: bytes) -> None:
        self.send_frame(ws.OPCODE_BINARY, data)

    def send_ping(self, payload: bytes = b"ping") -> None:
        self.send_frame(ws.OPCODE_PING, payload)

    def send_close(self, code: int = 1000, reason: bytes = b"") -> None:
        self.send_frame(ws.OPCODE_CLOSE, code.to_bytes(2, "big") + reason)

    # server -> client
    def _try_parse(self) -> tuple[bool, int, bytes] | None:
        buffer = self.buffer
        if len(buffer) < 2:
            return None
        fin = bool(buffer[0] & 0x80)
        opcode = buffer[0] & 0x0F
        if buffer[1] & 0x80:
            raise AssertionError("the server must not mask its frames")
        length = buffer[1] & 0x7F
        offset = 2
        if length == 126:
            if len(buffer) < 4:
                return None
            length = int.from_bytes(buffer[2:4], "big")
            offset = 4
        elif length == 127:
            if len(buffer) < 10:
                return None
            length = int.from_bytes(buffer[2:10], "big")
            offset = 10
        if len(buffer) < offset + length:
            return None
        payload = bytes(buffer[offset : offset + length])
        del buffer[: offset + length]
        return fin, opcode, payload

    def recv_frame(self, timeout: float = 5.0) -> tuple[bool, int, bytes]:
        self.sock.settimeout(timeout)
        while True:
            frame = self._try_parse()
            if frame is not None:
                return frame
            chunk = self.sock.recv(65536)
            if not chunk:
                raise AssertionError("connection closed while waiting for a frame")
            self.buffer.extend(chunk)

    def recv_message(self, timeout: float = 5.0) -> tuple[str, object]:
        """Read a data message, handling ping/pong and fragmentation."""
        payload = bytearray()
        opcode: int | None = None
        deadline = time.time() + timeout
        while True:
            remaining = max(0.1, deadline - time.time())
            fin, frame_opcode, data = self.recv_frame(remaining)
            if frame_opcode == ws.OPCODE_PING:
                self.send_frame(ws.OPCODE_PONG, data)
                continue
            if frame_opcode == ws.OPCODE_PONG:
                # Answers to our own pings are not part of the message stream.
                continue
            if frame_opcode in (ws.OPCODE_TEXT, ws.OPCODE_BINARY):
                opcode = frame_opcode
                payload = bytearray()
            elif frame_opcode == ws.OPCODE_CONTINUATION:
                if opcode is None:
                    raise AssertionError("unexpected continuation frame")
            elif frame_opcode == ws.OPCODE_CLOSE:
                return ("close", _close_code(data))
            payload.extend(data)
            if fin:
                raw = bytes(payload)
                if opcode == ws.OPCODE_TEXT:
                    return ("text", raw.decode("utf-8"))
                return ("bytes", raw)

    def recv_text(self, timeout: float = 5.0) -> str:
        kind, value = self.recv_message(timeout)
        assert kind == "text", (kind, value)
        return value

    def recv_close(self, timeout: float = 5.0) -> int:
        kind, value = self.recv_message(timeout)
        assert kind == "close", (kind, value)
        return value

    def expect_eof(self, timeout: float = 5.0) -> None:
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(65536)
        except ConnectionResetError:
            return
        assert data == b"", "expected the server to close the connection"


def _close_code(payload: bytes) -> int:
    return int.from_bytes(payload[:2], "big") if len(payload) >= 2 else 1005


# TLS helpers (shared by the TLS and WebSocket suites)


def write_self_signed_cert(directory: object) -> tuple[str, str]:
    """Write a self signed certificate for localhost and return its paths."""
    import datetime
    import ipaddress

    pytest.importorskip("cryptography", reason="cryptography is not installed")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


@pytest.fixture()
def tls_server(tmp_path: object):
    """A compression enabled TLS server with a freshly generated certificate."""
    certfile, keyfile = write_self_signed_cert(tmp_path)
    with ServerThread(certfile=certfile, keyfile=keyfile, compression=True) as instance:
        yield instance


def tls_socket(server: ServerThread, protocols: list[str]) -> object:
    """Open a TLS socket to ``server`` offering ``protocols`` over ALPN."""
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(protocols)
    raw = socket.create_connection((server.host, server.port), timeout=10)
    wrapped = context.wrap_socket(raw, server_hostname="localhost")
    wrapped.settimeout(10)
    return wrapped
