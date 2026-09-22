"""
Reverse proxying to a server on the loopback interface.

``app = "127.0.0.1:5000"`` puts Echocorn in front of a program that is already
listening there: the request is forwarded, the answer is streamed back, and
TLS, HTTP/2, the limits and the redirect stay in front. The upstream of these
tests is another Echocorn instance, so a proxied hop is checked end to end.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request

import pytest

from conftest import (
    H1Reader,
    ServerThread,
    WSClient,
    build_request,
    read_response,
)
from echocorn import websocket as ws
from echocorn import ServerConfig
from echocorn.config import ConfigError, load_settings, proxy_target
from echocorn.proxy import ProxyApp
from echocorn.server import resolve_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(tmp_path, text):
    path = tmp_path / "echocorn.toml"
    path.write_text(text, encoding="utf-8")
    return load_settings(path)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _send(server: ServerThread, raw: bytes, expect_body: bool = True):
    connection = server.connect()
    try:
        connection.sendall(raw)
        return read_response(connection, expect_body=expect_body)
    finally:
        connection.close()


def _get(server: ServerThread, target: str = "/", method: str = "GET", headers=None, body: bytes = b""):
    return _send(server, build_request(method=method, target=target, headers=headers, body=body, host="localhost"))


@pytest.fixture()
def upstream():
    """The locally listening program the front server proxies to."""
    with ServerThread() as instance:
        yield instance


@pytest.fixture()
def front(upstream):
    """A server whose ``app`` is a proxy to ``upstream``."""
    config = ServerConfig(host="127.0.0.1", port=0, access_log=False)
    application = ProxyApp("127.0.0.1", upstream.port, config)
    with ServerThread(application, access_log=False) as instance:
        yield instance


# Forwarding
def test_a_request_is_forwarded(front):
    response = _get(front)
    assert response.status == 200
    assert response.body == b"Hello, World!"
    assert response.header(b"content-type") == b"text/plain; charset=utf-8"


def test_the_upstream_status_is_forwarded(front):
    response = _get(front, "/missing.html")
    assert response.status == 404
    assert response.body == b"not found"


def test_a_request_body_is_forwarded(front):
    body = b"payload" * 1000
    response = _get(
        front,
        "/echo",
        method="POST",
        headers=[("Content-Length", str(len(body)))],
        body=body,
    )
    assert response.status == 200
    assert response.body == body
    assert response.header(b"x-received-bytes") == str(len(body)).encode()


def test_a_chunked_request_body_is_forwarded(front):
    raw = (
        b"POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    )
    response = _send(front, raw)
    assert response.status == 200
    assert response.body == b"hello world"


def test_a_streamed_response_is_forwarded(front):
    response = _get(front, "/stream")
    assert response.status == 200
    assert response.body == b"onetwothree"


def test_a_large_response_is_streamed_through(front):
    response = _get(front, "/big?size=300000")
    assert response.status == 200
    assert len(response.body) == 300000


def test_a_head_request_is_forwarded_without_a_body(front):
    connection = front.connect()
    reader = H1Reader(connection)
    try:
        connection.sendall(build_request(method="HEAD", host="localhost"))
        response = reader.read(expect_body=False)
    finally:
        connection.close()
    assert response.status == 200
    assert response.body == b""
    assert response.header(b"content-length") == b"13"


def test_the_upstream_sees_forwarded_headers(front, upstream):
    response = _get(front, "/headers")
    seen = {name.lower(): value for name, value in json.loads(response.body)["headers"]}
    assert seen["host"] == "127.0.0.1:%d" % upstream.port
    assert seen["x-real-ip"] == "127.0.0.1"
    assert seen["x-forwarded-for"] == "127.0.0.1"
    assert seen["x-forwarded-proto"] == "http"


# WebSocket tunnelling
def _upgrade(path: str = "/ws", extra: bytes = b"") -> bytes:
    """A raw RFC 6455 handshake for the cases a WSClient cannot read."""
    return (
        b"GET " + path.encode("latin-1") + b" HTTP/1.1\r\nHost: localhost\r\n"
        b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Key: " + base64.b64encode(bytes(range(16))) + b"\r\n"
        b"Sec-WebSocket-Version: 13\r\n" + extra + b"\r\n"
    )


def test_a_websocket_handshake_is_proxied(front):
    with WSClient(front) as client:
        assert client.status == 101
        assert client.response_headers[b"upgrade"].lower() == b"websocket"
        accept = ws.accept_key(client.key)
        assert client.response_headers[b"sec-websocket-accept"] == accept
        client.send_text("hello")
        assert client.recv_text() == "echo:hello"


def test_binary_messages_are_proxied(front):
    with WSClient(front) as client:
        assert client.status == 101
        client.send_bytes(b"\x00\x01\xff")
        assert client.recv_message() == ("bytes", b"echo:\x00\x01\xff")


def test_a_large_message_is_proxied(front):
    payload = "x" * 200000
    with WSClient(front) as client:
        assert client.status == 101
        client.send_text(payload)
        assert client.recv_text(timeout=10) == "echo:" + payload


def test_the_subprotocol_is_negotiated(front):
    with WSClient(front, path="/ws/subprotocol", headers=[(b"Sec-WebSocket-Protocol", b"chat, superchat")]) as client:
        assert client.status == 101
        assert client.response_headers[b"sec-websocket-protocol"] == b"chat"


def test_the_close_code_of_the_upstream_is_forwarded(front):
    with WSClient(front, path="/ws/close?code=1001") as client:
        assert client.status == 101
        assert client.recv_close() == 1001


def test_a_refused_handshake_is_relayed(front):
    """The client sees the answer of the application, not a generic error."""
    response = _send(front, _upgrade("/ws/deny-json"))
    assert response.status == 401
    assert response.header(b"www-authenticate") == b"Bearer"
    assert b"authenticate first" in response.body


def test_a_dead_upstream_refuses_a_websocket():
    config = ServerConfig(host="127.0.0.1", port=0, access_log=False)
    application = ProxyApp("127.0.0.1", _free_port(), config)
    with ServerThread(application, access_log=False) as front:
        response = _send(front, _upgrade())
    assert response.status == 502


# Failures
def test_a_dead_upstream_answers_502():
    config = ServerConfig(host="127.0.0.1", port=0, access_log=False)
    application = ProxyApp("127.0.0.1", _free_port(), config)
    with ServerThread(application, access_log=False) as front:
        response = _get(front)
    assert response.status == 502
    assert b"Bad Gateway" in response.body


def test_a_broken_upstream_answers_502():
    origin = _GarbageUpstream()
    config = ServerConfig(host="127.0.0.1", port=0, access_log=False)
    application = ProxyApp("127.0.0.1", origin.port, config)
    try:
        with ServerThread(application, access_log=False) as front:
            assert _get(front).status == 502
    finally:
        origin.close()


# Connection reuse
class _CountingUpstream:
    """A minimal keep-alive origin that counts the connections it accepts."""

    def __init__(self, body: bytes = b"ok") -> None:
        self.body = body
        self.connections = 0
        self.requests = 0
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(64)
        self._sock.setblocking(False)
        self.port = self._sock.getsockname()[1]
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(asyncio.start_server(self._handle, sock=self._sock))
        self._loop.run_forever()

    async def _handle(self, reader, writer) -> None:
        self.connections += 1
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                length = 0
                for line in head.split(b"\r\n")[1:]:
                    name, _, value = line.partition(b":")
                    if name.strip().lower() == b"content-length":
                        length = int(value)
                if length:
                    await reader.readexactly(length)
                self.requests += 1
                writer.write(
                    b"HTTP/1.1 200 OK\r\ncontent-length: %d\r\n\r\n" % len(self.body) + self.body
                )
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            return
        finally:
            writer.close()

    def close(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
        self._sock.close()


class _GarbageUpstream:
    """An origin that answers with something that is not an HTTP response."""

    def __init__(self) -> None:
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                connection, _ = self._sock.accept()
            except OSError:
                return
            try:
                connection.recv(4096)
                connection.sendall(b"not an http response\r\n\r\n")
            except OSError:
                pass
            finally:
                connection.close()

    def close(self) -> None:
        self._sock.close()


def test_the_upstream_connection_is_reused():
    origin = _CountingUpstream()
    config = ServerConfig(host="127.0.0.1", port=0, access_log=False)
    application = ProxyApp("127.0.0.1", origin.port, config)
    try:
        with ServerThread(application, access_log=False) as front:
            for _ in range(3):
                assert _get(front).status == 200
    finally:
        origin.close()
    assert origin.requests == 3
    assert origin.connections == 1


# Configuration
def test_a_loopback_app_setting_names_a_proxy(tmp_path):
    settings = _load(tmp_path, 'app = "127.0.0.1:5000"\n')
    assert proxy_target(settings.app) == ("127.0.0.1", 5000)
    application = resolve_app(settings.app, settings.config)
    assert isinstance(application, ProxyApp)
    assert application.authority == "127.0.0.1:5000"


@pytest.mark.parametrize(
    "value, expected",
    [
        ('"localhost:8080"', ("localhost", 8080)),
        ("'[::1]:80'", ("::1", 80)),
        ('"127.0.0.1:443"', ("127.0.0.1", 443)),
        ('"10.0.0.16:8080"', ("10.0.0.16", 8080)),
        ('"192.168.0.105:8000"', ("192.168.0.105", 8000)),
        ("'[fe80::1]:9000'", ("fe80::1", 9000)),
    ],
)
def test_every_local_spelling_is_accepted(tmp_path, value, expected):
    settings = _load(tmp_path, "app = %s\n" % value)
    assert proxy_target(settings.app) == expected


def test_a_remote_app_setting_is_refused(tmp_path):
    """A configuration file must not be able to build an open proxy."""
    with pytest.raises(ConfigError) as excinfo:
        _load(tmp_path, 'app = "example.com:80"\n')
    assert "only a local address" in str(excinfo.value)


def test_a_module_path_is_still_a_module(tmp_path):
    settings = _load(tmp_path, 'app = "myapp:asgi_app"\n')
    assert proxy_target(settings.app) is None


@pytest.mark.skipif(sys.platform == "win32", reason="the CLI test uses POSIX paths")
def test_cli_proxies_to_a_local_server(tmp_path, upstream):
    """``app = "127.0.0.1:port"`` serves another local server end to end."""
    port = _free_port()
    (tmp_path / "echocorn.toml").write_text(
        'app = "127.0.0.1:%d"\n'
        "\n[server]\n"
        'host = "127.0.0.1"\n'
        "port = %d\n"
        "\n[logging]\n"
        'level = "WARN"\n'
        "access = false\n" % (upstream.port, port),
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [sys.executable, "-m", "echocorn", "--config", "echocorn.toml"],
        cwd=str(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONPATH": ROOT},
    )
    try:
        deadline = time.time() + 20
        body = None
        while time.time() < deadline:
            try:
                with urllib.request.urlopen("http://127.0.0.1:%d/" % port, timeout=2) as ok:
                    body = ok.read()
                break
            except Exception:
                if process.poll() is not None:
                    raise AssertionError("the server exited: %s" % process.stderr.read()) from None
                time.sleep(0.1)
        assert body == b"Hello, World!"
    finally:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            process.kill()
    # The proxy answers the lifespan handshake itself.
    assert "does not support the lifespan" not in process.stderr.read()
