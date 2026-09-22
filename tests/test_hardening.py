"""
Hardening tests: timeouts, connection limits, socket options and RST.

These cover the protections that keep a production deployment safe from
slow-loris and resource-exhaustion attacks:

* every request must complete within ``request_timeout``, counted from the
  moment the connection appears (TLS handshake included);
* stalled peers are dropped with a TCP reset, never with a half response;
* over-sized requests and header floods are rejected with the right status;
* the accept path sets TCP_NODELAY / SO_KEEPALIVE / SO_REUSEPORT where the
  platform supports them.
"""

from __future__ import annotations

import os
import socket
import struct
import time

import pytest

from echocorn import ASGIServer, ServerConfig
from echocorn import utils
from echocorn.server import ConnectionProtocol
from conftest import (
    H2Client,
    ServerThread,
    app,
    build_request,
    http1_request,
    read_response,
)


def _status(raw: bytes) -> int:
    return int(raw.split(b" ", 2)[1])


#: asyncio's proactor transport (the Windows default) calls
#: ``shutdown(SHUT_RDWR)`` before closing a socket, which turns the abortive
#: close done by ``utils.force_reset`` into a plain FIN.
_GRACEFUL_DROP_OK = os.name == "nt"


def _expect_reset(sock: socket.socket, timeout: float = 5.0) -> float:
    """
    Wait until the server drops the connection; return the elapsed time.

    On POSIX the peer must see a TCP reset. On Windows a plain EOF is accepted
    because the proactor event loop always shuts the socket down first.
    """
    start = time.monotonic()
    sock.settimeout(timeout)
    try:
        while True:
            if not sock.recv(65536):
                break
    except ConnectionResetError:
        return time.monotonic() - start
    if _GRACEFUL_DROP_OK:  # pragma: no cover - Windows only
        return time.monotonic() - start
    raise AssertionError("server closed gracefully instead of resetting")


def _wait_for_connections(server: ServerThread, count: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if len(server.server._connections) == count:
            return
        time.sleep(0.01)
    raise AssertionError(
        "expected %d live connections, saw %d"
        % (count, len(server.server._connections))
    )


# Request timeout (slow-loris)


def test_stalled_request_head_is_reset():
    with ServerThread(request_timeout=0.5) as server:
        sock = server.connect(timeout=5.0)
        try:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: local")
            elapsed = _expect_reset(sock)
            assert elapsed < 4.0, "reset took %.2fs" % elapsed
        finally:
            sock.close()


def test_stalled_request_body_is_reset():
    with ServerThread(request_timeout=0.5) as server:
        sock = server.connect(timeout=5.0)
        try:
            sock.sendall(
                b"POST /echo HTTP/1.1\r\nHost: local\r\n"
                b"content-length: 100\r\n\r\nhalf"
            )
            _expect_reset(sock)
        finally:
            sock.close()


def test_connection_without_any_request_is_reset():
    with ServerThread(request_timeout=0.5) as server:
        sock = server.connect(timeout=5.0)
        try:
            _expect_reset(sock)
        finally:
            sock.close()


def test_trickled_bytes_do_not_extend_the_deadline():
    """One byte per 200 ms must not keep a stalled request alive forever."""
    with ServerThread(request_timeout=1.0) as server:
        sock = server.connect(timeout=5.0)
        try:
            start = time.monotonic()
            aborted = False
            for byte in b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n":
                try:
                    sock.sendall(bytes([byte]))
                except OSError:
                    aborted = True
                    break
                time.sleep(0.2)
            elapsed = time.monotonic() - start
            if not aborted:
                # Still connected: the server must have dropped us by now.
                _expect_reset(sock)
            assert elapsed < 3.0, "the deadline was extended by the trickle"
        finally:
            sock.close()


def test_slow_but_valid_request_is_served():
    with ServerThread(request_timeout=2.0) as server:
        sock = server.connect(timeout=5.0)
        try:
            sock.sendall(b"GET / HTTP/1.1\r\n")
            time.sleep(0.3)
            sock.sendall(b"Host: localhost\r\n\r\n")
            response = read_response(sock)
            assert response.status == 200
            assert response.body == b"Hello, World!"
        finally:
            sock.close()


# The single timeout covers the response phase too


def test_stalled_response_is_reset():
    with ServerThread(request_timeout=0.5) as server:
        sock = server.connect(timeout=5.0)
        try:
            sock.sendall(build_request(target="/never", host="localhost"))
            _expect_reset(sock)
        finally:
            sock.close()


def test_slow_first_byte_is_reset():
    with ServerThread(request_timeout=0.5) as server:
        sock = server.connect(timeout=5.0)
        try:
            sock.sendall(build_request(target="/slow-start?delay=3", host="localhost"))
            _expect_reset(sock)
        finally:
            sock.close()


def test_streaming_response_keeps_making_progress():
    """A 1.0 s stream survives a 0.6 s timeout: every write restarts it."""
    with ServerThread(request_timeout=0.6) as server:
        sock = server.connect(timeout=5.0)
        try:
            sock.sendall(build_request(target="/slow-stream?parts=5", host="localhost"))
            response = read_response(sock)
            assert response.status == 200
            assert response.body == b"part0part1part2part3part4"
        finally:
            sock.close()


def test_h2_stalled_response_is_reset_but_connection_survives():
    with ServerThread(request_timeout=0.6) as server:
        with H2Client(server) as client:
            stream_id = client.request("/never")

            def reset_seen() -> bool:
                response = client.responses.get(stream_id)
                return response is not None and response.reset is not None

            client._pump(reset_seen, timeout=6.0)
            assert client.responses[stream_id].reset == 8  # CANCEL
            assert client.wait(client.request("/")).status == 200


def test_request_timeout_can_be_disabled():
    with ServerThread(request_timeout=0.0) as server:
        sock = server.connect(timeout=5.0)
        try:
            sock.sendall(b"GET / HTTP/1.1\r\n")
            time.sleep(1.5)
            sock.sendall(b"Host: localhost\r\n\r\n")
            assert read_response(sock).status == 200
        finally:
            sock.close()


# Connection limits


def test_max_connections_answers_503():
    with ServerThread(max_connections=2) as server:
        # Each connection is accounted for before the next one is opened, so a
        # straggler can never push the count over the limit and turn a valid
        # connection into an unexpected rejection.
        _wait_for_connections(server, 0)
        first = server.connect(timeout=5.0)
        _wait_for_connections(server, 1)
        second = server.connect(timeout=5.0)
        try:
            _wait_for_connections(server, 2)
            # The rejected connection is answered right away, without waiting
            # for a request that will never be served.
            third = server.connect(timeout=5.0)
            try:
                response = read_response(third)
                assert response.status == 503
                assert response.header(b"connection") == b"close"
            finally:
                third.close()
            # The rejected connection must not have displaced a live one.
            _wait_for_connections(server, 2)
            first.sendall(build_request(host="localhost"))
            second.sendall(build_request(host="localhost"))
            assert read_response(first).status == 200
            assert read_response(second).status == 200
        finally:
            first.close()
            second.close()


# Socket options


def test_listen_socket_is_configured():
    server = ASGIServer(app, ServerConfig(host="127.0.0.1", port=0, workers=2))
    sock = server.create_listen_socket()
    try:
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) != 0
        assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) != 0
        if hasattr(socket, "SO_REUSEPORT"):
            assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT) != 0
    finally:
        sock.close()


def test_listen_socket_has_no_reuseport_with_a_single_worker():
    if not hasattr(socket, "SO_REUSEPORT"):  # pragma: no cover - platform
        pytest.skip("SO_REUSEPORT is unavailable")
    server = ASGIServer(app, ServerConfig(host="127.0.0.1", port=0, workers=1))
    sock = server.create_listen_socket()
    try:
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT) == 0
    finally:
        sock.close()


def test_accepted_sockets_are_tuned():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    peer = socket.create_connection(listener.getsockname())
    accepted, _ = listener.accept()
    try:
        ConnectionProtocol._tune_socket(accepted)
        assert accepted.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) != 0
        assert accepted.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) != 0
    finally:
        accepted.close()
        peer.close()
        listener.close()


# Request smuggling and injection attempts


def test_bare_line_feed_in_a_header_value_is_rejected(server: ServerThread):
    raw = http1_request(server, b"GET / HTTP/1.1\r\nHost: local\r\nx-evil: a\nb\r\n\r\n")
    assert _status(raw) == 400


def test_nul_in_a_header_value_is_rejected(server: ServerThread):
    raw = http1_request(server, b"GET / HTTP/1.1\r\nHost: local\r\nx-evil: a\x00b\r\n\r\n")
    assert _status(raw) == 400


def test_del_in_a_header_value_is_rejected(server: ServerThread):
    raw = http1_request(server, b"GET / HTTP/1.1\r\nHost: local\r\nx-evil: a\x7fb\r\n\r\n")
    assert _status(raw) == 400


def test_control_character_in_the_target_is_rejected(server: ServerThread):
    raw = http1_request(server, b"GET /a\x01b HTTP/1.1\r\nHost: local\r\n\r\n")
    assert _status(raw) == 400


def test_horizontal_tab_in_a_header_value_is_allowed(server: ServerThread):
    raw = http1_request(
        server, b"GET /headers HTTP/1.1\r\nHost: local\r\nx-pad: a\tb\r\n\r\n"
    )
    assert _status(raw) == 200
    # JSON escapes the tab, so the application really received "a\tb".
    assert b"a\\tb" in raw


def test_oversized_http1_request_body_gets_413():
    with ServerThread(max_request_size=1024) as server:
        raw = http1_request(
            server,
            build_request(
                method="POST",
                target="/echo",
                host="localhost",
                headers=[("content-length", "4096")],
                body=b"z" * 4096,
            ),
        )
        assert _status(raw) == 413


def test_too_many_http1_headers_get_431():
    with ServerThread(max_header_count=8) as server:
        headers = [("x-pad-%d" % i, "v") for i in range(20)]
        raw = http1_request(
            server, build_request(host="localhost", headers=headers)
        )
        assert _status(raw) == 431


# TCP reset helper


class _FakeTransport:
    """Minimal transport stub that exposes a real socket and ``abort``."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self.aborted = False

    def get_extra_info(self, name: str, default=None):
        if name == "socket":
            return self._sock
        return default

    def abort(self) -> None:
        self.aborted = True
        try:
            self._sock.close()
        except OSError:  # pragma: no cover - already closed
            pass


def test_force_reset_sends_a_tcp_reset():  # noqa: D401 - behaviour is the point
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    peer = socket.create_connection(listener.getsockname())
    accepted, _ = listener.accept()
    transport = _FakeTransport(accepted)
    try:
        utils.force_reset(transport)
        assert transport.aborted is True
        peer.settimeout(5.0)
        with pytest.raises(ConnectionResetError):
            peer.recv(64)
    finally:
        peer.close()
        listener.close()


def test_force_reset_survives_a_broken_transport():
    class Broken:
        def get_extra_info(self, name, default=None):
            raise RuntimeError("no socket")

        def abort(self):
            raise RuntimeError("no abort")

    utils.force_reset(Broken())  # must not raise


# HTTP/2 hardening


def test_h2_connection_without_requests_is_reset():
    with ServerThread(request_timeout=0.5, keep_alive_timeout=30.0) as server:
        client = H2Client(server, timeout=5.0)
        try:
            elapsed = _expect_reset(client.sock)
            assert elapsed < 4.0, "reset took %.2fs" % elapsed
        finally:
            client.close()


def test_h2_stalled_stream_is_reset_and_connection_survives():
    with ServerThread(request_timeout=1.0) as server:
        with H2Client(server) as client:
            assert client.wait(client.request("/")).status == 200
            stalled = client.request("/echo", method="POST", end_stream=False)

            def reset_seen() -> bool:
                response = client.responses.get(stalled)
                return response is not None and response.reset is not None

            deadline = time.time() + 6.0
            while not reset_seen():
                if time.time() > deadline:
                    raise AssertionError("stalled stream was never reset")
                time.sleep(0.05)
                client.sock.settimeout(1.0)
                try:
                    data = client.sock.recv(65535)
                except socket.timeout:
                    continue
                if not data:
                    raise AssertionError("connection died with the stalled stream")
                for event in client.conn.receive_data(data):
                    client._handle(event)
                outgoing = client.conn.data_to_send()
                if outgoing:
                    client.sock.sendall(outgoing)

            # One timed-out stream must not take the whole connection down.
            assert client.wait(client.request("/")).status == 200


def test_h2_request_body_over_the_limit_gets_413():
    with ServerThread(max_request_size=1024) as server:
        with H2Client(server) as client:
            stream_id = client.request("/echo", method="POST", body=b"z" * 4096)
            response = client.wait(stream_id, timeout=10)
            assert response.status == 413


def test_h2_header_flood_gets_431():
    with ServerThread(max_header_count=8) as server:
        with H2Client(server) as client:
            extra = [(b"x-pad-%d" % i, b"value") for i in range(20)]
            stream_id = client.request("/", headers=extra)
            response = client.wait(stream_id)
            assert response.status == 431


def test_h2_idle_connection_is_closed():
    with ServerThread(keep_alive_timeout=0.5, request_timeout=0.0) as server:
        with H2Client(server) as client:
            assert client.wait(client.request("/")).status == 200
            client._pump(lambda: client.goaway is not None, timeout=5.0)


def test_h2_client_disconnect_does_not_leak_connections():
    with ServerThread() as server:
        _wait_for_connections(server, 0)
        with H2Client(server) as client:
            assert client.wait(client.request("/")).status == 200
            _wait_for_connections(server, 1)
        _wait_for_connections(server, 0)


def test_struct_linger_is_available():  # noqa: D401 - documents an assumption
    """The reset path depends on SO_LINGER; make the assumption explicit."""
    assert hasattr(socket, "SO_LINGER")
    assert len(struct.pack("ii", 1, 0)) == 8
