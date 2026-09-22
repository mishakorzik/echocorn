"""
TLS tests: ALPN based protocol negotiation and HTTPS request handling.

The ``tls_server`` fixture and the ``tls_socket`` helper live in ``conftest`` so
that the WebSocket suite can reuse them.
"""

from __future__ import annotations

from conftest import H2Client, ServerThread, build_request, read_response, tls_socket


def _tls_socket(server: ServerThread, protocols):
    return tls_socket(server, list(protocols))


def test_alpn_negotiates_http2(tls_server: ServerThread):
    sock = _tls_socket(tls_server, ["h2", "http/1.1"])
    try:
        assert sock.selected_alpn_protocol() == "h2"
        with H2Client(tls_server, sock=sock) as client:
            stream_id = client.request("/")
            response = client.wait(stream_id)
            assert response.status == 200
            assert bytes(response.body) == b"Hello, World!"
    finally:
        sock.close()


def test_alpn_negotiates_http11(tls_server: ServerThread):
    sock = _tls_socket(tls_server, ["http/1.1"])
    try:
        assert sock.selected_alpn_protocol() == "http/1.1"
        sock.sendall(build_request(host="localhost"))
        response = read_response(sock)
        assert response.status == 200
        assert response.body == b"Hello, World!"
    finally:
        sock.close()


def test_tls_keeps_alive_and_handles_large_bodies(tls_server: ServerThread):
    sock = _tls_socket(tls_server, ["h2", "http/1.1"])
    try:
        with H2Client(tls_server, sock=sock, initial_window_size=32768) as client:
            stream_id = client.request("/big?size=1000000")
            response = client.wait(stream_id, timeout=30)
            assert response.status == 200
            assert len(response.body) == 1000000
    finally:
        sock.close()


def test_tls_compression(tls_server: ServerThread):
    sock = _tls_socket(tls_server, ["http/1.1"])
    try:
        sock.sendall(
            build_request(
                target="/compressible",
                host="localhost",
                headers=[("Accept-Encoding", "gzip")],
            )
        )
        response = read_response(sock)
        assert response.header(b"content-encoding") == b"gzip"
        import gzip

        assert gzip.decompress(response.body) == b"compression test payload " * 200
    finally:
        sock.close()


def test_cleartext_port_serves_both_protocols():
    """One plaintext port: h2c prior knowledge and HTTP/1.1 both work."""
    with ServerThread() as plaintext:
        with H2Client(plaintext) as client:
            stream_id = client.request("/status/201")
            response = client.wait(stream_id)
            assert response.status == 201
        # The same listener must still be serving HTTP/1.1 clients.
        sock = plaintext.connect()
        try:
            sock.sendall(build_request(host="localhost"))
            assert read_response(sock).status == 200
        finally:
            sock.close()
