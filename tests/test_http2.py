"""
End-to-end HTTP/2 (h2c prior knowledge) tests.

These tests drive the server with hyper-h2's client state machine over a plain
TCP socket, with full flow-control accounting. The large-body cases are the
regression tests for the flow-control bug in the original implementation:
``h2.send_data`` raises ``FlowControlError`` as soon as a response exceeds the
64 KiB window unless the writer waits for ``WINDOW_UPDATE`` frames.
"""

from __future__ import annotations

import gzip

from conftest import H2Client, ServerThread


def test_simple_get(server: ServerThread):
    with H2Client(server) as client:
        stream_id = client.request("/")
        response = client.wait(stream_id)
        assert response.status == 200
        assert bytes(response.body) == b"Hello, World!"
        assert response.header(b"content-type") == b"text/plain; charset=utf-8"
        assert response.header(b"content-length") == b"13"
        assert response.header(b"server") is not None
        assert response.header(b"date") is not None


def test_404(server: ServerThread):
    with H2Client(server) as client:
        stream_id = client.request("/missing")
        response = client.wait(stream_id)
        assert response.status == 404


def test_method_not_allowed(server: ServerThread):
    with H2Client(server) as client:
        stream_id = client.request("/", method="BREW")
        response = client.wait(stream_id)
        assert response.status == 405
        assert response.header(b"allow") is not None


def test_head_keeps_content_length_but_has_no_body(server: ServerThread):
    with H2Client(server) as client:
        stream_id = client.request("/", method="HEAD")
        response = client.wait(stream_id)
        assert response.status == 200
        assert bytes(response.body) == b""
        assert response.header(b"content-length") == b"13"


def test_204_has_no_body(server: ServerThread):
    with H2Client(server) as client:
        stream_id = client.request("/empty")
        response = client.wait(stream_id)
        assert response.status == 204
        assert bytes(response.body) == b""
        assert response.header(b"content-length") is None


def test_app_exception_returns_500(server: ServerThread):
    with H2Client(server) as client:
        stream_id = client.request("/boom")
        response = client.wait(stream_id)
        assert response.status == 500


def test_connection_with_content_length(server: ServerThread):
    with H2Client(server) as client:
        stream_id = client.request("/compressible")
        response = client.wait(stream_id)
        assert response.status == 200
        assert len(response.body) == len(b"compression test payload " * 200)


# Flow control - the regression tests
def test_large_response_respects_flow_control(server: ServerThread):
    total = 2 * 1024 * 1024
    with H2Client(server) as client:
        stream_id = client.request("/big?size=%d" % total)
        response = client.wait(stream_id, timeout=30)
        assert response.status == 200
        assert len(response.body) == total
        assert bytes(response.body) == b"x" * total


def test_large_request_body_roundtrip(server: ServerThread):
    total = 1024 * 1024
    payload = bytes(i % 251 for i in range(total))
    with H2Client(server) as client:
        stream_id = client.request("/echo", method="POST", body=payload)
        response = client.wait(stream_id, timeout=30)
        assert response.status == 200
        assert response.header(b"x-received-bytes") == str(total).encode()
        assert bytes(response.body) == payload


def test_tiny_window_forces_window_updates(server: ServerThread):
    """A 16 KiB peer window means ~128 round trips of flow control credit."""
    total = 2 * 1024 * 1024
    with H2Client(server, initial_window_size=16384) as client:
        stream_id = client.request("/big?size=%d" % total)
        response = client.wait(stream_id, timeout=30)
        assert response.status == 200
        assert len(response.body) == total


def test_many_parallel_streams(server: ServerThread):
    with H2Client(server) as client:
        streams = [
            client.request("/big?size=300000"),
            client.request("/"),
            client.request("/stream"),
            client.request("/echo", method="POST", body=b"z" * 100000),
        ]
        for stream_id in streams:
            response = client.wait(stream_id, timeout=30)
            assert response.status == 200
        assert len(client.responses[streams[0]].body) == 300000
        assert bytes(client.responses[streams[1]].body) == b"Hello, World!"
        assert bytes(client.responses[streams[2]].body) == b"onetwothree"
        assert bytes(client.responses[streams[3]].body) == b"z" * 100000


def test_stream_reset_keeps_connection_usable(server: ServerThread):
    with H2Client(server) as client:
        stream_id = client.request("/big?size=4000000")

        def has_data() -> bool:
            response = client.responses.get(stream_id)
            return bool(response and response.body)

        client._pump(has_data, timeout=10)
        client.conn.reset_stream(stream_id, error_code=8)  # CANCEL
        client.sock.sendall(client.conn.data_to_send())

        stream_id2 = client.request("/")
        response = client.wait(stream_id2, timeout=10)
        assert response.status == 200
        assert bytes(response.body) == b"Hello, World!"


def test_app_ignoring_body_keeps_connection_usable(server: ServerThread):
    with H2Client(server) as client:
        stream_id = client.request("/ignores-body", method="POST", body=b"q" * 200000)
        response = client.wait(stream_id, timeout=20)
        assert response.status == 200
        assert bytes(response.body) == b"ignored"
        stream_id2 = client.request("/", method="POST", body=b"")
        response2 = client.wait(stream_id2, timeout=10)
        assert response2.status == 200


# Header hygiene
def test_forbidden_headers_are_stripped(server: ServerThread):
    with H2Client(server) as client:
        stream_id = client.request("/badheaders")
        response = client.wait(stream_id)
        assert response.status == 200
        assert bytes(response.body) == b"ok"
        names = {name for name, _ in response.headers}
        assert b"connection" not in names
        assert b"transfer-encoding" not in names
        assert b"keep-alive" not in names
        assert response.header(b"content-length") == b"2"
        # The connection must still be healthy (h2 would have raised above).
        assert client.goaway is None


def test_informational_response_then_final(server: ServerThread):
    with H2Client(server) as client:
        stream_id = client.request("/early-hints")
        response = client.wait(stream_id)
        assert response.status == 200
        assert bytes(response.body) == b"hinted"
        assert client.informational
        assert client.informational[0][0] == (b":status", b"103")


def test_trailers_are_sent(server: ServerThread):
    with H2Client(server) as client:
        stream_id = client.request("/trailers")
        response = client.wait(stream_id)
        assert response.status == 200
        assert bytes(response.body) == b"body"
        assert (b"x-checksum", b"abc123") in response.trailers


def test_announced_trailers_that_never_arrive_still_end_the_stream(server: ServerThread):
    """A forgotten trailer block must not stall the stream until the deadline."""
    with H2Client(server) as client:
        stream_id = client.request("/forgotten-trailers")
        response = client.wait(stream_id, timeout=5.0)
        assert response.status == 200
        assert bytes(response.body) == b"no trailers"
        assert response.ended


def test_bodyless_response_with_announced_trailers_completes(server: ServerThread):
    """A bodyless response that announced trailers must still finish its turn."""
    with H2Client(server) as client:
        stream_id = client.request("/bodyless-trailers")
        response = client.wait(stream_id, timeout=5.0)
        assert response.status == 204
        assert response.ended
        # The stream must not be left half finished: a later stream still works
        # and the stalled one is not reset by the stream deadline.
        other = client.request("/")
        assert client.wait(other, timeout=5.0).status == 200
        assert client.resets == []


def test_late_trailers_do_not_stall_the_response(server: ServerThread):
    with H2Client(server) as client:
        stream_id = client.request("/late-trailers")
        response = client.wait(stream_id, timeout=5.0)
        assert response.status == 200
        assert bytes(response.body) == b"ok"


def test_ping_is_acknowledged(server: ServerThread):
    with H2Client(server) as client:
        client.conn.ping(b"echocorn")
        client.sock.sendall(client.conn.data_to_send())
        client._pump(lambda: bool(client.ping_acks), timeout=5)
        assert b"echocorn" in client.ping_acks


# Compression
def test_compression_over_http2(compression_server: ServerThread):
    with H2Client(compression_server) as client:
        stream_id = client.request(
            "/compressible", headers=[(b"accept-encoding", b"gzip")]
        )
        response = client.wait(stream_id)
        assert response.status == 200
        assert response.header(b"content-encoding") == b"gzip"
        assert gzip.decompress(bytes(response.body)) == b"compression test payload " * 200


def test_compression_skipped_when_not_accepted(compression_server: ServerThread):
    with H2Client(compression_server) as client:
        stream_id = client.request(
            "/compressible", headers=[(b"accept-encoding", b"gzip;q=0, deflate;q=0")]
        )
        response = client.wait(stream_id)
        assert response.header(b"content-encoding") is None
        assert bytes(response.body) == b"compression test payload " * 200


def test_compression_disabled_without_flag(server: ServerThread):
    with H2Client(server) as client:
        stream_id = client.request(
            "/compressible", headers=[(b"accept-encoding", b"gzip")]
        )
        response = client.wait(stream_id)
        assert response.header(b"content-encoding") is None


# Misc
def test_query_string_and_path(server: ServerThread):
    with H2Client(server) as client:
        stream_id = client.request("/big?size=64")
        response = client.wait(stream_id)
        assert len(response.body) == 64


def test_authority_binding_rejected():
    with ServerThread(bind_domain="example.com") as bound, H2Client(bound) as client:
        stream_id = client.request("/")
        response = client.wait(stream_id)
        assert response.status == 421
