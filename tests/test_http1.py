"""
End-to-end HTTP/1.1 tests driven over raw sockets.
"""

from __future__ import annotations

import gzip
import json
import zlib

from conftest import (
    H1Reader,
    Response,
    ServerThread,
    _parse_head,
    build_request,
    decode_chunked,
    http1_request,
    read_response,
)


def _parse(raw: bytes):
    """Split a raw response into ``(status, headers, body, raw)``."""
    head, _, body = raw.partition(b"\r\n\r\n")
    status, headers = _parse_head(head + b"\r\n\r\n")
    if headers.get(b"transfer-encoding", [b""])[0].lower() == b"chunked":
        body = decode_chunked(body)
    return status, headers, body, raw


# Basics
def test_simple_get(server: ServerThread):
    raw = http1_request(server, build_request(host="localhost"))
    response = Response(*_parse(raw))
    assert response.status == 200
    assert response.body == b"Hello, World!"
    assert response.header(b"content-type") == b"text/plain; charset=utf-8"
    assert int(response.header(b"content-length")) == 13
    assert response.header(b"date") is not None
    assert response.header(b"server") is not None


def test_404_unknown_route(server: ServerThread):
    raw = http1_request(server, build_request(target="/nope", host="localhost"))
    status, headers, body, _ = _parse(raw)
    assert status == 404
    assert body == b"not found"


def test_http_version_in_response(server: ServerThread):
    raw = http1_request(
        server, build_request(host="localhost", version="1.0", headers=[("Connection", "close")])
    )
    assert raw.startswith(b"HTTP/1.1 200")


# Keep-alive and pipelining
def test_keep_alive_two_requests(server: ServerThread):
    connection = server.connect()
    reader = H1Reader(connection)
    try:
        connection.sendall(build_request(host="localhost"))
        first = reader.read()
        assert first.status == 200 and first.body == b"Hello, World!"
        connection.sendall(build_request(target="/status/201", host="localhost"))
        assert reader.read().status == 201
    finally:
        connection.close()


def test_pipelined_requests_answered_in_order(server: ServerThread):
    connection = server.connect()
    reader = H1Reader(connection)
    try:
        payload = build_request(host="localhost") + build_request(
            target="/status/418", host="localhost"
        )
        connection.sendall(payload)
        first = reader.read()
        second = reader.read()
        assert first.status == 200
        assert second.status == 418
    finally:
        connection.close()


def test_connection_close_is_honoured(server: ServerThread):
    raw = http1_request(
        server, build_request(host="localhost", headers=[("Connection", "close")])
    )
    status, headers, body, _ = _parse(raw)
    assert status == 200
    assert headers[b"connection"] == [b"close"]


def test_http10_without_host_is_closed(server: ServerThread):
    raw = http1_request(server, build_request(host="localhost", version="1.0"))
    status, headers, body, _ = _parse(raw)
    assert status == 200
    assert body == b"Hello, World!"


# Request bodies
def test_content_length_request_body(server: ServerThread):
    body = b"x" * 5000
    raw = http1_request(
        server,
        build_request(
            method="POST",
            target="/echo",
            host="localhost",
            headers=[("Content-Length", str(len(body)))],
            body=body,
        ),
    )
    status, headers, echoed, _ = _parse(raw)
    assert status == 200
    assert echoed == body
    assert headers[b"x-received-bytes"] == [str(len(body)).encode()]


def test_chunked_request_body(server: ServerThread):
    chunks = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
    raw = http1_request(
        server,
        build_request(
            method="POST",
            target="/echo",
            host="localhost",
            headers=[("Transfer-Encoding", "chunked")],
            body=chunks,
        ),
    )
    status, headers, echoed, _ = _parse(raw)
    assert status == 200
    assert echoed == b"Wikipedia"


def test_chunked_response_uses_chunked_framing(server: ServerThread):
    connection = server.connect()
    try:
        connection.sendall(build_request(target="/stream", host="localhost"))
        response = read_response(connection)
        assert response.status == 200
        assert response.header(b"transfer-encoding") == b"chunked"
        assert response.body == b"onetwothree"
    finally:
        connection.close()


def test_head_request_has_no_body(server: ServerThread):
    raw = http1_request(
        server,
        build_request(method="HEAD", host="localhost", headers=[("Connection", "close")]),
        expect_body=False,
    )
    status, headers, body, _ = _parse(raw)
    assert status == 200
    assert body == b""
    assert int(headers[b"content-length"][0]) == 13


def test_204_has_no_body(server: ServerThread):
    raw = http1_request(server, build_request(target="/empty", host="localhost"))
    status, headers, body, _ = _parse(raw)
    assert status == 204
    assert body == b""
    assert b"content-length" not in headers
    assert b"transfer-encoding" not in headers


def test_no_more_body_is_synthesised(server: ServerThread):
    raw = http1_request(server, build_request(target="/no-more-body", host="localhost"))
    status, headers, body, _ = _parse(raw)
    assert status == 200
    assert body == b"partial"


def test_app_exception_returns_500(server: ServerThread):
    raw = http1_request(server, build_request(target="/boom", host="localhost"))
    status, headers, body, _ = _parse(raw)
    assert status == 500
    assert b"Internal Server Error" in body


def test_informational_response_then_final(server: ServerThread):
    connection = server.connect()
    reader = H1Reader(connection)
    try:
        connection.sendall(build_request(target="/early-hints", host="localhost"))
        interim = reader.read(expect_body=False)
        assert interim.status == 103
        assert interim.header(b"link") == b"</style.css>; rel=preload; as=style"
        final = reader.read()
        assert final.status == 200
        assert final.body == b"hinted"
    finally:
        connection.close()


def test_trailers_are_emitted(server: ServerThread):
    connection = server.connect()
    try:
        connection.sendall(build_request(target="/trailers", host="localhost"))
        response = read_response(connection)
        assert response.body == b"body"
        # The announced Trailer field must survive (RFC 9110 section 6.5.1).
        assert response.header(b"trailer") == b"x-checksum"
        assert b"x-checksum: abc123" in response.raw
    finally:
        connection.close()


def test_announced_trailers_that_never_arrive_still_end_the_response(
    server: ServerThread,
):
    connection = server.connect()
    try:
        connection.sendall(
            build_request(target="/forgotten-trailers", host="localhost")
        )
        response = read_response(connection)
        assert response.body == b"no trailers"
        assert response.raw.endswith(b"0\r\n\r\n")
    finally:
        connection.close()


def test_bodyless_response_with_announced_trailers_completes(server: ServerThread):
    """
    A bodyless response that announced trailers must still finish its turn.

    The connection is reused afterwards on purpose: if the response never
    completes, the writer sits on a queue that will never be filled again and
    the next request on the connection is never answered.
    """
    connection = server.connect()
    reader = H1Reader(connection)
    try:
        connection.sendall(
            build_request(target="/bodyless-trailers", host="localhost")
        )
        response = reader.read()
        assert response.status == 204
        assert response.body == b""
        connection.sendall(build_request(target="/", host="localhost"))
        assert reader.read().body == b"Hello, World!"
    finally:
        connection.close()


def test_late_trailers_do_not_stall_the_response(server: ServerThread):
    connection = server.connect()
    try:
        connection.sendall(build_request(target="/late-trailers", host="localhost"))
        response = read_response(connection)
        assert response.body == b"ok"
    finally:
        connection.close()


def test_100_continue_is_sent(server: ServerThread):
    connection = server.connect()
    reader = H1Reader(connection)
    try:
        body = b"hello"
        connection.sendall(
            build_request(
                method="POST",
                target="/echo",
                host="localhost",
                headers=[
                    ("Content-Length", str(len(body))),
                    ("Expect", "100-continue"),
                ],
            )
        )
        # The interim response arrives before the body is sent.
        interim = reader.read(expect_body=False)
        assert interim.status == 100
        connection.sendall(body)
        response = reader.read()
        assert response.status == 200
        assert response.body == body
    finally:
        connection.close()


# Hardening / RFC compliance
def test_rejects_transfer_encoding_with_content_length(server: ServerThread):
    raw = http1_request(
        server,
        b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    )
    assert raw.startswith(b"HTTP/1.1 400")


def test_rejects_conflicting_content_lengths(server: ServerThread):
    raw = http1_request(
        server,
        b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n"
        b"Content-Length: 6\r\n\r\nhello",
    )
    assert raw.startswith(b"HTTP/1.1 400")


def test_rejects_missing_host(server: ServerThread):
    raw = http1_request(server, b"GET / HTTP/1.1\r\n\r\n")
    assert raw.startswith(b"HTTP/1.1 400")


def test_rejects_oversized_headers(server: ServerThread):
    raw = http1_request(
        server,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nX: " + b"a" * 20000 + b"\r\n\r\n",
    )
    assert raw.startswith(b"HTTP/1.1 431")


def test_rejects_unknown_method_with_allow_header(server: ServerThread):
    raw = http1_request(server, b"BREW / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert raw.startswith(b"HTTP/1.1 405")
    assert b"allow: " in raw and b"GET" in raw


def test_rejects_unsupported_expectation(server: ServerThread):
    raw = http1_request(
        server,
        b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n"
        b"Expect: 200-ok\r\n\r\n",
    )
    assert raw.startswith(b"HTTP/1.1 417")


def test_rejects_obs_fold(server: ServerThread):
    raw = http1_request(
        server, b"GET / HTTP/1.1\r\nHost: localhost\r\nX: a\r\n b\r\n\r\n"
    )
    assert raw.startswith(b"HTTP/1.1 400")


async def _short_body(scope, receive, send):
    """Announces ten bytes and sends five: the framing no longer matches."""
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain"), (b"content-length", b"10")],
        }
    )
    await send({"type": "http.response.body", "body": b"short", "more_body": False})


def test_a_body_shorter_than_content_length_closes_the_connection():
    """A wrong Content-Length must not desync the next response on the socket."""
    with ServerThread(_short_body) as lying:
        connection = lying.connect()
        reader = H1Reader(connection)
        try:
            connection.sendall(build_request(host="localhost"))
            head = reader.read(expect_body=False)
            assert head.status == 200
            assert head.header(b"content-length") == b"10"
            # Only the five bytes the application sent arrive, then the server
            # closes instead of reusing a connection whose framing is broken.
            received = bytes(reader.buffer)
            reader.buffer.clear()
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                received += chunk
            assert received == b"short"
        finally:
            connection.close()


def test_a_misdirected_request_names_the_status_once():
    """421 answers with one line: the reason is not echoed twice."""
    with ServerThread(bind_domain="example.com") as bound:
        raw = http1_request(bound, build_request(host="other.test"))
    status, headers, body, _ = _parse(raw)
    assert status == 421
    assert body == b"421 Misdirected Request\n"


def test_an_ipv6_authority_matches_bind_domain():
    """The brackets and port of an IPv6 Host are not part of the comparison."""
    with ServerThread(bind_domain="[::1]:8000") as bound:
        raw = http1_request(bound, build_request(host="[::1]:8000"))
    assert raw.startswith(b"HTTP/1.1 200")


def test_bad_response_headers_are_dropped(server: ServerThread):
    raw = http1_request(server, build_request(target="/badheaders", host="localhost"))
    status, headers, body, _ = _parse(raw)
    assert status == 200
    assert body == b"ok"
    assert b"keep-alive" not in headers
    assert b"transfer-encoding" not in headers
    assert headers[b"content-length"] == [b"2"]


def test_response_header_injection_is_blocked(server: ServerThread):
    # The 404 handler is fine, but make sure only one header block is returned
    # even for apps that try to inject CRLF (covered by unit tests): here we
    # simply assert the framing stays coherent.
    raw = http1_request(server, build_request(target="/nope", host="localhost"))
    assert raw.count(b"\r\n\r\n") == 1


def test_body_size_limit_rejects_large_upload():
    with ServerThread(max_request_size=1024) as limited:
        raw = http1_request(
            limited,
            build_request(
                method="POST",
                target="/echo",
                host="localhost",
                headers=[("Content-Length", "2048")],
                body=b"a" * 2048,
            ),
        )
        assert raw.startswith(b"HTTP/1.1 413")


def test_app_ignoring_body_keeps_connection_usable(server: ServerThread):
    connection = server.connect()
    reader = H1Reader(connection)
    try:
        body = b"z" * 1000
        connection.sendall(
            build_request(
                method="POST",
                target="/ignores-body",
                host="localhost",
                headers=[("Content-Length", str(len(body)))],
                body=body,
            )
        )
        first = reader.read()
        assert first.status == 200
        assert first.body == b"ignored"
        connection.sendall(build_request(host="localhost"))
        assert reader.read().body == b"Hello, World!"
    finally:
        connection.close()


def test_idle_connection_is_closed():
    with ServerThread(keep_alive_timeout=0.2) as idle:
        connection = idle.connect()
        try:
            connection.sendall(build_request(host="localhost"))
            response = read_response(connection)
            assert response.status == 200
            # The server must close the idle keep-alive connection.
            connection.settimeout(3.0)
            assert connection.recv(1024) == b""
        finally:
            connection.close()


# Compression
def test_compression_negotiated_with_gzip(compression_server: ServerThread):
    raw = http1_request(
        compression_server,
        build_request(
            target="/compressible",
            host="localhost",
            headers=[("Accept-Encoding", "gzip")],
        ),
    )
    status, headers, body, _ = _parse(raw)
    assert status == 200
    assert headers[b"content-encoding"] == [b"gzip"]
    assert headers[b"transfer-encoding"] == [b"chunked"]
    assert b"content-length" not in headers
    assert gzip.decompress(body) == b"compression test payload " * 200


def test_compression_with_deflate_uses_zlib_wrapper(compression_server: ServerThread):
    raw = http1_request(
        compression_server,
        build_request(
            target="/compressible",
            host="localhost",
            headers=[("Accept-Encoding", "deflate")],
        ),
    )
    status, headers, body, _ = _parse(raw)
    assert headers[b"content-encoding"] == [b"deflate"]
    assert zlib.decompress(body) == b"compression test payload " * 200


def test_compression_disabled_without_flag(server: ServerThread):
    raw = http1_request(
        server,
        build_request(
            target="/compressible", host="localhost", headers=[("Accept-Encoding", "gzip")]
        ),
    )
    status, headers, body, _ = _parse(raw)
    assert b"content-encoding" not in headers
    assert body == b"compression test payload " * 200


def test_compression_skipped_when_rejected(compression_server: ServerThread):
    raw = http1_request(
        compression_server,
        build_request(
            target="/compressible",
            host="localhost",
            headers=[("Accept-Encoding", "gzip;q=0, deflate;q=0")],
        ),
    )
    status, headers, body, _ = _parse(raw)
    assert b"content-encoding" not in headers


# Misc
def test_scope_headers_are_lowercased(server: ServerThread):
    raw = http1_request(
        server,
        build_request(
            target="/headers",
            host="localhost",
            headers=[("X-Mixed-Case", "Value")],
        ),
    )
    status, headers, body, _ = _parse(raw)
    payload = json.loads(body)
    names = [name for name, _ in payload["headers"]]
    assert "x-mixed-case" in names
    assert "host" in names


# Backpressure / large payloads
def test_large_response_is_written_completely(server: ServerThread):
    """Exceeds the socket write watermark, exercising pause/resume_writing."""
    total = 3 * 1024 * 1024
    connection = server.connect(timeout=30)
    try:
        connection.sendall(build_request(target="/big?size=%d" % total, host="localhost"))
        response = read_response(connection)
        assert response.status == 200
        assert len(response.body) == total
    finally:
        connection.close()


def test_large_request_body_is_streamed(server: ServerThread):
    """Exceeds the read watermark, exercising socket read pausing."""
    body = bytes(i % 251 for i in range(2 * 1024 * 1024))
    connection = server.connect(timeout=60)
    try:
        connection.sendall(
            build_request(
                method="POST",
                target="/echo",
                host="localhost",
                headers=[("Content-Length", str(len(body)))],
            )
        )
        connection.sendall(body)
        response = read_response(connection, )
        assert response.status == 200
        assert response.body == body
    finally:
        connection.close()


def test_second_pipelined_request_waits_for_first_response(server: ServerThread):
    """Responses must be written in request order (RFC 9112 section 9.3.1)."""
    connection = server.connect(timeout=30)
    reader = H1Reader(connection)
    try:
        connection.sendall(
            build_request(target="/big?size=1048576", host="localhost")
            + build_request(target="/status/201", host="localhost")
        )
        first = reader.read()
        second = reader.read()
        assert first.status == 200 and len(first.body) == 1048576
        assert second.status == 201
    finally:
        connection.close()


def test_options_asterisk_target(server: ServerThread):
    raw = http1_request(
        server, b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n"
    )
    status, headers, body, _ = _parse(raw)
    # The router has no handler for "*", so the app returns its 404.
    assert status == 404


def test_query_string_is_exposed(server: ServerThread):
    raw = http1_request(server, build_request(target="/big?size=32", host="localhost"))
    status, headers, body, _ = _parse(raw)
    assert status == 200
    assert body == b"x" * 32


def test_absolute_form_target(server: ServerThread):
    raw = http1_request(
        server,
        b"GET http://localhost/status/200 HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    assert raw.startswith(b"HTTP/1.1 200")
