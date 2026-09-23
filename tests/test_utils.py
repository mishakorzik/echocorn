"""Unit tests for the shared helpers and the HTTP/1.1 request parser."""

from __future__ import annotations

import pytest

from echocorn import utils
from echocorn.config import ServerConfig
from echocorn.http1 import ChunkedDecoder, _ProtocolError, parse_request_head


# status / date helpers
def test_status_phrase_known_and_unknown():
    assert utils.status_phrase(200) == "OK"
    assert utils.status_phrase(404) == "Not Found"
    assert utils.status_phrase(418) == "I'm a Teapot"
    assert utils.status_phrase(599) == "Unknown Status"


def test_format_http_date_is_imf_fixdate():
    value = utils.format_http_date()
    assert value.endswith("GMT")
    # e.g. "Sun, 06 Nov 1994 08:49:37 GMT"
    assert len(value) == 29
    assert value[3] == "," and value[4] == " "


# Accept-Encoding negotiation (RFC 9110 12.5.3)
def _ae(value: str):
    return utils.negotiate_content_encoding([(b"accept-encoding", value.encode())])


def test_negotiate_picks_gzip_by_default():
    assert _ae("gzip, deflate") == "gzip"


def test_negotiate_respects_quality_order():
    assert _ae("deflate;q=0.9, gzip;q=0.1") == "deflate"


def test_negotiate_respects_explicit_rejection():
    assert _ae("gzip;q=0, deflate") == "deflate"
    assert _ae("gzip;q=0, deflate;q=0") is None


def test_negotiate_handles_wildcard():
    assert _ae("*") == "gzip"
    assert _ae("br, *") == "gzip"
    assert _ae("*;q=0") is None


def test_negotiate_ignores_unknown_and_missing():
    assert _ae("br") is None
    assert utils.negotiate_content_encoding([]) is None
    assert utils.negotiate_content_encoding([(b"x", b"gzip")]) is None


def test_negotiate_is_case_insensitive():
    assert _ae("GZIP") == "gzip"


# response header hygiene
def test_normalize_response_headers_drops_forbidden():
    headers = utils.normalize_response_headers(
        [
            (b"Content-Type", b"text/plain"),
            (b"Connection", b"close"),
            (b"Transfer-Encoding", b"chunked"),
            (b"Keep-Alive", b"timeout=5"),
            (b"TE", b"trailers"),
            (b"X-Custom", b"  spaced  "),
        ]
    )
    names = [name for name, _ in headers]
    assert b"Content-Type" in names
    assert b"X-Custom" in names
    assert not {b"Connection", b"Transfer-Encoding", b"Keep-Alive", b"TE"} & set(names)
    assert dict(headers)[b"X-Custom"] == b"spaced"


def test_normalize_response_headers_keeps_trailer_announcement():
    headers = utils.normalize_response_headers([(b"Trailer", b"x-checksum")])
    assert headers == [(b"Trailer", b"x-checksum")]


def test_normalize_response_headers_lowercases_for_http2():
    headers = utils.normalize_response_headers([(b"X-Test", b"1")], lowercase=True)
    assert headers == [(b"x-test", b"1")]


def test_normalize_response_headers_rejects_injection_and_bad_length():
    headers = utils.normalize_response_headers(
        [
            (b"X-Bad", b"value\r\nInjected: yes"),
            (b"content-length", b"not-a-number"),
            (b"content-length", b"-5"),
            (b"", b"empty-name"),
            (b"X-Ok", b"fine"),
        ]
    )
    assert headers == [(b"X-Ok", b"fine")]


def test_normalize_response_headers_accepts_strings():
    headers = utils.normalize_response_headers([("X-Str", "value")])
    assert headers == [(b"X-Str", b"value")]


def test_normalize_response_headers_rejects_names_that_are_not_tokens():
    headers = utils.normalize_response_headers(
        [
            (b"X Bad", b"1"),
            (b"X-Bad\r\nX-Injected", b"1"),
            (b"X:Bad", b"1"),
            (b"X-Good", b"1"),
        ]
    )
    assert headers == [(b"X-Good", b"1")]


# authority comparison (used by bind_domain)
def test_authority_host_strips_the_port():
    assert utils.authority_host(b"Example.COM:8000") == "example.com"
    assert utils.authority_host(b"example.com") == "example.com"


def test_authority_host_keeps_ipv6_literals():
    assert utils.authority_host(b"[::1]:8000") == "::1"
    assert utils.authority_host(b"::1") == "::1"


# compression decisions
def test_compressible_content_types():
    assert utils.compressible_content_type(b"text/html; charset=utf-8")
    assert utils.compressible_content_type(b"application/json")
    assert utils.compressible_content_type(b"application/vnd.api+json")
    assert not utils.compressible_content_type(b"image/png")
    assert not utils.compressible_content_type(b"application/octet-stream")
    assert not utils.compressible_content_type(b"")


def test_should_compress_rules():
    request_headers = [(b"accept-encoding", b"gzip")]
    plain = [(b"content-type", b"text/plain"), (b"content-length", b"2048")]
    assert utils.should_compress("GET", 200, plain, request_headers) == "gzip"
    # HEAD / 204 / 304 never carry a body
    assert utils.should_compress("HEAD", 200, plain, request_headers) is None
    assert utils.should_compress("GET", 204, plain, request_headers) is None
    assert utils.should_compress("GET", 304, plain, request_headers) is None
    # already encoded / partial / too small
    assert (
        utils.should_compress(
            "GET", 200, plain + [(b"content-encoding", b"br")], request_headers
        )
        is None
    )
    assert utils.should_compress("GET", 206, plain, request_headers) is None
    small = [(b"content-type", b"text/plain"), (b"content-length", b"10")]
    assert utils.should_compress("GET", 200, small, request_headers) is None
    assert (
        utils.should_compress("GET", 200, [(b"content-type", b"image/png")], request_headers)
        is None
    )


def test_compressible_response_is_what_the_response_alone_decides():
    plain = [(b"content-type", b"text/plain"), (b"content-length", b"2048")]
    assert utils.compressible_response("GET", 200, plain)
    assert not utils.compressible_response("HEAD", 200, plain)
    assert not utils.compressible_response("GET", 304, plain)
    assert not utils.compressible_response("GET", 206, plain)
    assert not utils.compressible_response(
        "GET", 200, [(b"content-type", b"text/plain")] + [(b"content-range", b"bytes 0-9/100")]
    )
    assert not utils.compressible_response(
        "GET", 200, [(b"content-type", b"text/plain"), (b"content-encoding", b"br")]
    )
    assert not utils.compressible_response("GET", 200, [(b"content-type", b"image/png")])


def test_add_vary_extends_and_never_replaces():
    assert utils.add_vary([]) == [(b"vary", b"Accept-Encoding")]
    assert utils.add_vary([(b"vary", b"Accept-Language")]) == [
        (b"vary", b"Accept-Language, Accept-Encoding")
    ]
    # Already announced (however it is spelled), or covered by the wildcard.
    assert utils.add_vary([(b"vary", b"accept-encoding")]) == [(b"vary", b"accept-encoding")]
    assert utils.add_vary([(b"vary", b"Accept-Language, Accept-Encoding")]) == [
        (b"vary", b"Accept-Language, Accept-Encoding")
    ]
    assert utils.add_vary([(b"vary", b"*")]) == [(b"vary", b"*")]
    # The header list the application sent is left alone.
    original = [(b"vary", b"Accept-Language")]
    utils.add_vary(original)
    assert original == [(b"vary", b"Accept-Language")]


def test_compressor_roundtrip_gzip_and_deflate():
    import gzip
    import zlib

    payload = b"hello world " * 100
    gz = utils.Compressor("gzip")
    blob = gz.compress(payload) + gz.flush()
    assert gzip.decompress(blob) == payload

    df = utils.Compressor("deflate")
    blob = df.compress(payload) + df.flush()
    # RFC 9110 requires the zlib wrapper for "deflate".
    assert zlib.decompress(blob) == payload

    with pytest.raises(ValueError):
        utils.Compressor("brotli")


# chunked decoder
def test_chunked_decoder_streams_incrementally():
    decoder = ChunkedDecoder()
    buffer = bytearray(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    chunks = decoder.feed(buffer, 0)
    assert b"".join(chunks) == b"hello world"
    assert decoder.done
    assert buffer == b""


def test_chunked_decoder_handles_split_input():
    decoder = ChunkedDecoder()
    collected = []
    for part in (b"4\r\nab", b"cd\r\n", b"0\r\n", b"\r\n"):
        buffer = bytearray(part)
        collected.extend(decoder.feed(buffer, 0))
    assert b"".join(collected) == b"abcd"
    assert decoder.done


def test_chunked_decoder_accepts_extensions_and_trailers():
    decoder = ChunkedDecoder()
    buffer = bytearray(b"3;a=b\r\nabc\r\n0\r\nx-trailer: 1\r\n\r\n")
    chunks = decoder.feed(buffer, 0)
    assert b"".join(chunks) == b"abc"
    assert decoder.done


def test_chunked_decoder_rejects_garbage():
    decoder = ChunkedDecoder()
    with pytest.raises(_ProtocolError):
        decoder.feed(bytearray(b"zz\r\nabc\r\n"), 0)


def test_chunked_decoder_enforces_max_size():
    decoder = ChunkedDecoder()
    with pytest.raises(_ProtocolError) as excinfo:
        decoder.feed(bytearray(b"1000\r\n"), 16)
    assert excinfo.value.status == 413


# request head parsing
CONFIG = ServerConfig()


def _head(raw: bytes):
    return parse_request_head(bytearray(raw), CONFIG)


def test_parse_simple_request():
    head = _head(b"GET /path?a=1 HTTP/1.1\r\nHost: example.com\r\nX-A: b\r\n\r\n")
    assert head is not None
    assert head.method == b"GET"
    assert head.target == b"/path?a=1"
    assert head.version == "1.1"
    assert head.keep_alive is True
    assert (b"host", b"example.com") in head.headers


def test_parse_returns_none_until_head_complete():
    assert parse_request_head(bytearray(b"GET / HTTP/1.1\r\n"), CONFIG) is None


def test_parse_header_without_space_is_accepted():
    head = _head(b"GET / HTTP/1.1\r\nHost:example.com\r\nX:1\r\n\r\n")
    assert head is not None
    assert (b"host", b"example.com") in head.headers
    assert (b"x", b"1") in head.headers


def test_parse_rejects_obs_fold():
    with pytest.raises(_ProtocolError) as excinfo:
        _head(b"GET / HTTP/1.1\r\nHost: x\r\nX: a\r\n b\r\n\r\n")
    assert excinfo.value.status == 400


def test_parse_rejects_missing_host_on_http11():
    with pytest.raises(_ProtocolError) as excinfo:
        _head(b"GET / HTTP/1.1\r\n\r\n")
    assert excinfo.value.status == 400


def test_parse_rejects_te_with_content_length():
    with pytest.raises(_ProtocolError) as excinfo:
        _head(
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
        )
    assert excinfo.value.status == 400


def test_parse_rejects_conflicting_content_lengths():
    with pytest.raises(_ProtocolError) as excinfo:
        _head(
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n"
        )
    assert excinfo.value.status == 400


def test_parse_accepts_duplicate_identical_content_length():
    head = _head(
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n"
    )
    assert head is not None and head.content_length == 3


def test_parse_rejects_unsupported_transfer_coding():
    with pytest.raises(_ProtocolError) as excinfo:
        _head(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n")
    assert excinfo.value.status in (400, 501)


def test_parse_rejects_double_chunked():
    with pytest.raises(_ProtocolError) as excinfo:
        _head(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, chunked\r\n\r\n")
    assert excinfo.value.status == 400


def test_parse_rejects_unknown_method_with_allow():
    with pytest.raises(_ProtocolError) as excinfo:
        _head(b"BREW / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert excinfo.value.status == 405
    assert "GET" in (excinfo.value.allow or "")


def test_parse_rejects_bad_expectation():
    with pytest.raises(_ProtocolError) as excinfo:
        _head(b"POST / HTTP/1.1\r\nHost: x\r\nExpect: something-else\r\n\r\n")
    assert excinfo.value.status == 417


def test_parse_sets_expect_continue():
    head = _head(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nExpect: 100-continue\r\n\r\n")
    assert head is not None and head.expect_continue is True


def test_parse_rejects_oversized_head():
    raw = b"GET / HTTP/1.1\r\nHost: x\r\nX: " + b"a" * 20000 + b"\r\n\r\n"
    with pytest.raises(_ProtocolError) as excinfo:
        _head(raw)
    assert excinfo.value.status == 431


def test_parse_rejects_too_many_headers():
    headers = b"".join(b"X-%d: v\r\n" % i for i in range(200))
    with pytest.raises(_ProtocolError) as excinfo:
        _head(b"GET / HTTP/1.1\r\nHost: x\r\n" + headers + b"\r\n")
    assert excinfo.value.status == 431


def test_parse_http10_implies_close():
    head = _head(b"GET / HTTP/1.0\r\n\r\n")
    assert head is not None
    assert head.version == "1.0"
    assert head.keep_alive is False


def test_parse_http10_keep_alive_with_known_authority():
    head = _head(b"GET / HTTP/1.0\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
    assert head is not None and head.keep_alive is True


def test_parse_http10_keep_alive_without_authority_closes():
    # Without a Host header or an absolute target the authority is unknown, so
    # reusing the connection could send the next request to another origin.
    head = _head(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
    assert head is not None and head.keep_alive is False


def test_parse_connection_close_on_http11():
    head = _head(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert head is not None and head.keep_alive is False


def test_parse_body_size_limit():
    config = ServerConfig(max_request_size=10)
    with pytest.raises(_ProtocolError) as excinfo:
        parse_request_head(bytearray(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\n"), config)
    assert excinfo.value.status == 413
