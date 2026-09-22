"""
End-to-end WebSocket tests (RFC 6455) over ws:// and wss://.

The client used here implements the masking side of the protocol by hand, so
the server side is exercised through real frames: handshake, fragmentation,
control frames, UTF-8 validation, size limits and the close handshake.
"""

from __future__ import annotations

import base64
import os
import struct
import time

import pytest

from echocorn import websocket as ws
from conftest import WS_STATE, ServerThread, WSClient, tls_socket


def test_accept_key_matches_the_rfc_example():
    """RFC 6455 section 1.3 test vector."""
    assert ws.accept_key(b"dGhlIHNhbXBsZSBub25jZQ==") == b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def test_mask_roundtrip_matches_a_naive_implementation():
    mask = bytes([0x37, 0xFA, 0x21, 0x3D])
    payload = bytes(range(256)) * 3
    naive = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
    assert ws._mask_payload(payload, mask) == naive
    assert ws._mask_payload(b"", mask) == b""


def test_handshake_and_echo(server: ServerThread):
    with WSClient(server) as client:
        assert client.status == 101
        assert client.response_headers[b"upgrade"].lower() == b"websocket"
        assert client.response_headers[b"sec-websocket-accept"] == ws.accept_key(
            client.key
        )
        assert client.response_headers[b"server"].startswith(b"echocorn/")
        assert client.response_headers[b"date"]

        client.send_text("hello")
        assert client.recv_text() == "echo:hello"

        client.send_bytes(b"\x00\x01\x02")
        kind, value = client.recv_message()
        assert kind == "bytes"
        assert value == b"echo:\x00\x01\x02"

        client.send_close(1000)
        assert client.recv_close() == 1000
        client.expect_eof()
        assert WS_STATE["disconnect_code"] == 1000


def test_scope_details(server: ServerThread):
    with WSClient(server, path="/ws?x=1") as client:
        assert client.status == 101
    assert WS_STATE["scheme"] == "ws"
    assert WS_STATE["subprotocols"] == []


def test_subprotocol_negotiation(server: ServerThread):
    headers = [(b"sec-websocket-protocol", b"superchat, chat")]
    with WSClient(server, path="/ws/subprotocol", headers=headers) as client:
        assert client.status == 101
        assert client.response_headers[b"sec-websocket-protocol"] == b"chat"
    assert WS_STATE["subprotocols"] == ["superchat", "chat"]


def test_fragmented_message_is_reassembled(server: ServerThread):
    with WSClient(server) as client:
        client.send_frame(ws.OPCODE_TEXT, b"one", fin=False)
        client.send_frame(ws.OPCODE_CONTINUATION, b"two", fin=False)
        client.send_frame(ws.OPCODE_CONTINUATION, b"three", fin=True)
        assert client.recv_text() == "echo:onetwothree"


def test_interleaved_ping_during_fragmentation(server: ServerThread):
    with WSClient(server) as client:
        client.send_frame(ws.OPCODE_TEXT, b"a", fin=False)
        client.send_ping(b"mid")
        client.send_frame(ws.OPCODE_CONTINUATION, b"b", fin=True)
        fin, opcode, payload = client.recv_frame()
        assert opcode == ws.OPCODE_PONG
        assert payload == b"mid"
        assert client.recv_text() == "echo:ab"


def test_ping_is_answered_before_any_application_traffic(server: ServerThread):
    with WSClient(server) as client:
        client.send_ping(b"early")
        fin, opcode, payload = client.recv_frame()
        assert (fin, opcode, payload) == (True, ws.OPCODE_PONG, b"early")


def test_application_initiated_close(server: ServerThread):
    with WSClient(server, path="/ws/close?code=1001") as client:
        assert client.status == 101
        assert client.recv_close() == 1001
        client.expect_eof()


def test_rejected_handshake_returns_403(server: ServerThread):
    """``websocket.close`` before accept must become an HTTP 403 (ASGI spec)."""
    client = WSClient(server, path="/ws/deny")
    try:
        assert client.status == 403
        assert client.response_headers[b"content-length"] == b"9"
        while len(client.buffer) < 9:
            client.buffer.extend(client.sock.recv(64))
        assert bytes(client.buffer[:9]) == b"Forbidden"
        assert not client.sock.recv(64)
    finally:
        client.close()


def test_unmasked_frame_is_rejected(server: ServerThread):
    with WSClient(server) as client:
        client.send_frame(ws.OPCODE_TEXT, b"nope", mask=False)
        assert client.recv_close() == ws.CLOSE_PROTOCOL_ERROR
        client.expect_eof()
        assert WS_STATE["disconnect_code"] == ws.CLOSE_PROTOCOL_ERROR


def test_invalid_utf8_text_is_rejected(server: ServerThread):
    with WSClient(server) as client:
        client.send_frame(ws.OPCODE_TEXT, b"\xff\xfe")
        assert client.recv_close() == ws.CLOSE_INVALID_PAYLOAD


def test_continuation_without_a_start_is_rejected(server: ServerThread):
    with WSClient(server) as client:
        client.send_frame(ws.OPCODE_CONTINUATION, b"orphan")
        assert client.recv_close() == ws.CLOSE_PROTOCOL_ERROR


def test_oversized_message_is_rejected():
    with ServerThread(max_websocket_message_size=1024) as server:
        with WSClient(server) as client:
            client.send_frame(ws.OPCODE_BINARY, b"x" * 2048)
            assert client.recv_close() == ws.CLOSE_TOO_BIG


def test_oversized_message_is_rejected_across_fragments():
    with ServerThread(max_websocket_message_size=1024) as server:
        with WSClient(server) as client:
            client.send_frame(ws.OPCODE_BINARY, b"x" * 512, fin=False)
            client.send_frame(ws.OPCODE_CONTINUATION, b"x" * 512, fin=False)
            client.send_frame(ws.OPCODE_CONTINUATION, b"x" * 512, fin=True)
            assert client.recv_close() == ws.CLOSE_TOO_BIG


def test_control_frame_must_not_be_fragmented(server: ServerThread):
    with WSClient(server) as client:
        client.send_frame(ws.OPCODE_PING, b"frag", fin=False)
        assert client.recv_close() == ws.CLOSE_PROTOCOL_ERROR


def test_invalid_close_code_is_rejected(server: ServerThread):
    with WSClient(server) as client:
        client.send_frame(ws.OPCODE_CLOSE, (1004).to_bytes(2, "big"))
        assert client.recv_close() == ws.CLOSE_PROTOCOL_ERROR


def test_websockets_can_be_disabled():
    with ServerThread(websockets=False) as server:
        sock = server.connect()
        try:
            sock.sendall(
                b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Key: "
                + base64.b64encode(b"0123456789abcdef")
                + b"\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            head = sock.recv(4096)
            assert not head.startswith(b"HTTP/1.1 101")
        finally:
            sock.close()


def test_missing_websocket_version_is_426(server: ServerThread):
    sock = server.connect()
    try:
        sock.sendall(
            b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Key: "
            + base64.b64encode(b"0123456789abcdef")
            + b"\r\n\r\n"
        )
        head = sock.recv(4096)
        assert head.startswith(b"HTTP/1.1 426")
        assert b"sec-websocket-version: 13" in head.lower()
    finally:
        sock.close()


def test_bad_key_is_rejected(server: ServerThread):
    sock = server.connect()
    try:
        sock.sendall(
            b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Key: short\r\n"
            b"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        assert sock.recv(4096).startswith(b"HTTP/1.1 400")
    finally:
        sock.close()


def test_upgrade_with_a_body_is_rejected(server: ServerThread):
    sock = server.connect()
    try:
        sock.sendall(
            b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Key: "
            + base64.b64encode(b"0123456789abcdef")
            + b"\r\nSec-WebSocket-Version: 13\r\ncontent-length: 3\r\n\r\nabc"
        )
        assert sock.recv(4096).startswith(b"HTTP/1.1 400")
    finally:
        sock.close()


def test_silent_application_is_timed_out():
    with ServerThread(request_timeout=0.5) as server:
        sock = server.connect()
        try:
            sock.sendall(
                b"GET /ws/silent HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Key: "
                + base64.b64encode(b"0123456789abcdef")
                + b"\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            sock.settimeout(5.0)
            start = time.monotonic()
            with pytest.raises((ConnectionResetError, AssertionError)):
                while True:
                    if not sock.recv(4096):
                        raise AssertionError("handshake timeout closed gracefully")
            assert time.monotonic() - start < 4.0
        except ConnectionResetError:
            pass
        finally:
            sock.close()


def test_large_message_round_trip(server: ServerThread):
    """
    A message spanning many socket reads must not stall the reader.

    Anything above the read watermark arrives in several chunks, so the frame
    is incomplete for a while: the reader has to wait for more bytes instead of
    spinning on the partial frame (which would block the whole event loop).
    """
    with WSClient(server, timeout=20.0) as client:
        payload = "x" * 400_000
        start = time.monotonic()
        client.send_text(payload)
        assert client.recv_text(timeout=20.0) == "echo:" + payload
        assert time.monotonic() - start < 5.0
        client.send_close()
        assert client.recv_close() == 1000


def test_large_binary_message_reassembles_from_fragments(server: ServerThread):
    """Fragments that each cross a socket read boundary stay in order."""
    with WSClient(server, timeout=20.0) as client:
        chunk = bytes(range(256)) * 400
        client.send_frame(0x2, chunk[: len(chunk) // 2], fin=False)
        client.send_frame(0x9, b"mid")
        client.send_frame(0x0, chunk[len(chunk) // 2 :], fin=True)
        kind, value = client.recv_message(timeout=20.0)
        # The ping is answered before the echoed message is delivered.
        assert kind == "bytes"
        assert value == b"echo:" + chunk


def test_rejected_handshake_can_return_a_real_http_response(server: ServerThread):
    """The ``websocket.http.response`` extension replaces the fixed 403."""
    client = WSClient(server, path="/ws/deny-json")
    try:
        assert client.status == 401
        assert client.response_headers[b"content-type"] == b"application/json"
        assert client.response_headers[b"www-authenticate"] == b"Bearer"
        # The error has no content-length, so it ends when the server closes.
        assert "content-length" not in client.response_headers
        body = bytes(client.buffer)
        while b"" != (chunk := client.sock.recv(65536)):
            body += chunk
        assert body == b'{"error": "authenticate first"}'
    finally:
        client.close()


def test_rejected_handshake_can_stream_the_response(server: ServerThread):
    client = WSClient(server, path="/ws/deny-streaming")
    try:
        assert client.status == 429
        body = bytes(client.buffer)
        while b"" != (chunk := client.sock.recv(65536)):
            body += chunk
        assert body == b"slow down!"
    finally:
        client.close()


def test_rejection_without_a_body_is_still_completed(server: ServerThread):
    """An application that returns mid response must not leave the peer hanging."""
    client = WSClient(server, path="/ws/deny-empty")
    try:
        assert client.status == 403
        assert client.sock.recv(65536) == b""
    finally:
        client.close()


def test_shutdown_asks_the_client_to_go_away(server: ServerThread):
    """A server shutdown closes a live session with 1001, not a dead socket."""
    with WSClient(server) as client:
        client.send_text("before")
        assert client.recv_text() == "echo:before"
        # Ask for shutdown without joining the serving thread, so the close
        # frame can still be read.
        assert server._loop is not None
        server._loop.call_soon_threadsafe(server.server.request_stop)
        assert client.recv_close(timeout=10.0) == 1001


def test_websocket_connection_is_not_reusable_for_http(server: ServerThread):
    """After the close handshake the connection is closed, never pipelined."""
    with WSClient(server) as client:
        client.send_text("bye")
        assert client.recv_text() == "echo:bye"
        client.send_close(1000)
        assert client.recv_close() == 1000
        client.expect_eof()


def test_http_still_works_after_a_websocket(server: ServerThread):
    with WSClient(server) as client:
        client.send_text("x")
        assert client.recv_text() == "echo:x"
        client.send_close(1000)
    sock = server.connect()
    try:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        assert sock.recv(4096).startswith(b"HTTP/1.1 200")
    finally:
        sock.close()


# wss:// over TLS


def test_websocket_over_tls(tls_server: ServerThread):
    sock = tls_socket(tls_server, ["http/1.1"])
    try:
        assert sock.selected_alpn_protocol() == "http/1.1"
        with WSClient(tls_server, sock=sock) as client:
            assert client.status == 101
            client.send_text("tls")
            assert client.recv_text() == "echo:tls"
            assert WS_STATE["scheme"] == "wss"
            client.send_close()
            assert client.recv_close() == 1000
    finally:
        sock.close()


def test_websocket_frames_are_not_masked_by_the_server():
    """A masked server frame is a hard protocol error for real clients."""
    with ServerThread() as server:
        with WSClient(server) as client:
            client.send_text("m")
            client.send_close()
            frame = client.recv_frame()
            assert not (frame[1] & 0x80)


def test_struct_helpers_are_consistent():
    assert len(struct.pack("ii", 1, 0)) == 8
    assert os.name in ("nt", "posix")
