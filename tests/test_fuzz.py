"""
Property tests: whatever bytes arrive, the answer is an answer or a close.

The parsers are the only code in the server that reads attacker-controlled
bytes, so they are fuzzed here with a fixed seed: random garbage, mutations of a
valid request, and random bytes sent to a live server.  The property is always
the same - a documented refusal, never an unexpected exception, a hang or a
crash - and the server must still serve a normal request afterwards.
"""

from __future__ import annotations

import random
import socket

import pytest

from conftest import (
    ServerThread,
    build_request,
    read_response,
    write_self_signed_cert,
)
from echocorn import ServerConfig, websocket
from echocorn import utils
from echocorn.http1 import ChunkedDecoder, _ProtocolError, parse_request_head


def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _wait_until_listening(port, timeout=5.0):
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            probe = socket.create_connection(("127.0.0.1", port), timeout=0.5)
        except OSError:
            time.sleep(0.02)
        else:
            probe.close()
            return
    raise AssertionError("the listener did not come up")

#: Fixed seed: a failure here is reproducible.
SEED = 20260923

VALID = (
    b"POST /echo?a=1&b=%20 HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"User-Agent: fuzz\r\n"
    b"Content-Length: 5\r\n"
    b"X-Custom: value\r\n"
    b"\r\n"
    b"hello"
)


def _fuzz_head(count: int, rng: random.Random) -> None:
    config = ServerConfig()
    for _ in range(count):
        size = rng.randrange(0, 240)
        data = bytes(rng.randrange(0, 256) for _ in range(size))
        buffer = bytearray(data)
        try:
            parse_request_head(buffer, config)
        except _ProtocolError:
            pass


def test_random_bytes_never_break_the_request_parser():
    """Only a refusal may come out of it - never another exception."""
    _fuzz_head(3000, random.Random(SEED))


def test_mutations_of_a_valid_request_never_break_the_parser():
    rng = random.Random(SEED + 1)
    for _ in range(3000):
        mutated = bytearray(VALID)
        for _ in range(rng.randrange(1, 6)):
            position = rng.randrange(len(mutated))
            mutated[position] = rng.randrange(0, 256)
        try:
            parse_request_head(mutated, ServerConfig())
        except _ProtocolError:
            pass


@pytest.mark.parametrize("seed", [SEED + 2, SEED + 3])
def test_random_bytes_never_break_the_chunked_decoder(seed):
    rng = random.Random(seed)
    for _ in range(3000):
        decoder = ChunkedDecoder()
        parts = bytes(rng.randrange(0, 256) for _ in range(rng.randrange(0, 200)))
        try:
            decoder.feed(bytearray(parts), 0)
        except _ProtocolError:
            pass


def test_random_chunked_streams_terminate_and_stay_bounded():
    """A decoded stream must always end, and never exceed what it was given."""
    rng = random.Random(SEED + 4)
    for _ in range(1500):
        body = bytes(rng.randrange(0, 256) for _ in range(rng.randrange(0, 300)))
        decoder = ChunkedDecoder()
        if body:
            encoded = b"%x\r\n" % len(body) + body + b"\r\n0\r\nx-t: 1\r\n\r\n"
        else:
            # No data chunk at all: the zero chunk IS the message.
            encoded = b"0\r\nx-t: 1\r\n\r\n"
        buffer = bytearray(encoded)
        given = len(buffer)
        chunks = decoder.feed(buffer, 0)
        decoded = b"".join(chunks)
        assert decoded == body
        # It never invents data, and it consumes the whole stream exactly.
        assert len(decoded) <= given
        assert decoder.done
        assert decoder.trailers == [(b"x-t", b"1")]
        assert buffer == b""


def test_random_bytes_never_break_the_websocket_frame_parser():
    rng = random.Random(SEED + 5)
    for _ in range(3000):
        parser = websocket.FrameParser(1024, require_mask=False)
        data = bytes(rng.randrange(0, 256) for _ in range(rng.randrange(0, 200)))
        try:
            parser.feed(bytearray(data))
        except websocket.WebSocketError:
            pass


def test_random_targets_always_decode():
    """``decode_path`` runs on every request target: it may not raise."""
    rng = random.Random(SEED + 6)
    for _ in range(3000):
        raw = bytes(rng.randrange(0, 256) for _ in range(rng.randrange(0, 60)))
        path = utils.decode_path(raw)
        assert isinstance(path, str)


def _hammer(server: ServerThread, payload: bytes, *, reads: int = 1) -> bytes:
    """Send ``payload`` and then half-close, so the server cannot wait forever.

    The half-close is what keeps this fast: the reader sees EOF immediately
    instead of sitting out the request deadline of every malformed request.
    """
    connection = server.connect(timeout=10.0)
    try:
        if payload:
            connection.sendall(payload)
        try:
            connection.shutdown(socket.SHUT_WR)
        except OSError:
            return b""
        received = bytearray()
        for _ in range(reads):
            try:
                chunk = connection.recv(65536)
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            received.extend(chunk)
        return bytes(received)
    finally:
        connection.close()


def _still_alive(server: ServerThread) -> None:
    """A plain request on a fresh connection must still be answered."""
    connection = server.connect(timeout=10.0)
    try:
        connection.sendall(build_request(target="/", host="localhost"))
        assert read_response(connection).status == 200
    finally:
        connection.close()


def test_a_live_server_survives_random_requests():
    """Garbage on a real socket, then a normal request that must be served."""
    rng = random.Random(SEED + 7)
    with ServerThread(request_timeout=5.0) as server:
        for _ in range(150):
            size = rng.randrange(0, 400)
            payload = bytes(rng.randrange(0, 256) for _ in range(size))
            answer = _hammer(server, payload, reads=4)
            # Whatever came back is either nothing or a complete status line.
            assert answer == b"" or answer[:8] == b"HTTP/1.1" or answer[:7] == b"HTTP/1.0", answer[:64]
        _still_alive(server)


def test_a_live_server_survives_random_chunked_bodies():
    """A chunked body with hostile framing, over and over."""
    rng = random.Random(SEED + 8)
    with ServerThread(request_timeout=5.0) as server:
        for _ in range(120):
            payload = bytearray(
                b"POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            for _ in range(rng.randrange(1, 6)):
                payload.extend(
                    bytes(rng.randrange(0, 256) for _ in range(rng.randrange(0, 40)))
                )
            answer = _hammer(server, bytes(payload), reads=4)
            assert answer == b"" or answer[:8] == b"HTTP/1.1", answer[:64]
        _still_alive(server)


def test_a_live_redirect_listener_survives_random_requests(tmp_path):
    """The plaintext listener parses bytes of its own: it must not crash."""
    rng = random.Random(SEED + 9)
    certfile, keyfile = write_self_signed_cert(tmp_path)
    port = _free_port()
    with ServerThread(
        certfile=certfile,
        keyfile=keyfile,
        redirect_enabled=True,
        redirect_host="127.0.0.1",
        redirect_port=port,
    ):
        _wait_until_listening(port)
        for _ in range(150):
            connection = socket.create_connection(("127.0.0.1", port), timeout=5.0)
            try:
                connection.sendall(
                    bytes(rng.randrange(0, 256) for _ in range(rng.randrange(0, 300)))
                )
                connection.shutdown(socket.SHUT_WR)
                connection.settimeout(5.0)
                try:
                    connection.recv(65536)
                except (socket.timeout, OSError):
                    pass
            finally:
                connection.close()
        # Still answering a well formed request.
        connection = socket.create_connection(("127.0.0.1", port), timeout=5.0)
        try:
            connection.sendall(build_request(target="/x", host="localhost"))
            response = read_response(connection)
        finally:
            connection.close()
    assert response.status == 308
