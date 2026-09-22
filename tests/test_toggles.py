"""
Protocol switches: HTTP/1.1, HTTP/2 and WebSockets can each be turned off.

Each section of the configuration file owns one protocol, and switching one off
must be visible in the protocol negotiation, not just ignored: ALPN stops
offering it and a client that speaks it anyway is answered with a 505.
"""

from __future__ import annotations

from conftest import (
    H2Client,
    ServerThread,
    build_request,
    read_response,
    tls_socket,
    write_self_signed_cert,
)
from echocorn.http1 import CONNECTION_PREFACE


def test_http11_requests_are_refused_when_http1_is_disabled():
    with ServerThread(http1_enabled=False, websockets=False) as server:
        sock = server.connect()
        try:
            sock.sendall(build_request(host="localhost"))
            response = read_response(sock)
            assert response.status == 505
            assert b"HTTP/1.1 is disabled" in response.body
        finally:
            sock.close()


def test_http2_keeps_working_while_http1_is_disabled():
    """The h2c preface is still served; only HTTP/1.1 text is refused."""
    with ServerThread(http1_enabled=False, websockets=False) as server:
        with H2Client(server) as client:
            response = client.wait(client.request("/status/201"))
            assert response.status == 201


def test_http2_preface_is_refused_when_http2_is_disabled():
    with ServerThread(http2_enabled=False) as server:
        sock = server.connect()
        try:
            sock.sendall(CONNECTION_PREFACE)
            response = read_response(sock)
            assert response.status == 505
            assert b"HTTP/2 is disabled" in response.body
        finally:
            sock.close()


def test_http11_keeps_working_while_http2_is_disabled():
    with ServerThread(http2_enabled=False) as server:
        sock = server.connect()
        try:
            sock.sendall(build_request(host="localhost"))
            assert read_response(sock).status == 200
        finally:
            sock.close()


def test_alpn_stops_offering_http2_when_it_is_disabled(tmp_path):
    certfile, keyfile = write_self_signed_cert(tmp_path)
    with ServerThread(
        certfile=certfile, keyfile=keyfile, http2_enabled=False
    ) as server:
        sock = tls_socket(server, ["h2", "http/1.1"])
        try:
            assert sock.selected_alpn_protocol() == "http/1.1"
            sock.sendall(build_request(host="localhost"))
            assert read_response(sock).status == 200
        finally:
            sock.close()


def test_alpn_offers_only_http2_when_http1_is_disabled(tmp_path):
    certfile, keyfile = write_self_signed_cert(tmp_path)
    with ServerThread(
        certfile=certfile,
        keyfile=keyfile,
        http1_enabled=False,
        websockets=False,
    ) as server:
        sock = tls_socket(server, ["h2", "http/1.1"])
        try:
            assert sock.selected_alpn_protocol() == "h2"
        finally:
            sock.close()


def test_a_websocket_upgrade_is_a_plain_request_when_websockets_are_off():
    """With the switch off the upgrade is not intercepted, the app decides."""
    with ServerThread(websockets=False) as server:
        sock = server.connect()
        try:
            sock.sendall(
                build_request(
                    target="/ws",
                    host="localhost",
                    headers=[
                        ("Upgrade", "websocket"),
                        ("Connection", "Upgrade"),
                        ("Sec-WebSocket-Key", "MDEyMzQ1Njc4OWFiY2RlZg=="),
                        ("Sec-WebSocket-Version", "13"),
                    ],
                )
            )
            response = read_response(sock)
            assert response.status == 404
            assert b"upgrade" not in response.headers
        finally:
            sock.close()
