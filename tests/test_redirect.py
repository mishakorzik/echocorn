"""
The HTTP to HTTPS redirect listener.

The redirect is configured through ``[redirect]`` and served by a single
listener next to the TLS one: every plaintext request is answered with a
redirect that keeps the path and query string, and nothing is handed to the
application.
"""

from __future__ import annotations

import os
import socket
import ssl
import subprocess
import sys
import time

import pytest

from conftest import (
    ServerThread,
    build_request,
    read_response,
    tls_socket,
    write_self_signed_cert,
)
from echocorn.config import ServerConfig
from echocorn.redirect import build_location

CONFIG = ServerConfig(port=8443)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Location building
def test_location_keeps_path_and_query():
    assert (
        build_location(CONFIG, b"/a/b?x=1&y=2", b"example.com")
        == b"https://example.com:8443/a/b?x=1&y=2"
    )


def test_location_replaces_the_request_port():
    assert build_location(CONFIG, b"/", b"example.com:8000") == b"https://example.com:8443/"


def test_location_omits_the_default_https_port():
    assert build_location(ServerConfig(port=443), b"/x", b"example.com") == b"https://example.com/x"


def test_location_keeps_ipv6_brackets():
    assert build_location(CONFIG, b"/", b"[::1]:8000") == b"https://[::1]:8443/"


def test_location_falls_back_to_bind_domain():
    config = ServerConfig(port=443, bind_domain="example.com")
    assert build_location(config, b"/x", b"") == b"https://example.com/x"


def test_location_keeps_an_absolute_target():
    assert build_location(CONFIG, b"http://example.com/x", b"") == b"https://example.com/x"


def test_location_refuses_a_request_without_authority():
    assert build_location(CONFIG, b"/x", b"") is None


def test_location_refuses_a_target_that_is_not_a_path():
    assert build_location(CONFIG, b"*", b"example.com") is None


@pytest.mark.parametrize(
    "host",
    [
        b"example.com\nX-Injected: yes",
        b"example.com\rX-Injected: yes",
        b"exa\x0bmple.com",
        b"example.com\x00",
        b"exa mple.com",
    ],
)
def test_location_refuses_a_host_that_cannot_go_in_a_header(host):
    """A control byte in Host would end the ``location`` field early.

    A bare LF is a line terminator to a good few parsers even though this
    server does not treat it as one, so the answer would carry a header the
    client never wrote - and the value is attacker controlled.
    """
    assert build_location(CONFIG, b"/x", host) is None


def test_location_refuses_an_absolute_target_with_a_control_byte():
    assert build_location(CONFIG, b"http://example.com\nX-Injected: 1/x", b"") is None


# A live redirect listener
def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _wait_until_listening(port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            probe = socket.create_connection(("127.0.0.1", port), timeout=0.5)
        except OSError:
            time.sleep(0.02)
        else:
            probe.close()
            return
    raise AssertionError("the redirect listener did not come up")


@pytest.fixture()
def redirecting(tmp_path):
    """A TLS server that also serves the plaintext redirect on a spare port."""
    certfile, keyfile = write_self_signed_cert(tmp_path)
    port = _free_port()
    with ServerThread(
        certfile=certfile,
        keyfile=keyfile,
        redirect_enabled=True,
        redirect_host="127.0.0.1",
        redirect_port=port,
    ) as server:
        _wait_until_listening(port)
        yield server, port


def _request(port: int, target: str = "/", host: str = "example.com", method: str = "GET", expect_body: bool = True):
    connection = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        connection.sendall(build_request(method=method, target=target, host=host))
        return read_response(connection, expect_body=expect_body)
    finally:
        connection.close()


def test_plain_request_is_redirected_with_its_path_and_query(redirecting):
    server, port = redirecting
    response = _request(port, "/docs/page?q=1")
    assert response.status == 308
    assert response.header(b"location") == b"https://example.com:%d/docs/page?q=1" % server.port
    assert response.header(b"connection") == b"close"


def test_redirect_status_is_configurable(tmp_path):
    certfile, keyfile = write_self_signed_cert(tmp_path)
    port = _free_port()
    with ServerThread(
        certfile=certfile,
        keyfile=keyfile,
        redirect_enabled=True,
        redirect_host="127.0.0.1",
        redirect_port=port,
        redirect_status=301,
    ):
        _wait_until_listening(port)
        assert _request(port, "/moved").status == 301


def test_a_head_request_is_redirected_without_a_body(redirecting):
    _, port = redirecting
    response = _request(port, "/x", method="HEAD", expect_body=False)
    assert response.status == 308
    assert response.body == b""
    assert response.header(b"location") is not None


def test_a_malformed_request_line_is_answered_with_400(redirecting):
    _, port = redirecting
    connection = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        connection.sendall(b"NOT A REQUEST\r\n\r\n")
        response = read_response(connection)
    finally:
        connection.close()
    assert response.status == 400
    assert response.header(b"location") is None


def test_a_host_with_a_bare_lf_is_refused_not_reflected(redirecting):
    """The listener parses its own headers, so it validates them itself."""
    _, port = redirecting
    connection = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        connection.sendall(b"GET /x HTTP/1.1\r\nHost: example.com\nX-Injected: yes\r\n\r\n")
        raw = b""
        while True:
            try:
                data = connection.recv(65536)
            except (socket.timeout, OSError):
                break
            if not data:
                break
            raw += data
    finally:
        connection.close()
    assert raw.startswith(b"HTTP/1.1 400"), raw[:40]
    assert b"X-Injected" not in raw
    assert b"location" not in raw.lower()


def test_the_redirect_never_reaches_the_application(redirecting):
    """The redirect listener is separate: the app still serves the TLS port."""
    server, port = redirecting
    assert _request(port, "/").status == 308
    sock = tls_socket(server, ["http/1.1"])
    try:
        sock.sendall(build_request(host="localhost"))
        response = read_response(sock)
    finally:
        sock.close()
    assert response.status == 200
    assert response.body == b"Hello, World!"


def test_the_redirect_listener_is_rate_limited(tmp_path):
    """The plaintext listener is the one an abusive client finds first."""
    certfile, keyfile = write_self_signed_cert(tmp_path)
    port = _free_port()
    with ServerThread(
        certfile=certfile,
        keyfile=keyfile,
        redirect_enabled=True,
        redirect_host="127.0.0.1",
        redirect_port=port,
        ratelimit_enabled=True,
        ratelimit_requests=1,
        ratelimit_peak=1,
        ratelimit_window=1.0,
        ratelimit_ban=1.0,
    ):
        _wait_until_listening(port)
        assert _request(port, "/").status == 308
        refused = _request(port, "/")
        assert refused.status == 429
        assert refused.header(b"retry-after") == b"1"
        assert refused.header(b"connection") == b"close"
        assert refused.header(b"location") is None


# The command line: many workers, one redirect listener
CLI_APP = (
    "async def app(scope, receive, send):\n"
    "    if scope['type'] != 'http':\n"
    "        return\n"
    "    body = b'cli-ok!'\n"
    "    await send({'type': 'http.response.start', 'status': 200,\n"
    "                'headers': [(b'content-type', b'text/plain'),\n"
    "                            (b'content-length', str(len(body)).encode())]})\n"
    "    await send({'type': 'http.response.body', 'body': body})\n"
)


def _write_cli_config(tmp_path, certfile, keyfile, https_port, redirect_port, workers):
    """Write the application module and a redirecting TLS configuration."""
    (tmp_path / "cli_app.py").write_text(CLI_APP, encoding="utf-8")
    (tmp_path / "echocorn.toml").write_text(
        'app = "cli_app:app"\n'
        "\n[server]\n"
        'host = "127.0.0.1"\n'
        "port = %d\n"
        "workers = %d\n"
        "\n[tls]\n"
        "certfile = '%s'\n"
        "keyfile = '%s'\n"
        "\n[redirect]\n"
        "enabled = true\n"
        'host = "127.0.0.1"\n'
        "port = %d\n" % (https_port, workers, certfile, keyfile, redirect_port),
        encoding="utf-8",
    )


def _start_cli(tmp_path):
    process = subprocess.Popen(
        [sys.executable, "-m", "echocorn", "--config", "echocorn.toml"],
        cwd=str(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONPATH": ROOT},
    )
    return process


def _stop_cli(process) -> str:
    process.terminate()
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        process.kill()
    return process.stderr.read()


def _listening(port: int) -> bool:
    try:
        probe = socket.create_connection(("127.0.0.1", port), timeout=0.5)
    except OSError:
        return False
    probe.close()
    return True


def _wait_until_released(port: int, timeout: float = 10.0) -> bool:
    """True once nothing accepts on ``port`` any more."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _listening(port):
            return True
        time.sleep(0.05)
    return False


def _wait_until_the_application_answers(port: int, timeout: float = 20.0) -> bytes:
    """Poll the TLS listener until a worker serves the application."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    deadline = time.time() + timeout
    last: object = None
    while time.time() < deadline:
        try:
            raw = socket.create_connection(("127.0.0.1", port), timeout=2)
            sock = context.wrap_socket(raw, server_hostname="localhost")
            try:
                sock.sendall(build_request(host="127.0.0.1"))
                response = read_response(sock)
            finally:
                sock.close()
        except (OSError, AssertionError) as exc:
            last = exc
            time.sleep(0.05)
            continue
        if response.status == 200:
            return response.body
        last = response.status
        time.sleep(0.05)
    raise AssertionError("the application did not answer on %d: %r" % (port, last))


@pytest.mark.skipif(sys.platform == "win32", reason="the CLI test uses POSIX paths")
def test_cli_gives_the_redirect_a_worker_of_its_own(tmp_path):
    """With several workers, one of them does nothing but the redirect."""
    certfile, keyfile = write_self_signed_cert(tmp_path)
    https_port = _free_port()
    redirect_port = _free_port()
    _write_cli_config(tmp_path, certfile, keyfile, https_port, redirect_port, workers=2)
    process = _start_cli(tmp_path)
    try:
        _wait_until_listening(redirect_port, timeout=20.0)
        response = _request(redirect_port, "/page?x=1", host="127.0.0.1")
        assert response.status == 308
        assert response.header(b"location") == b"https://127.0.0.1:%d/page?x=1" % https_port
        # The other worker - the only one left - serves the application.
        assert _wait_until_the_application_answers(https_port) == b"cli-ok!"
    finally:
        output = _stop_cli(process)
    # The redirect worker bound the application socket for the others, so the
    # shutdown has to release both ports.
    assert _wait_until_released(https_port), "the application port is still held"
    assert _wait_until_released(redirect_port), "the redirect port is still held"
    assert "Waiting for all workers (2)" in output, output
    assert "Worker #2 ready" in output, output
    assert "Serving HTTP on 127.0.0.1:%d" % redirect_port in output, output
    assert "Serving HTTPS on 127.0.0.1:%d" % https_port in output, output
    # The plaintext listener is announced before the TLS one.
    assert output.index("Serving HTTP on") < output.index("Serving HTTPS on")


@pytest.mark.skipif(sys.platform == "win32", reason="the CLI test uses POSIX paths")
def test_cli_skips_the_redirect_with_a_single_worker(tmp_path):
    """A single worker serves the application; the redirect is not started."""
    certfile, keyfile = write_self_signed_cert(tmp_path)
    https_port = _free_port()
    redirect_port = _free_port()
    _write_cli_config(tmp_path, certfile, keyfile, https_port, redirect_port, workers=1)
    process = _start_cli(tmp_path)
    try:
        assert _wait_until_the_application_answers(https_port) == b"cli-ok!"
        assert not _listening(redirect_port)
    finally:
        output = _stop_cli(process)
    assert "redirect.enabled is skipped" in output, output
    assert "Serving HTTP on" not in output, output
    assert _wait_until_released(https_port), "the application port is still held"
