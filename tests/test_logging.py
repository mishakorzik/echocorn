"""
Logging: one line shape, five level names, and the lifecycle banner.

The server prints every line as::

    2026-09-22 19:44:24 +0300 [INFO ]  381063: h11, ip=127.0.0.1, ...

and the startup lines are shown whatever the configured level is.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import socket
import time

import pytest

from conftest import (
    ServerThread,
    WSClient,
    build_request,
    read_response,
    tls_socket,
    write_self_signed_cert,
)
from echocorn import utils
from echocorn.server import _configure_logging, banner, format_address, logger, run_lifespan
from echocorn.websocket import OPCODE_TEXT

ACCESS = logging.getLogger("echocorn.access")

LINE_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4} \[(\w+)\s*\]\s+(\d+): (.*)$")


def _configure_for_test(level, color=False):
    """
    Configure the server logging, returning a function that undoes it.

    ``capsys`` is a dependency of the fixtures below on purpose: the handler
    binds ``sys.stderr`` when it is created, so it must be created after
    pytest has replaced that stream.
    """
    root = logging.getLogger()
    saved = (list(root.handlers), root.level, logger.level, banner.level)
    _configure_logging(level, color)

    def restore():
        root.handlers = saved[0]
        root.setLevel(saved[1])
        logger.setLevel(saved[2])
        banner.setLevel(saved[3])

    return restore


@pytest.fixture
def logs(capsys):
    """Configure the server logging for one test, then restore it."""
    restore = _configure_for_test("INFO")
    try:
        yield
    finally:
        restore()


@pytest.fixture
def debug_logs(capsys):
    """The same, with DEBUG switched on too."""
    restore = _configure_for_test("DEBUG")
    try:
        yield
    finally:
        restore()


@pytest.fixture
def muted_logs(capsys):
    """The same, with everything below CRIT muted."""
    restore = _configure_for_test("CRIT")
    try:
        yield
    finally:
        restore()


def printed(capsys):
    """The log lines written since the last read."""
    return [line for line in capsys.readouterr().err.splitlines() if line.strip()]


def messages(capsys):
    """The message part of every log line written since the last read."""
    result = []
    for line in printed(capsys):
        match = LINE_RE.match(line)
        assert match, line
        result.append(match.group(3))
    return result


def wait_for(capsys, text, timeout=5.0):
    """Read stderr until ``text`` appears (a session ends asynchronously)."""
    deadline = time.monotonic() + timeout
    collected = ""
    while time.monotonic() < deadline:
        collected += capsys.readouterr().err
        if text in collected:
            return collected
        time.sleep(0.05)
    return collected


def test_every_line_carries_time_offset_level_pid_and_message(logs, capsys):
    logger.info("hello")
    (line,) = printed(capsys)
    match = LINE_RE.match(line)
    assert match, line
    assert match.group(1) == "INFO"
    assert int(match.group(2)) == os.getpid()
    assert match.group(3) == "hello"
    assert " +" in line or " -" in line  # the UTC offset is there


def test_only_five_level_names_are_printed(debug_logs, capsys):
    for level, name in (
        (logging.DEBUG, "DEBUG"),
        (logging.INFO, "INFO"),
        (logging.WARNING, "WARN"),
        (logging.ERROR, "ERROR"),
        (logging.CRITICAL, "CRIT"),
    ):
        logger.log(level, name)
    output = capsys.readouterr().err
    assert "[DEBUG]" in output
    assert "[INFO ]" in output
    assert "[WARN ]" in output
    assert "[ERROR]" in output
    assert "[CRIT ]" in output
    assert "WARNING" not in output
    assert "CRITICAL" not in output


def test_lifecycle_lines_survive_a_muted_level(muted_logs, capsys):
    """Even at the quietest level, "the server is up" is still printed."""
    logger.info("hidden")
    banner.info("Serving HTTP on :8000")
    output = capsys.readouterr().err
    assert "Serving HTTP on :8000" in output
    assert "hidden" not in output


def test_coloured_logging_paints_every_level(logs, capsys):
    """With colour on, each level gets its ANSI colour and a reset."""
    restore = _configure_for_test("DEBUG", color=True)
    try:
        for level, name in (
            (logging.DEBUG, "DEBUG"),
            (logging.INFO, "INFO"),
            (logging.WARNING, "WARN"),
            (logging.ERROR, "ERROR"),
            (logging.CRITICAL, "CRIT"),
        ):
            logger.log(level, name)
        output = capsys.readouterr().err
    finally:
        restore()
    for color in ("\033[94m", "\033[34m", "\033[93m", "\033[91m", "\033[95m"):
        assert color in output
    assert "\033[90m" in output  # the timestamp is dimmed
    assert "\033[0m" in output  # and every span is reset
    # The readable layout is unchanged by the colour.
    assert "[INFO ]" in output and "[CRIT ]" in output


def test_plain_logging_has_no_ansi_escapes(logs, capsys):
    logger.info("plain")
    assert "\033[" not in capsys.readouterr().err


async def _start_and_stop_lifespan(application):
    """Drive one lifespan handshake and shut the context down again."""
    context = await run_lifespan(application, timeout=0.5)
    await context.shutdown(0.5)


def test_a_lifespan_less_application_is_reported_without_a_stray_format(logs, capsys):
    """An application that ignores the lifespan scope is reported cleanly."""

    async def bare_app(scope, receive, send):
        return

    asyncio.run(_start_and_stop_lifespan(bare_app))
    output = capsys.readouterr().err
    assert "does not support the lifespan protocol" in output
    # The message used to carry a literal '%s' because of a misplaced condition.
    assert "%s" not in output


def test_a_lifespan_scope_that_raises_is_reported_with_the_error(logs, capsys):
    """A WSGI bridge rejecting the scope names the error it raised."""

    async def refusing_app(scope, receive, send):
        raise RuntimeError("HTTP only")

    asyncio.run(_start_and_stop_lifespan(refusing_app))
    output = capsys.readouterr().err
    assert "does not support the lifespan protocol" in output
    assert "RuntimeError" in output


def test_the_access_line_has_the_documented_shape(logs, capsys):
    utils.access_log(ACCESS, "h11", ("127.0.0.1", 51000), "GET", "/", 200, 1.7324)
    assert messages(capsys) == [
        "h11, ip=127.0.0.1, method=GET, path=/, code=200, time=1.732s"
    ]


def test_http2_and_websocket_access_lines(logs, capsys):
    utils.access_log(
        ACCESS, "h20", ("127.0.0.1", 51000), "GET", "/test.html", 404, 0.9712
    )
    utils.access_log(
        ACCESS, "wss", ("127.0.0.1", 51000), None, "/ws", 1000, 12.48, messages=4
    )
    assert messages(capsys) == [
        "h20, ip=127.0.0.1, method=GET, path=/test.html, code=404, time=0.971s",
        "wss, ip=127.0.0.1, path=/ws, code=1000, time=12.480s, msgs=4",
    ]


def test_a_hostile_path_cannot_forge_log_entries(logs, capsys):
    utils.access_log(ACCESS, "h11", ("127.0.0.1", 1), "GET", "/a\r\nb\x00c", 400, 0.001)
    (line,) = messages(capsys)
    assert "\\x0d\\x0a" in line
    assert "\r" not in line and "\n" not in line and "\x00" not in line


def test_access_lines_are_not_built_when_the_level_filters_them_out(
    muted_logs, capsys
):
    utils.access_log(ACCESS, "h11", ("127.0.0.1", 1), "GET", "/", 200, 1.0)
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize(
    "address, expected",
    [
        (("0.0.0.0", 8000), ":8000"),
        (("127.0.0.1", 8000), "127.0.0.1:8000"),
        (("::1", 8000), "[::1]:8000"),
    ],
)
def test_serving_address_formatting(address, expected):
    family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.bind(address)
        assert format_address(sock) == expected
    finally:
        sock.close()


def test_http_requests_are_logged_by_the_server(logs, capsys):
    with ServerThread(access_log=True) as server:
        sock = server.connect()
        try:
            sock.sendall(build_request(host="localhost"))
            assert read_response(sock).status == 200
        finally:
            sock.close()
    assert "h11, ip=127.0.0.1, method=GET, path=/, code=200, time=" in (
        wait_for(capsys, "h11, ip=")
    )


def test_a_websocket_session_is_logged_as_one_line(logs, capsys):
    with ServerThread(access_log=True) as server:
        with WSClient(server) as client:
            client.send_text("ping")
            fin, opcode, payload = client.recv_frame()
            assert opcode == OPCODE_TEXT and payload == b"echo:ping"
            client.send_close(1000)
        output = wait_for(capsys, "ws, ip=")
    match = re.search(
        r"ws, ip=127\.0\.0\.1, path=/ws, code=(\d+), time=\d+\.\d{3}s, msgs=(\d+)",
        output,
    )
    assert match, output
    assert match.group(1) == "1000"
    assert match.group(2) == "1"


def test_a_refused_websocket_handshake_is_logged_with_its_status(logs, capsys):
    with ServerThread(access_log=True) as server:
        with WSClient(server, path="/ws/deny-json") as client:
            assert client.status == 401
        output = wait_for(capsys, "ws, ip=")
    assert "ws, ip=127.0.0.1, path=/ws/deny-json, code=401, time=" in output
    assert "msgs=" not in output


def test_a_websocket_over_tls_is_logged_as_wss(logs, tmp_path, capsys):
    certfile, keyfile = write_self_signed_cert(tmp_path)
    with ServerThread(certfile=certfile, keyfile=keyfile, access_log=True) as server:
        sock = tls_socket(server, ["http/1.1"])
        try:
            with WSClient(server, sock=sock) as client:
                assert client.status == 101
                client.send_text("hi")
                assert client.recv_frame()[2] == b"echo:hi"
                client.send_close(1000)
            output = wait_for(capsys, "wss, ip=")
        finally:
            sock.close()
    assert "wss, ip=127.0.0.1, path=/ws, code=1000, time=" in output
