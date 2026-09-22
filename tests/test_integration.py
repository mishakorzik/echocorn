"""Integration tests with a real framework (Starlette/FastAPI) and the CLI."""

from __future__ import annotations

import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from conftest import H2Client, ServerThread

starlette = pytest.importorskip("starlette", reason="starlette is not installed")

from starlette.applications import Starlette  # noqa: E402
from starlette.responses import JSONResponse, PlainTextResponse, StreamingResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


async def homepage(request):
    return JSONResponse({"hello": "world", "path": request.url.path})


async def echo(request):
    body = await request.body()
    return JSONResponse({"length": len(body), "query": request.query_params.get("x")})


async def item(request):
    return PlainTextResponse("item %s" % request.path_params["item_id"])


async def boom(request):
    raise RuntimeError("kaboom")


async def stream(request):
    async def generate():
        for index in range(5):
            yield b"chunk-%d;" % index

    return StreamingResponse(generate(), media_type="text/plain")


async def headers(request):
    return JSONResponse(
        {
            "host": request.headers.get("host"),
            "user_agent": request.headers.get("user-agent"),
            "custom": request.headers.get("x-custom"),
        }
    )


def build_app() -> "Starlette":
    return Starlette(
        routes=[
            Route("/", homepage),
            Route("/echo", echo, methods=["POST"]),
            Route("/items/{item_id}", item),
            Route("/boom", boom),
            Route("/stream", stream),
            Route("/headers", headers),
        ]
    )


@pytest.fixture()
def starlette_server():
    with ServerThread(build_app(), compression=True) as instance:
        yield instance


# HTTP/1.1 through httpx
def test_starlette_over_http11(starlette_server: ServerThread):
    httpx = pytest.importorskip("httpx")
    base = "http://%s:%d" % (starlette_server.host, starlette_server.port)
    with httpx.Client(base_url=base, timeout=10.0) as client:
        assert client.get("/").json()["hello"] == "world"
        assert client.get("/items/42").text == "item 42"
        assert client.post("/echo?x=1", content=b"abc").json() == {
            "length": 3,
            "query": "1",
        }
        assert client.get("/headers", headers={"x-custom": "yes"}).json()["custom"] == "yes"
        streamed = client.get("/stream")
        assert streamed.text == "".join("chunk-%d;" % i for i in range(5))
        with pytest.raises(httpx.HTTPStatusError):
            client.get("/boom").raise_for_status()
        assert client.get("/boom").status_code == 500


def test_starlette_keep_alive_reuses_connection(starlette_server: ServerThread):
    httpx = pytest.importorskip("httpx")
    base = "http://%s:%d" % (starlette_server.host, starlette_server.port)
    with httpx.Client(base_url=base, timeout=10.0) as client:
        for _ in range(5):
            assert client.get("/").status_code == 200


def test_compression_applied_to_starlette_json(starlette_server: ServerThread):
    httpx = pytest.importorskip("httpx")
    base = "http://%s:%d" % (starlette_server.host, starlette_server.port)
    with httpx.Client(base_url=base, timeout=10.0) as client:
        response = client.get("/", headers={"accept-encoding": "gzip"})
        # httpx transparently decompresses, but the header proves the coding.
        assert response.headers.get("content-encoding") in (None, "gzip")
        assert response.json()["hello"] == "world"


# HTTP/2 through the h2 client
def test_starlette_over_http2(starlette_server: ServerThread):
    with H2Client(starlette_server) as client:
        stream_id = client.request("/")
        response = client.wait(stream_id)
        assert response.status == 200
        payload = json.loads(bytes(response.body))
        assert payload["hello"] == "world"

        stream_id = client.request("/items/7")
        response = client.wait(stream_id)
        assert bytes(response.body) == b"item 7"

        stream_id = client.request(
            "/echo", method="POST", body=b"12345",
            headers=[(b"content-type", b"application/octet-stream")],
        )
        response = client.wait(stream_id)
        assert json.loads(bytes(response.body))["length"] == 5


def test_starlette_streaming_over_http2(starlette_server: ServerThread):
    with H2Client(starlette_server) as client:
        stream_id = client.request("/stream")
        response = client.wait(stream_id, timeout=20)
        assert response.status == 200
        assert bytes(response.body) == "".join("chunk-%d;" % i for i in range(5)).encode()


def test_starlette_error_over_http2(starlette_server: ServerThread):
    with H2Client(starlette_server) as client:
        stream_id = client.request("/boom")
        response = client.wait(stream_id)
        assert response.status == 500


# CLI: every setting comes from the configuration file
def _run_cli(args, timeout=30, cwd=ROOT):
    return subprocess.run(
        [sys.executable, "-m", "echocorn", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "PYTHONPATH": ROOT},
    )


def test_cli_version():
    result = _run_cli(["--version"])
    assert result.returncode == 0
    assert "echocorn" in result.stdout


def test_cli_about():
    result = _run_cli(["--about"])
    assert result.returncode == 0
    assert "echocorn" in result.stdout


def test_cli_help_explains_the_configuration_file():
    result = _run_cli(["--help"])
    assert result.returncode == 0
    assert "--config PATH" in result.stdout


def test_cli_rejects_server_flags(tmp_path):
    """The command line no longer configures the server."""
    _write_config(tmp_path, port=8000)
    result = _run_cli(["--config", "echocorn.toml", "--port", "9000"], cwd=tmp_path)
    assert result.returncode == 2
    assert "unexpected argument '--port'" in result.stderr


def test_cli_requires_a_configuration_file(tmp_path):
    result = _run_cli([], cwd=tmp_path)
    assert result.returncode == 2
    assert "no configuration file given" in result.stderr


def test_cli_takes_the_config_path_as_its_only_argument(tmp_path):
    result = _run_cli(["-c", "echocorn.toml"], cwd=tmp_path)
    assert result.returncode == 2
    assert "unexpected argument '-c'" in result.stderr


def test_cli_reports_a_missing_app_key(tmp_path):
    (tmp_path / "echocorn.toml").write_text('[server]\nport = 8001\n', encoding="utf-8")
    result = _run_cli(["--config", "echocorn.toml"], cwd=tmp_path)
    assert result.returncode == 2
    assert "'app' key is required" in result.stderr


def test_cli_reports_an_unknown_setting(tmp_path):
    (tmp_path / "echocorn.toml").write_text('app = "x:y"\n[server]\nprot = 8001\n', encoding="utf-8")
    result = _run_cli(["--config", "echocorn.toml"], cwd=tmp_path)
    assert result.returncode == 2
    assert "unknown setting 'server.prot'" in result.stderr
    assert "port" in result.stderr


def test_cli_reports_a_wrong_type(tmp_path):
    (tmp_path / "echocorn.toml").write_text('app = "x:y"\n[server]\nport = "8000"\n', encoding="utf-8")
    result = _run_cli(["--config", "echocorn.toml"], cwd=tmp_path)
    assert result.returncode == 2
    assert "server.port must be an integer" in result.stderr


def test_cli_reports_broken_toml(tmp_path):
    (tmp_path / "echocorn.toml").write_text('app = "x:y\n', encoding="utf-8")
    result = _run_cli(["--config", "echocorn.toml"], cwd=tmp_path)
    assert result.returncode == 2
    assert "not valid TOML" in result.stderr


def test_cli_rejects_mismatched_tls_files(tmp_path):
    (tmp_path / "echocorn.toml").write_text('app = "x:y"\n\n[tls]\ncertfile = "cert.pem"\n', encoding="utf-8")
    result = _run_cli(["--config", "echocorn.toml"], cwd=tmp_path)
    assert result.returncode == 2
    assert "tls.certfile and tls.keyfile" in result.stderr


def test_an_app_without_lifespan_neither_stalls_nor_breaks():
    """A WSGI bridge rejects the lifespan scope; that must not cost 10s twice."""

    async def bare_app(scope, receive, send):  # pragma: no cover - never called
        raise RuntimeError("this application only speaks HTTP")

    start = time.monotonic()
    with ServerThread(bare_app) as server:
        assert time.monotonic() - start < 3.0
        sock = server.connect()
        try:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            # The application crashes on every request, which is answered with a
            # 500: the point is that the server itself started and stayed up.
            assert sock.recv(4096).startswith(b"HTTP/1.1 500")
        finally:
            sock.close()
    assert time.monotonic() - start < 6.0


def test_a_failing_lifespan_startup_does_not_stop_serving():
    """A ``lifespan.startup.failed`` is reported, not fatal."""

    async def app(scope, receive, send):  # noqa: D401
        if scope["type"] == "lifespan":
            await receive()
            await send({"type": "lifespan.startup.failed", "message": "no database"})
            return
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-length", b"2")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    with ServerThread(app) as server:
        httpx = pytest.importorskip("httpx")
        base = "http://%s:%d" % (server.host, server.port)
        with httpx.Client(base_url=base, timeout=10.0) as client:
            assert client.get("/").text == "ok"


CLI_APP_SOURCE = (
    "async def app(scope, receive, send):\n"
    "    if scope['type'] == 'lifespan':\n"
    "        while True:\n"
    "            message = await receive()\n"
    "            if message['type'] == 'lifespan.shutdown':\n"
    "                await send({'type': 'lifespan.shutdown.complete'})\n"
    "                return\n"
    "            await send({'type': 'lifespan.startup.complete'})\n"
    "    status = 200 if scope['path'] == '/' else 404\n"
    "    body = b'cli-ok!' if status == 200 else b'missing'\n"
    "    await send({'type': 'http.response.start', 'status': status,\n"
    "                'headers': [(b'content-type', b'text/plain'),\n"
    "                            (b'content-length', str(len(body)).encode())]})\n"
    "    await send({'type': 'http.response.body', 'body': body})\n"
)


def _write_config(tmp_path, port=None, workers=None, level="WARN", access=False, sections=()):
    """Write the app module and an ``echocorn.toml`` that serves it."""
    (tmp_path / "cli_app.py").write_text(CLI_APP_SOURCE, encoding="utf-8")
    if port is None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
    lines = [
        'app = "cli_app:app"',
        "",
        "[server]",
        'host = "127.0.0.1"',
        "port = %d" % port,
    ]
    if workers is not None:
        lines.append("workers = %d" % workers)
    lines += [
        "",
        "[logging]",
        'level = "%s"' % level,
        "access = %s" % ("true" if access else "false"),
    ]
    for name, body in sections:
        lines += ["", "[%s]" % name, *body]
    (tmp_path / "echocorn.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return port


def _start_cli_server(
    tmp_path,
    workers=None,
    config_name=None,
    level="WARN",
    access=False,
    sections=(),
    new_process_group=False,
):
    port = _write_config(
        tmp_path, workers=workers, level=level, access=access, sections=sections
    )
    config_path = config_name or "echocorn.toml"
    if config_name is not None:
        (tmp_path / config_name).write_bytes((tmp_path / "echocorn.toml").read_bytes())
    arguments = [sys.executable, "-m", "echocorn", "--config", config_path]
    creationflags = 0
    if new_process_group and sys.platform == "win32":  # pragma: no cover - Windows
        # Ctrl+Break can only be raised for a process group of our own.
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
    process = subprocess.Popen(
        arguments,
        cwd=str(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONPATH": ROOT},
        creationflags=creationflags,
    )
    deadline = time.time() + 20
    last_error = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/" % port, timeout=2) as r:
                assert r.status == 200
                assert r.read() == b"cli-ok!"
                return process, port
        except Exception as exc:  # server not up yet
            last_error = exc
            if process.poll() is not None:
                raise AssertionError(
                    "server exited early: %s / %s"
                    % (process.stdout.read(), process.stderr.read())
                ) from None
            time.sleep(0.1)
    process.kill()
    raise AssertionError("server never became ready: %r" % (last_error,))


def _stop_cli_server(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:  # pragma: no cover
            process.kill()


def test_cli_serves_requests(tmp_path):
    process, _ = _start_cli_server(tmp_path)
    _stop_cli_server(process)


def test_cli_serves_with_multiple_workers(tmp_path):
    process, _ = _start_cli_server(tmp_path, workers=2)
    _stop_cli_server(process)


def test_cli_serves_from_an_explicit_config_path(tmp_path):
    process, _ = _start_cli_server(tmp_path, config_name="production.toml")
    _stop_cli_server(process)


def test_cli_finds_the_app_next_to_the_config_file(tmp_path):
    """``app = "cli_app:app"`` resolves from the configuration directory."""
    process, port = _start_cli_server(tmp_path)
    _stop_cli_server(process)
    assert port


def test_cli_exits_on_sigterm(tmp_path):
    process, _ = _start_cli_server(tmp_path)
    try:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:  # pragma: no cover
            raise AssertionError("server did not shut down on SIGTERM") from None
        assert process.poll() is not None
    finally:
        _stop_cli_server(process)


# Startup output and the access log format
EVENT_LOOP_RE = re.compile(r"Using '(uvloop|asyncio)' as event loop")
ACCESS_LINE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4} \[INFO \] +\d+: "
    r"h11, ip=127\.0\.0\.1, method=GET, path=/\S*, code=\d+, time=\d+\.\d{3}s$"
)


def _wait_port_released(port, timeout=15.0):
    """True once nothing is listening on ``port`` any more."""
    deadline = time.time() + timeout
    while True:
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                if time.time() > deadline:
                    return False
                time.sleep(0.1)
            else:
                return True


def test_cli_startup_lines_are_shown_even_when_logging_is_muted(tmp_path):
    """The lifecycle lines survive level = CRIT with the access log off."""
    process, port = _start_cli_server(tmp_path, level="CRIT")
    _stop_cli_server(process)
    output = process.stderr.read()
    assert EVENT_LOOP_RE.search(output), output
    assert "Serving HTTP on 127.0.0.1:%d" % port in output
    assert "h11, ip=" not in output


def test_cli_startup_lists_every_worker(tmp_path):
    process, port = _start_cli_server(tmp_path, workers=3, level="CRIT")
    _stop_cli_server(process)
    output = process.stderr.read()
    assert "Waiting for all workers (3)" in output
    assert "Worker #1 ready (current)" in output
    assert "Worker #2 ready" in output
    assert "Worker #3 ready" in output
    assert "Serving HTTP on 127.0.0.1:%d" % port in output
    assert output.index("Worker #1 ready (current)") < output.index("Serving HTTP on")


def test_cli_access_log_matches_the_documented_format(tmp_path):
    process, port = _start_cli_server(tmp_path, level="INFO", access=True)
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/" % port, timeout=5) as ok:
            assert ok.status == 200
        try:
            urllib.request.urlopen("http://127.0.0.1:%d/missing.html" % port, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
    finally:
        _stop_cli_server(process)
    lines = process.stderr.read().splitlines()
    assert any(ACCESS_LINE_RE.match(line) for line in lines), lines
    assert any("path=/missing.html, code=404" in line for line in lines), lines


def test_cli_stops_cleanly_on_ctrl_c(tmp_path):
    """Ctrl+C must stop the workers too, and leave the port free."""
    process, port = _start_cli_server(tmp_path, workers=2, new_process_group=True)
    try:
        if sys.platform == "win32":  # pragma: no cover - platform dependent
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:  # pragma: no cover
            raise AssertionError("the server did not stop") from None
        assert process.returncode == 0
        assert _wait_port_released(port), "a worker is still serving the port"
        output = process.stderr.read()
        assert "Shutting down" in output
        assert "Shutdown complete" in output
    finally:
        _stop_cli_server(process)
