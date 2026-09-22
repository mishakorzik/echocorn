"""
Integration tests against the frameworks Echocorn is meant to serve.

Quart is a native ASGI framework, so it exercises the plain ASGI path, its
WebSocket support included. Flask is a WSGI framework: the documented way to
serve it with an ASGI server is the ``asgiref`` WSGI-to-ASGI bridge, which is
what these tests use, so the request/response path under test is the real one.
"""

from __future__ import annotations

import json

import pytest

from conftest import H2Client, ServerThread

quart = pytest.importorskip("quart", reason="quart is not installed")

from quart import Quart, jsonify, request, websocket  # noqa: E402

ECHO_PREFIX = "echo:"


def build_quart_app() -> "Quart":
    app = Quart(__name__)

    @app.get("/")
    async def index():
        return jsonify({"framework": "quart", "path": request.path})

    @app.post("/echo")
    async def echo():
        body = await request.get_data()
        return jsonify({"length": len(body), "query": request.args.get("x")})

    @app.get("/stream")
    async def stream():
        async def generate():
            for index in range(5):
                yield b"chunk-%d;" % index

        return generate(), {"content-type": "text/plain"}

    @app.websocket("/ws")
    async def ws():
        while True:
            message = await websocket.receive()
            await websocket.send(ECHO_PREFIX + message)

    @app.websocket("/ws/subprotocol")
    async def ws_subprotocol():
        await websocket.accept(subprotocol="chat")
        while True:
            message = await websocket.receive()
            await websocket.send(ECHO_PREFIX + message)

    @app.websocket("/ws/denied")
    async def ws_denied():
        # A framework answers a refused handshake through the
        # "websocket.http.response" ASGI extension.
        return {"error": "authenticate first"}, 401, {"www-authenticate": "Bearer"}

    return app


@pytest.fixture()
def quart_server():
    with ServerThread(build_quart_app(), compression=True) as instance:
        yield instance


def test_quart_over_http11(quart_server: ServerThread):
    httpx = pytest.importorskip("httpx")
    base = "http://%s:%d" % (quart_server.host, quart_server.port)
    with httpx.Client(base_url=base, timeout=10.0) as client:
        assert client.get("/").json() == {"framework": "quart", "path": "/"}
        assert client.post("/echo?x=7", content=b"abcd").json() == {
            "length": 4,
            "query": "7",
        }
        assert client.get("/stream").text == "".join("chunk-%d;" % i for i in range(5))


def test_quart_keep_alive_and_pipelining(quart_server: ServerThread):
    httpx = pytest.importorskip("httpx")
    base = "http://%s:%d" % (quart_server.host, quart_server.port)
    with httpx.Client(base_url=base, timeout=10.0) as client:
        for _ in range(5):
            assert client.get("/").status_code == 200


def test_quart_over_http2(quart_server: ServerThread):
    with H2Client(quart_server) as client:
        stream_id = client.request("/")
        response = client.wait(stream_id)
        assert response.status == 200
        assert json.loads(bytes(response.body))["framework"] == "quart"

        stream_id = client.request("/stream")
        response = client.wait(stream_id, timeout=20)
        assert bytes(response.body) == "".join("chunk-%d;" % i for i in range(5)).encode()


def test_quart_websocket_with_a_synchronous_client(quart_server: ServerThread):
    websockets = pytest.importorskip("websockets.sync.client")
    url = "ws://%s:%d/ws" % (quart_server.host, quart_server.port)
    with websockets.connect(url, open_timeout=10) as socket:
        socket.send("hello")
        assert socket.recv(timeout=10) == ECHO_PREFIX + "hello"
        socket.send("world")
        assert socket.recv(timeout=10) == ECHO_PREFIX + "world"
        socket.close()


def test_quart_websocket_with_an_asyncio_client(quart_server: ServerThread):
    """The asynchronous client negotiates a subprotocol and pings the server."""
    asyncio_websockets = pytest.importorskip("websockets.asyncio.client")
    import asyncio

    url = "ws://%s:%d/ws/subprotocol" % (quart_server.host, quart_server.port)

    async def run() -> None:
        async with asyncio_websockets.connect(
            url, subprotocols=["chat"], open_timeout=10, ping_interval=None
        ) as socket:
            assert socket.subprotocol == "chat"
            pong = await socket.ping(b"probe")
            await asyncio.wait_for(pong, timeout=10)
            await socket.send("async")
            assert await asyncio.wait_for(socket.recv(), timeout=10) == ECHO_PREFIX + "async"

    asyncio.run(run())


def test_quart_rejected_handshake_returns_a_real_http_response(quart_server: ServerThread):
    """Quart's 401 reply must reach the client intact, not as a bare 403."""
    httpx = pytest.importorskip("httpx")
    import websockets.sync.client

    url = "ws://%s:%d/ws/denied" % (quart_server.host, quart_server.port)
    with pytest.raises(Exception) as excinfo:
        with websockets.sync.client.connect(url, open_timeout=10):
            pass
    assert "401" in str(excinfo.value)

    # The body is part of the response, so read the raw bytes as well.
    response = httpx.get(
        "http://%s:%d/ws/denied" % (quart_server.host, quart_server.port),
        headers={
            "connection": "Upgrade",
            "upgrade": "websocket",
            "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
            "sec-websocket-version": "13",
        },
        timeout=10.0,
    )
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json() == {"error": "authenticate first"}


def test_quart_websocket_large_and_fragmented_messages(quart_server: ServerThread):
    """A big message and explicit fragments must survive the round trip."""
    asyncio_websockets = pytest.importorskip("websockets.asyncio.client")
    import asyncio

    url = "ws://%s:%d/ws" % (quart_server.host, quart_server.port)
    payload = "x" * 400_000

    async def run() -> None:
        async with asyncio_websockets.connect(
            url, open_timeout=10, ping_interval=None, max_size=None
        ) as socket:
            await socket.send(payload)
            assert await asyncio.wait_for(socket.recv(), timeout=20) == ECHO_PREFIX + payload
            # Two fragments of one message, interleaved with a ping.
            await socket.send(["frag-", "mented"])
            await socket.ping(b"mid")
            assert await asyncio.wait_for(socket.recv(), timeout=10) == ECHO_PREFIX + "frag-mented"

    asyncio.run(run())


def test_quart_websocket_close_handshake(quart_server: ServerThread):
    """The client's close frame is answered with the same code."""
    asyncio_websockets = pytest.importorskip("websockets.asyncio.client")
    import asyncio
    from websockets.exceptions import ConnectionClosed

    url = "ws://%s:%d/ws" % (quart_server.host, quart_server.port)

    async def run() -> None:
        socket = await asyncio_websockets.connect(url, open_timeout=10, ping_interval=None)
        await socket.send("bye")
        assert await asyncio.wait_for(socket.recv(), timeout=10) == ECHO_PREFIX + "bye"
        await socket.close(code=1000, reason="done")
        with pytest.raises(ConnectionClosed) as excinfo:
            await asyncio.wait_for(socket.recv(), timeout=10)
        assert excinfo.value.rcvd is not None
        assert excinfo.value.rcvd.code == 1000

    asyncio.run(run())


# Flask over the standard WSGI-to-ASGI bridge
def build_flask_asgi_app():
    asgiref_wsgi = pytest.importorskip(
        "asgiref.wsgi", reason="asgiref is not installed"
    )
    from flask import Flask, jsonify

    app = Flask(__name__)

    @app.get("/")
    def index():
        return jsonify({"framework": "flask"})

    @app.post("/echo")
    def echo():
        from flask import request as flask_request

        return jsonify(
            {
                "length": len(flask_request.get_data()),
                "query": flask_request.args.get("x"),
            }
        )

    @app.get("/stream")
    def stream():
        from flask import Response

        return Response(
            ("chunk-%d;" % index for index in range(5)), mimetype="text/plain"
        )

    @app.get("/boom")
    def boom():
        raise RuntimeError("kaboom")

    return asgiref_wsgi.WsgiToAsgi(app)


@pytest.fixture()
def flask_server():
    app = build_flask_asgi_app()
    with ServerThread(app, compression=True) as instance:
        yield instance


def test_flask_over_http11(flask_server: ServerThread):
    httpx = pytest.importorskip("httpx")
    base = "http://%s:%d" % (flask_server.host, flask_server.port)
    with httpx.Client(base_url=base, timeout=10.0) as client:
        assert client.get("/").json() == {"framework": "flask"}
        assert client.post("/echo?x=3", content=b"12345").json() == {
            "length": 5,
            "query": "3",
        }
        assert client.get("/stream").text == "".join("chunk-%d;" % i for i in range(5))
        assert client.get("/boom").status_code == 500


def test_flask_keep_alive_reuses_the_connection(flask_server: ServerThread):
    httpx = pytest.importorskip("httpx")
    base = "http://%s:%d" % (flask_server.host, flask_server.port)
    with httpx.Client(base_url=base, timeout=10.0) as client:
        for _ in range(5):
            assert client.get("/").status_code == 200


def test_flask_over_http2(flask_server: ServerThread):
    with H2Client(flask_server) as client:
        stream_id = client.request("/")
        response = client.wait(stream_id)
        assert response.status == 200
        assert json.loads(bytes(response.body)) == {"framework": "flask"}


def test_flask_large_upload_over_http2(flask_server: ServerThread):
    body = b"u" * 300_000
    # WSGI has no way to describe a body without CONTENT_LENGTH, so real clients
    # always send it; without it Werkzeug sees an empty request body.
    length = [(b"content-length", str(len(body)).encode())]
    with H2Client(flask_server, initial_window_size=16384) as client:
        stream_id = client.request("/echo", method="POST", body=body, headers=length)
        response = client.wait(stream_id, timeout=30)
        assert json.loads(bytes(response.body))["length"] == len(body)


def test_flask_large_response_over_http11(flask_server: ServerThread):
    """A big JSON body must pass the WSGI bridge unchanged."""
    import flask

    app = flask.Flask("large")

    @app.get("/big")
    def big():
        return flask.jsonify({"payload": "y" * 500_000})

    from asgiref.wsgi import WsgiToAsgi

    with ServerThread(WsgiToAsgi(app)) as server:
        httpx = pytest.importorskip("httpx")
        base = "http://%s:%d" % (server.host, server.port)
        with httpx.Client(base_url=base, timeout=20.0) as client:
            assert len(client.get("/big").json()["payload"]) == 500_000
