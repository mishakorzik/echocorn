# Echocorn

**Echocorn** is a fast, lightweight ASGI server: a hand written HTTP/1.1
implementation plus first class HTTP/2 built on
[`h2`](https://pypi.org/project/h2/). It runs modern async applications
(FastAPI, Starlette, Quart, Django, ...) with a small dependency footprint and
the protocol details that matter in production: RFC compliant framing, correct
HTTP/2 flow control, backpressure, timeouts, TLS with ALPN and graceful
shutdown.

---

## Features

* **HTTP/1.1**: keep-alive and pipelining, chunked request
  and response bodies, `Expect: 100-continue`, trailers, informational (1xx)
  responses, close-delimited HTTP/1.0 bodies.
* **HTTP/2**: ALPN over TLS and h2c with prior knowledge, concurrent
  streams, inbound **and** outbound flow control, stream resets, GOAWAY, PING,
  trailers and `SETTINGS` advertised to clients.
* **WebSockets** over `ws://` and `wss://`: the ASGI `websocket`
  protocol with subprotocol negotiation, ping/pong, fragmentation, strict frame
  validation (masking, reserved bits, UTF-8, size limits), backpressure and a
  proper close handshake. WebSocket over HTTP/2 is deliberately not
  advertised, so browsers upgrade over HTTP/1.1 as they do with other servers.
* **Transparent compression**: `gzip`/`deflate` negotiated with
  `Accept-Encoding` quality values on HTTP/1.1 and HTTP/2 alike, applied only to
  compressible, non-partial responses, with a streaming compressor (no threads).
  Negotiated answers carry `Vary: Accept-Encoding` and `deflate` uses the zlib
  wrapper.
* **Security by default**: strict request framing that rejects request smuggling
  (`Transfer-Encoding` + `Content-Length`, conflicting lengths, obs-fold,
  illegal names/values), header injection protection in both directions,
  connection-specific header stripping for HTTP/2, optional hardened response
  headers and domain binding.
* **Abuse resistance and rate limiting**: one absolute request deadline per
  request (TLS handshake included), TCP reset for stalled peers,
  connection/head/body limits, socket options, and `[ratelimit]` - per client
  address, over a sliding window, with one burst per window and a lockout, counted
  for all workers together in one shared table (no file, no disk on the request
  path); over-limit requests get `429` + `Retry-After` and never reach the
  application.
* **Backpressure everywhere**: bounded request queues, socket read pausing, write
  buffer watermarks and HTTP/2 flow-control windows, so a slow client never
  becomes unbounded memory growth.
* **Optional HTTP to HTTPS redirect** (`[redirect] enabled = true`), served by a
  worker of its own, keeping the path and query string.
* **Reverse proxy mode**: `app = "127.0.0.1:5000"` puts the whole server in front
  of a program that is already listening locally; TLS, HTTP/2, compression, the
  limits and the redirect keep working, the upstream connection is pooled, both
  bodies are streamed, WebSockets are tunnelled and `X-Forwarded-*` is rewritten.
* **One configuration file** (`echocorn.toml`, read with the standard library
  `tomllib`), validated at startup, with `uvloop` picked up automatically, a
  multi-process model over one shared listening socket and an embeddable
  `ASGIServer` API.

---

## Installation

Python 3.11 or newer (the configuration file is read with `tomllib`):

```bash
pip install echocorn

pip install "echocorn[uvloop]"  # libuv event loop (not available on Windows)
pip install "echocorn[test]"    # test dependencies
```

---

## Quick start

Everything the server needs is in one TOML file, next to your application:

```toml
# echocorn.toml
app = "app:app"  # "module:attribute", or "127.0.0.1:5000" / "10.0.0.16:8080"

[server]
host = "0.0.0.0"
port = 8000
workers = 4
compression = true
safe_headers = true

[tls]
certfile = "cert.pem"
keyfile = "key.pem"
```

```bash
echocorn --config echocorn.toml

echocorn --help  # help menu
echocorn --version
```

`--config` is the only option the command line takes (no environment variable,
no server flag). A fully commented example ships with the project
([`echocorn.toml`](echocorn.toml)); copy it and edit what you care about.

### Embedding

```python
import asyncio
from echocorn import ASGIServer, ServerConfig

config = ServerConfig(host="127.0.0.1", port=8080, compression=True)
server = ASGIServer(app, config)

asyncio.run(server.serve())  # or server.run() to block
```

An existing configuration file can be reused with the same validation the
command line applies:

```python
from echocorn import ASGIServer, load_settings, resolve_app

settings = load_settings("echocorn.toml")  # the path is always explicit
ASGIServer(resolve_app(settings.app, settings.config), settings.config).run()
```

`resolve_app` imports a `module:attribute` setting and turns a `host:port` one
into a proxy (`import_app` is the module-only form). `server.request_stop()` asks
the server to shut down cleanly and is thread-safe.

### Frameworks

Native ASGI applications (Starlette, FastAPI, Quart, Django, Litestar, ...) run
directly: `app = "myapp:asgi_app"`. Flask is WSGI, so it needs an adapter - the
standard one is `asgiref`, a single extra line:

```python
# app.py
from asgiref.wsgi import WsgiToAsgi
from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return {"hello": "world"}

app = WsgiToAsgi(app)
```

A WSGI adapter that rejects the ASGI `lifespan` scope is detected immediately:
the server logs it and serves instead of waiting for the handshake to time out.

### Reverse proxy

When the program to serve *already* listens on a local address, name it by
address instead of by module:

```toml
app = "127.0.0.1:5000"

[server]
port = 443
compression = true

[tls]
certfile = "cert.pem"
keyfile = "key.pem"

[redirect]
enabled = true
port = 80
```

A request is forwarded as plain HTTP/1.1 and the answer is streamed back: neither
body is buffered whole, a chunked upload stays chunked, and the upstream
connection is pooled and reused. The `Host` field is replaced by the upstream
address, while `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`,
`X-Forwarded-Host` and `X-Forwarded-Port` describe the real client - **replaced,
never extended**: whatever the client sent (including `Forwarded`) is thrown away
first, so an application, its logs or its own rate limiter cannot be lied to.
The older spellings of the same two claims - `X-Forwarded-Ssl`,
`X-Forwarded-Scheme`, `X-Url-Scheme`, `X-Https`, `Front-End-Https` - are rebuilt
from the connection as well: a framework that still reads one of them to decide
about a secure cookie, or about whether to trust its own authentication, must
not be told by the client that a plaintext request was encrypted.
Hop-by-hop fields are dropped in both directions and the framing is re-derived,
so an HTTP/2 client gets a close-delimited or chunked upstream answer just as
well, and an announced trailer section is relayed. Every proxy connection is an
`asyncio.Protocol`, like the rest of the server: one coroutine per exchange,
with write-watermark backpressure.

Two failure modes that would otherwise be a mysterious `502` are handled: a
pooled connection the upstream closed meanwhile is detected on the first write
and the request is sent once more on a fresh connection (idempotent methods
without a body only, since a body already read cannot be replayed), and an
answer that dies mid-body is *cut*, never framed as whole - on HTTP/1.1 the
connection closes with the body unterminated, on HTTP/2 the stream is reset.
`max_response_size` caps what the proxy relays (a too-large answer is a `502`
before it starts, a streamed one that grows past the limit is cut off), and
`request_timeout` bounds the whole exchange. An upstream head that is cut short,
or one that arrives in pieces and is never finished, is a `502` too - and one
that grows past `max_header_size` is refused whether it arrived in one piece or
in ten, since the reader waits for the bytes it has not seen yet instead of
walking the ones it has. A WebSocket upgrade is proxied too:
the handshake is repeated against the upstream, frames are forwarded both ways
(a ping is answered on the side it arrives on), a refused handshake is relayed
as it is so a client sees the application's `401`, and a tunnel never returns to
the pool. An unreachable upstream answers `502 Bad Gateway` with the reason in
the body.

A `host:port` target must be local - loopback (`127.0.0.0/8`, `::1`, `localhost`),
a private network (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) or
link-local (`169.254.0.0/16`, `fe80::/10`) - so `10.0.0.16:8080` is valid while
`example.com:80` is refused: a configuration file can never turn the server into
an open proxy. The hop to the upstream is always HTTP/1.1 (h2c to the upstream is
not used), and the same switch is available from Python:

```python
from echocorn import ASGIServer, ServerConfig, resolve_app

config = ServerConfig(port=443, certfile="cert.pem", keyfile="key.pem")
ASGIServer(resolve_app("127.0.0.1:5000", config), config).run()
```

---

## Command line

```
usage: echocorn --config PATH

Options:
  --config PATH   configuration file to read (required)
  -h, --help      show this message
  --version       show the version
  --about         show version and author information
```

TLS connections negotiate `h2` through ALPN and fall back to `http/1.1`.
Cleartext connections speak HTTP/2 when the client sends the HTTP/2 connection
preface (h2c with prior knowledge); anything else is HTTP/1.1.
Upgrade-based `h2c` is intentionally not implemented.

---

## Security

* Strict request framing removes the classic request smuggling vectors; field
  names and values are validated in both directions, so response splitting
  (`CRLF` injection) is impossible, and access log fields are escaped so a
  hostile path cannot forge log entries.
* Every request the server refuses itself - a misdirected `421`, a refused
  method, a head that was too large, a rate limited client, an illegal upgrade -
  is logged as a `WARN` line shaped like the access log (address, method, target,
  status, reason). Those answers never reach the application, so the log is the
  only place they can be seen.
* A single absolute deadline, per-stream deadlines and an idle timeout (HTTP/2)
  stop slow-loris attacks during the TLS handshake, the head and the body.
* WebSocket frames are validated strictly (masking, reserved bits, non-minimal
  lengths, control frame rules, UTF-8) and messages are capped by
  `websocket.max_message_size`.
* Heads, header counts, bodies and simultaneous connections are all bounded, and
  a protocol that is switched off cannot be reached at all.
* `safe_headers` adds HSTS, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy` and the cross-origin policies.

For production, pair Echocorn with the usual hardening: a TLS 1.2+ cipher policy,
OS tuning (file descriptor limits, `somaxconn`), a reverse proxy or load balancer
where appropriate, and monitoring.

---

## Screenshots

Examples of running Echocorn and request logs:

<img width="99.9%" src="https://raw.githubusercontent.com/mishakorzik/echocorn/refs/heads/main/screenshot1.jpg"/>
<img width="99.9%" src="https://raw.githubusercontent.com/mishakorzik/echocorn/refs/heads/main/screenshot2.jpg"/>

---

## Donate

If you find Echocorn useful and want to support development, you can donate here:

[<img title="Donate" src="https://img.shields.io/badge/Donate-Echocorn-blue?style=for-the-badge&logo=github"/>](https://www.buymeacoffee.com/misakorzik)
