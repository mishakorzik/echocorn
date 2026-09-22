# Echocorn

**Echocorn** is a fast, lightweight ASGI server with a hand written HTTP/1.1
implementation and first class HTTP/2 support built on [`h2`](https://pypi.org/project/h2/).
It targets modern async applications (FastAPI, Starlette, Quart, Django, ...) and
keeps a
small dependency footprint while implementing the protocol details that matter in
production: RFC compliant framing, correct HTTP/2 flow control, backpressure,
timeouts, TLS with ALPN and graceful shutdown.

---

## Key features

* **HTTP/1.1** (RFC 9110 / RFC 9112): keep-alive and pipelining, chunked request
  and response bodies, `Expect: 100-continue`, trailers, informational (1xx)
  responses, close-delimited HTTP/1.0 bodies.
* **HTTP/2** (RFC 9113): ALPN over TLS and h2c with prior knowledge on cleartext
  ports, concurrent streams, correct inbound **and** outbound flow control
  (`WINDOW_UPDATE` handling), stream resets, GOAWAY, PING, trailers and
  `SETTINGS` advertised to clients.
* **Security by default**: strict request framing that rejects request smuggling
  attempts (`Transfer-Encoding` + `Content-Length`, conflicting lengths, obs-fold,
  illegal header names/values), header injection protection, connection-specific
  header stripping for HTTP/2, optional hardened response headers and domain
  binding.
* **Transparent compression**: `gzip`/`deflate` negotiated with
  `Accept-Encoding` quality values, applied only to compressible, non-partial
  responses, with a streaming compressor (no threads involved).
* **WebSockets** (RFC 6455) over `ws://` and `wss://`: the ASGI `websocket`
  protocol with subprotocol negotiation, ping/pong, fragmentation, strict frame
  validation (masking, reserved bits, UTF-8, size limits), backpressure and a
  proper close handshake. WebSocket over HTTP/2 (RFC 8441) is deliberately not
  advertised, so browsers open an HTTP/1.1 connection for upgrades, exactly as
  they do with other servers.
* **Backpressure everywhere**: bounded request queues, socket read pausing, write
  buffer watermark handling and HTTP/2 flow-control windows. A slow client never
  turns into unbounded memory growth.
* **Abuse resistance**: a single total request deadline (from the TCP accept
  onwards, TLS handshake included), TCP reset for stalled peers, connection and
  header limits, request body limits and socket level latency/liveness options.
* **One configuration file** (`echocorn.toml`, read with the standard library
  `tomllib`): settings grouped into `[server]`, `[http1]`, `[http2]`,
  `[websocket]`, `[logging]`, `[tls]` and `[redirect]`, each protocol switchable
  on its own, validated at startup, with nothing extra to install.
* **Optional HTTP to HTTPS redirect**: `[redirect] enabled = true` answers
  plaintext requests with a redirect to the HTTPS origin, keeping the path and
  query string. One worker of its own does nothing but the redirect, so
  `workers = 4` gives one redirect worker and three that serve the
  application; a single worker skips the redirect.
* **Optional coloured logging**: `[logging] color = true` paints the timestamp
  and the level with ANSI escapes for a terminal, without changing the layout
  of a line.
* **Reverse proxy mode**: `app = "127.0.0.1:5000"` puts the whole server in
  front of a program that is already listening on the loopback interface - a
  development server, a WSGI process, an application that will not move to
  ASGI. TLS, HTTP/2, compression, the limits and the redirect keep working, the
  upstream connection is pooled and reused, both bodies are streamed and
  WebSocket sessions are tunnelled frame by frame; the target may be on the
  loopback interface or on a private network, never a public address.
* **Production ergonomics**: graceful shutdown on `SIGINT`/`SIGTERM` (including
  every worker process), a multi-process model over one shared listening socket,
  `uvloop` picked up automatically when it is installed, keep-alive/shutdown
  timeouts, request size limits, one-line access logging and an embeddable
  `ASGIServer` API.

---

## Installation

Python 3.11 or newer (the configuration file is read with `tomllib`):

```bash
pip install echocorn
```

Optional extras:

```bash
pip install "echocorn[uvloop]"  # libuv event loop (not available on Windows)
pip install "echocorn[test]"    # test dependencies
```

---

## Quick start

Everything the server needs is in one TOML file, `echocorn.toml`, which sits
next to your application:

```toml
# echocorn.toml
app = "app:app"  # "module:attribute", or "127.0.0.1:5000" / "10.0.0.16:8080"

[server]
host = "0.0.0.0"
port = 8000
workers = 4
compression = true
```

```bash
echocorn --config echocorn.toml
```

`--config` is the only option the command line takes: the path to the
configuration file (there is no environment variable and no server flag).

A fully commented example ships with the project
([`echocorn.toml`](echocorn.toml)); copy it and edit the values you care about.
The file is read with the standard library `tomllib`, so there is no dependency
to install. Serve HTTP/2 over TLS with compression and hardened headers by
filling in the related keys:

```toml
[server]
compression = true
safe_headers = true

[tls]
certfile = "cert.pem"
keyfile = "key.pem"
```

```bash
echocorn --help  # how to start it
echocorn --version
```

### Configuration reference

Settings are grouped into sections, and each section maps to the fields of
`ServerConfig`; every value is validated while the file is loaded.

`app` is the only top-level key and it is required. It names an ASGI
application as `module:attribute`, whose module is imported from the directory
of the configuration file (so a deployment directory stays self contained), or
a server that is already listening locally as `host:port`, which turns Echocorn
into a [reverse proxy](#reverse-proxy) in front of it.

**`[server]`** - binding, process model, limits and timeouts:

| Key                  | Default        | Meaning                                                       |
| -------------------- | -------------- | ------------------------------------------------------------- |
| `host`               | all interfaces | Address to bind (dual-stack when empty)                       |
| `port`               | `8000`         | Port to bind                                                  |
| `workers`            | `1`            | Worker processes sharing the listening socket                 |
| `bind_domain`        | off            | Reject requests whose `Host`/`:authority` differs (421)       |
| `compression`        | `false`        | gzip/deflate response compression                             |
| `safe_headers`       | `false`        | Add HSTS, CSP related and other hardening headers             |
| `request_timeout`    | `10.0`         | The one timeout guarding a request in every phase (`0` = off) |
| `keep_alive_timeout` | `5.0`          | Idle time between two requests on a connection                |
| `graceful_timeout`   | `10.0`         | Time to drain in-flight requests on shutdown                  |
| `max_connections`    | `0`            | Simultaneous connections, extra ones get `503`                |
| `max_request_size`   | `0`            | Maximum request body size in bytes                            |
| `max_header_size`    | `16384`        | Maximum size of the request head / header list                |
| `max_header_count`   | `128`          | Maximum number of header fields per request                   |
| `backlog`            | `2048`         | `listen(2)` backlog                                           |

**`[http1]`** and **`[http2]`** - one switch per protocol; what is switched off
is not offered through ALPN either, and a client that speaks it anyway is
answered with `505`:

| Key                              | Default | Meaning                                                        |
| -------------------------------- | ------- | -------------------------------------------------------------- |
| `http1.enabled`                  | `true`  | Serve HTTP/1.1 (RFC 9110, RFC 9112)                            |
| `http2.enabled`                  | `true`  | Serve HTTP/2 (RFC 9113) over TLS/ALPN or `h2c` prior knowledge |
| `http2.max_concurrent_streams`   | `100`   | `SETTINGS_MAX_CONCURRENT_STREAMS`                              |
| `http2.initial_window_size`      | `65535` | `SETTINGS_INITIAL_WINDOW_SIZE`                                 |
| `http2.max_frame_size`           | `16384` | `SETTINGS_MAX_FRAME_SIZE`                                      |
| `http2.max_header_list_size`     | `16384` | `SETTINGS_MAX_HEADER_LIST_SIZE`                                |

**`[websocket]`** - RFC 6455 over `ws://` and `wss://`:

| Key                         | Default   | Meaning                                           |
| --------------------------- | --------- | ------------------------------------------------- |
| `websocket.enabled`         | `true`    | Accept WebSocket upgrades (needs `http1.enabled`) |
| `websocket.max_message_size`| `4194304` | Maximum size of one message, fragments included   |

**`[logging]`**:

| Key              | Default | Meaning                                           |
| ---------------- | ------- | ------------------------------------------------- |
| `logging.level`  | `INFO`  | `CRIT`/`ERROR`/`WARN`/`INFO`/`DEBUG`              |
| `logging.access` | `true`  | One line per request and per WebSocket session    |
| `logging.color`  | `false` | Colour the timestamp and the level for a terminal |

**`[tls]`**:

| Key                            | Default | Meaning                                  |
| ------------------------------ | ------- | ---------------------------------------- |
| `tls.certfile` / `tls.keyfile` | off     | Certificate chain and key; enables ALPN  |

**`[redirect]`** - the optional plaintext listener that sends HTTP clients to
HTTPS; it needs `[tls]` and at least two workers:

| Key                | Default               | Meaning                                         |
| ------------------ | --------------------- | ----------------------------------------------- |
| `redirect.enabled` | `false`               | Listen on `redirect.port` and redirect to HTTPS |
| `redirect.host`    | follows `server.host` | Address of the redirect listener                |
| `redirect.port`    | `80`                  | Port of the redirect listener (`0` picks one)   |
| `redirect.status`  | `308`                 | `308` (default), `301`, `302` or `307`          |

One worker does nothing but the redirect, so `workers = 4` leaves three workers
for the application and `workers = 1` skips the redirect entirely (the single
worker serves the site, and a warning says so). With `workers = 2` and above
exactly one redirect listener exists, never one per worker. An embedded
`ASGIServer.serve()` has no worker to spare either: it serves the redirect next
to the application in its own process.

A request that names neither a `Host` header nor a `bind_domain` is refused with
`400` instead of being redirected to a guess, and only the path of the request
is carried over - a redirect never leaks credentials or a fragment.

A key that does not exist is refused with a "did you mean" hint (and a flat,
pre-sections file is pointed at the section it moved to), a value of the wrong
type names the key, and an out of range value is reported with the limit it
broke - all three with the file name, before the server binds a socket:

```
echocorn: /srv/app/echocorn.toml: unknown setting 'server.prot'; did you mean port?
echocorn: /srv/app/echocorn.toml: unknown setting 'port'; did you mean server.port?
echocorn: /srv/app/echocorn.toml: server.port must be an integer, got str
echocorn: /srv/app/echocorn.toml: request_timeout must not be negative
```

Relative `tls.certfile`/`tls.keyfile` paths are resolved from the directory of
the configuration file. On Windows write such a path with forward slashes, or
inside single quotes, because backslashes are escape characters in a TOML
string.

### Embedding

```python
import asyncio
from echocorn import ASGIServer, ServerConfig

config = ServerConfig(host="127.0.0.1", port=8080, compression=True)
server = ASGIServer(app, config)

asyncio.run(server.serve())   # or server.run() to block
```

An existing configuration file can be reused from Python, with the same
validation the command line applies:

```python
from echocorn import ASGIServer, load_settings, resolve_app

settings = load_settings("echocorn.toml")  # the path is always explicit
ASGIServer(resolve_app(settings.app, settings.config), settings.config).run()
```

`resolve_app` imports a `module:attribute` setting; a `host:port` one becomes a
proxy (use `import_app` directly when only the module form is wanted).

Call `server.request_stop()` (thread-safe via `loop.call_soon_threadsafe`) to ask
the server to shut down cleanly.

### Frameworks

Native ASGI applications (Starlette, FastAPI, Quart, Django, Litestar, ...) run
directly, by naming them in the configuration file:

```toml
app = "myapp:asgi_app"
```

```bash
echocorn --config echocorn.toml
```

Flask is a WSGI framework, so it needs an ASGI adapter - the standard one is
`asgiref`, and it is a single extra line:

```python
# app.py
from asgiref.wsgi import WsgiToAsgi
from flask import Flask

flask_app = Flask(__name__)

@flask_app.get("/")
def index():
    return {"hello": "world"}

app = WsgiToAsgi(flask_app)
```

```toml
app = "app:app"
```

```bash
echocorn --config echocorn.toml
```

A WSGI adapter that rejects the ASGI `lifespan` scope is detected immediately:
the server logs it and starts serving instead of waiting for the handshake to
time out.

### Reverse proxy

When the program to serve is *already* listening on a local address - a
framework's own development server, a WSGI process, an old application - name
it by address instead of by module:

```toml
# echocorn.toml
app = "127.0.0.1:5000"    # proxy to a server that already listens here

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

Everything in front of the application keeps working: TLS with ALPN, HTTP/1.1
and HTTP/2, compression, the header and head limits, request timeouts, the
access log and the HTTP to HTTPS redirect - so a local development server can
be reached as `https://example.com` on port 443 with `http://` redirected, the
way a reverse proxy is normally set up.

A request is forwarded as a plain HTTP/1.1 request, and the answer is streamed
back as it is produced: neither body is buffered whole, a chunked upload stays
chunked, and the upstream connection is kept alive and reused. The original
`Host` header is replaced by the upstream address while `X-Forwarded-For`,
`X-Real-IP`, `X-Forwarded-Proto` and `X-Forwarded-Host` tell the upstream what
the client really asked for. Hop-by-hop fields (`Connection`, `Keep-Alive`,
`Transfer-Encoding`, `Upgrade`, `TE`, `Trailer`, ...) are dropped in both
directions, and the framing of the answer is re-derived, so a close-delimited
or chunked upstream answer is served to an HTTP/2 client just as well.

A WebSocket upgrade is proxied too: the handshake is repeated against the
upstream, and once both sides accepted, messages are forwarded frame by frame
in both directions (a ping is answered on the side it arrives on), so a proxied
session behaves like a direct one. A handshake the upstream refuses is relayed
as it is - a client sees the `401` of the application rather than a generic
error - and the close code of either side ends the tunnel; a tunnel never goes
back into the pooled connections.

An unreachable or broken upstream answers `502 Bad Gateway` (the reason is in
the body, which is useful next to a development server). A `host:port` target
must be local - loopback (`127.0.0.0/8`, `::1`, `localhost`), a private network
(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), or a link-local
address (`169.254.0.0/16`, `fe80::/10`), so `10.0.0.16:8080` and
`192.168.0.105:5000` are valid while `example.com:80` is refused: a
configuration file can never turn the server into an open proxy.

The client-facing protocol is terminated here and the hop to the upstream is
always HTTP/1.1: an HTTP/2 client (or an HTTP/2 request over TLS with `h2`
ALPN) is translated to HTTP/1.1 on the way out, its answer is re-framed for
HTTP/2 on the way back, and the same holds for a WebSocket session, which is a
plain HTTP/1.1 upgrade on both sides. HTTP/2 to the upstream (`h2c`) is not
used - a local development server is reached over HTTP/1.1.

The same switch is available from Python:

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
preface (h2c with prior knowledge, RFC 9113 section 3.2); anything else is
treated as HTTP/1.1. Upgrade-based `h2c` is intentionally not implemented.

---

## Logging

Every line carries the local time with its UTC offset, the level, the process id
and the message, and the level names are only ever `DEBUG`, `INFO`, `WARN`,
`ERROR` and `CRIT`:

```
2026-09-22 19:44:24 +0300 [INFO ]  381063: Using 'uvloop' as event loop
2026-09-22 19:44:24 +0300 [INFO ]  381063: Waiting for all workers (4)
2026-09-22 19:44:24 +0300 [INFO ]  381063: Worker #1 ready (current)
2026-09-22 19:44:24 +0300 [INFO ]  381066: Worker #3 ready
2026-09-22 19:44:24 +0300 [INFO ]  381065: Worker #2 ready
2026-09-22 19:44:24 +0300 [INFO ]  381067: Worker #4 ready
2026-09-22 19:44:24 +0300 [INFO ]  381063: Serving HTTPS on :8000
```

The service line names the scheme it serves, so a TLS deployment says
`Serving HTTPS on :443` and a plaintext one `Serving HTTP on :8000`; when
`[redirect]` is enabled, `Serving HTTP on :80` is printed first, right before
the TLS listener.

Those lifecycle lines are printed whatever `logging.level` is - the operator
always sees how the server started and stopped - while everything else follows
the configured level. `uvloop` is used automatically when it is importable (the
first line then names it), and each further worker is a child process that
reports in once its socket is bound; the master is worker #1 and prints the
`Serving` lines last.

Requests and WebSocket sessions are logged in the same shape, one line each:

```
2026-09-22 19:44:24 +0300 [INFO ]  381063: h11, ip=127.0.0.1, method=GET, path=/, code=200, time=1.732s
2026-09-20 14:17:59 +0300 [INFO ]  381063: h20, ip=127.0.0.1, method=GET, path=/test.html, code=404, time=0.971s
2026-09-22 19:44:31 +0300 [INFO ]  381063: wss, ip=127.0.0.1, path=/ws, code=1000, time=12.480s, msgs=4
```

`h11` is HTTP/1.1, `h20` is HTTP/2 and `ws`/`wss` are WebSocket sessions over
plaintext and TLS. A WebSocket line reports the close code the session ended
with (a refused handshake reports its HTTP status instead) and how many messages
the peer sent. Control characters in a logged path are escaped, so a hostile
request cannot forge log entries. Set `logging.access = false` to silence the
per-request lines; the startup lines stay.

With `logging.color = true` the timestamp is dimmed and the level is painted -
`DEBUG` blue, `INFO` dark blue, `WARN` yellow, `ERROR` red and `CRIT` magenta -
while the text of a line stays exactly the same, so a log file collected from a
terminal is still readable and machine parseable.

---

## Timeouts and abuse protection

**One deadline per request.** `request_timeout` (default 10 s) is the only
timeout an operator has to reason about. It starts the moment a connection is
accepted - before TLS, before the first byte - and must cover the complete
request head and body. If it does not, the connection is dropped and (on POSIX)
reset with `RST` instead of a `FIN`, so a stalling client learns about the
failure immediately and cannot keep a half-open connection alive. Trickling one
byte per second does not extend the deadline: it is absolute.

While the response is being produced the same budget becomes progress based: it
is restarted on every successful write, so a streaming response may run for as
long as it keeps flowing, while an application that stalls (or a client that
stops reading) is dropped instead of pinning a connection forever.

On HTTP/2 the same budget applies per stream: a stream that times out gets
`RST_STREAM` and the connection keeps serving the other streams, while a
connection that never completes a single request is reset as a whole. Idle
HTTP/2 connections are retired with `GOAWAY`. `0` disables the timeout.

Because the clock starts with the connection, an idle or stalled peer is retired
without the application ever being involved. The keep-alive and graceful
timeouts then handle the phases that follow a fully received request.

**Sockets.** The listening socket sets `SO_REUSEADDR`, `SO_REUSEPORT` (when
`workers > 1` and the platform supports it) and `TCP_NODELAY`; every accepted
socket gets `TCP_NODELAY` and `SO_KEEPALIVE`, so small responses are not delayed
by Nagle and dead peers are detected by the kernel. TLS requires 1.2+, disables
compression and renegotiation, and the handshake is bounded by the same
`request_timeout`.

**Workers.** With `workers > 1` the master binds one listening socket and hands
it to each child, so several processes accept on the same port even where
`SO_REUSEPORT` does not exist. Every worker watches the shared stop event, the
signals and the master itself: a worker whose supervisor disappeared stops
too, so a hard-killed master cannot leave orphan processes (or a port) behind.

**Limits.** `max_connections` finishes over-limit connections with a minimal
`503`; `max_header_size` and `max_header_count` bound request heads (and the
HPACK decoder for HTTP/2); `max_request_size` bounds request bodies and is
enforced while streaming for both protocols (`413`).

---

## Protocol conformance notes

The implementation follows the relevant RFCs where behaviour is observable:

* **Framing (RFC 9112)**: a request containing both `Transfer-Encoding` and
  `Content-Length` is rejected with `400`; multiple `Content-Length` fields must
  agree; `chunked` must be the final transfer coding and may only appear once;
  `Transfer-Encoding` is rejected on HTTP/1.0; responses never mix
  `Content-Length` with `Transfer-Encoding`.
* **Bodies (RFC 9110 §6.4.1)**: 1xx, `204` and `304` responses and responses to
  `HEAD` never carry a body; `Content-Length` is preserved for `HEAD` and `304`
  and omitted for `1xx`/`204`.
* **Content negotiation (RFC 9110 §12.5.3)**: `Accept-Encoding` is parsed with
  quality values and the `*` wildcard; `q=0` disables a coding. The `deflate`
  coding uses the zlib wrapper.
* **HTTP/2 (RFC 9113)**: header names are lower-cased, connection-specific
  fields are never sent, pseudo-header fields are validated, `TE: trailers` is
  the only accepted `TE`, and every DATA frame respects the peer's flow-control
  window while received DATA is acknowledged only after the application
  consumes it.

---

## Testing

```bash
pip install -e ".[test]"
pytest

# The server runs on uvloop when it is installed; the suite can too:
ECHOCORN_TEST_UVLOOP=1 pytest
```

The suite (325+ tests) covers:

* unit tests for header hygiene, content-coding negotiation and request parsing;
* end-to-end HTTP/1.1 over raw sockets: keep-alive, pipelining, chunked bodies,
  `100-continue`, trailers, smuggling rejection, limits, compression;
* end-to-end HTTP/2 with real flow-control accounting, including multi-megabyte
  responses with a 16 KiB peer window, parallel streams, stream resets and
  connection reuse;
* TLS tests validating ALPN (`h2` and `http/1.1`) with a generated certificate;
* WebSocket tests (RFC 6455) over `ws://` and `wss://`: handshake and
  subprotocol negotiation, echo, fragmentation, control frames, UTF-8 and frame
  validation, size limits, close handshake, large messages, and interoperability
  with the `websockets` client library;
* integration tests running Starlette, Quart (HTTP/1.1, h2c and WebSockets) and
  Flask through the `asgiref` WSGI bridge;
* proxy tests: a `host:port` `app` configuration, a proxied request in both
  directions (status, headers, streamed bodies, chunked uploads, `HEAD`),
  `X-Forwarded-*` headers, upstream connection reuse, `502` for a dead or
  broken upstream, a tunnelled WebSocket session (handshake, subprotocol, text,
  bytes, a large message, the relayed refusal and close code), the local-only
  target rule and a CLI run against a real local server;
* configuration tests: the shipped example matches the defaults, every key is
  validated, unknown keys are reported with their section, and the CLI reads its
  app, port and worker count from `--config`;
* protocol switch tests: HTTP/1.1, HTTP/2 and WebSockets each turned off, with
  ALPN and `505` answers checked;
* logging tests: the line format, the five level names, the `h11`/`h20`/`ws`/
  `wss` access lines, log-injection escaping, the coloured formatter and the
  always-on lifecycle lines;
* redirect tests: the `Location` a request is sent to (path, query, port,
  IPv6), a live redirect listener, its `400` answers, the CLI giving the
  redirect a worker of its own and the CLI skipping it with a single worker
  (both ports released on shutdown);
* hardening tests: slow-loris deadlines (headers, bodies, trickle, HTTP/2
  streams), connection limits, request-body and header limits, injection
  attempts, TCP reset behaviour and socket options.

---

## Security

* Request framing is validated strictly, which removes the classic request
  smuggling vectors.
* Header names and values are validated in both directions; response splitting
  (`CRLF` injection) is impossible.
* HTTP/2 forbids connection-specific header fields; any the application tries to
  set are dropped instead of corrupting the HPACK stream.
* A single absolute request deadline (`request_timeout`, 10 s by default)
  counts from the TCP accept and stops slow-loris attacks that trickle headers or
  bodies, including the TLS handshake phase; stalled connections are reset.
* Per-stream deadlines and an idle timeout cover HTTP/2, where the protocol
  itself has no notion of a slow request.
* WebSocket frames are validated strictly (masking, reserved bits, non-minimal
  lengths, control frame rules, UTF-8) and message size is capped by
  `websocket.max_message_size`; a refused upgrade is answered (or, with the
  `websocket.http.response` extension, answered with a real HTTP response).
* Request heads, header counts, request bodies and simultaneous connections are
  all bounded (`max_header_size`, `max_header_count`, `max_request_size`,
  `max_connections`), and a protocol that is switched off cannot be reached at
  all.
* Header names, values and request targets are validated; `NUL`, `CR`, `LF` and
  other control bytes are rejected with `400`, which removes header and log
  injection together with response splitting. Access log fields are escaped as
  well, so a hostile path cannot forge log entries.
* `safe_headers` adds HSTS, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy` and the cross-origin policies.

For production deployment pair Echocorn with standard hardening: TLS 1.2+
cipher policy, OS level tuning (file descriptor limits, `somaxconn`), a reverse
proxy or load balancer where appropriate, and monitoring.

---

## Screenshots

Examples of running Echocorn and request logs:

<img width="99.9%" src="https://raw.githubusercontent.com/mishakorzik/echocorn/refs/heads/main/screenshot1.jpg"/>
<img width="99.9%" src="https://raw.githubusercontent.com/mishakorzik/echocorn/refs/heads/main/screenshot2.jpg"/>

---

## Donate

If you find Echocorn useful and want to support development, you can donate here:

[<img title="Donate" src="https://img.shields.io/badge/Donate-Echocorn-blue?style=for-the-badge&logo=github"/>](https://www.buymeacoffee.com/misakorzik)
