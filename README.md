# Echocorn

Fast, lightweight ASGI server with HTTP/1.1, HTTP/2 and WebSockets. For FastAPI, Starlette, Django, Quart and others.

## Install

Python 3.11+:

```bash
pip install echocorn
pip install "echocorn[uvloop]"  # faster loop, no Windows
```

## Quick start

`echocorn.toml` next to your app:

```toml
app = "app:app"  # or "127.0.0.1:5000" for proxy mode

[server]
host = "0.0.0.0"
port = 8000
workers = 4
```

```bash
echocorn --config echocorn.toml
```

Full example with comments: [`echocorn.toml`](echocorn.toml).

Python API:

```python
from echocorn import ASGIServer, ServerConfig
ASGIServer(app, ServerConfig(host="127.0.0.1", port=8080)).run()
# or: await server.serve()
```

Flask (WSGI) needs one line:

```python
from asgiref.wsgi import WsgiToAsgi
app = WsgiToAsgi(app)
```

## Features

* HTTP/1.1 (keep-alive, chunked, 100-continue, trailers) and HTTP/2 (ALPN, h2c, flow control, GOAWAY).
* WebSockets (`ws/wss`, subprotocols, ping/pong, fragmentation).
* gzip/deflate, `Vary: Accept-Encoding`.
* Strict framing (no smuggling), header injection protection, `safe_headers`, `bind_domain`.
* Timeouts, limits, rate limiting (`429 + Retry-After`), graceful shutdown.
* HTTP->HTTPS redirect and reverse-proxy mode (`app = "127.0.0.1:5000"`).

Proxy example:

```toml
app = "127.0.0.1:5000"

[server]
port = 443

[tls]
certfile = "cert.pem"
keyfile = "key.pem"

[redirect]
enabled = true
port = 80
```

Only local upstreams allowed (`127.0.0.0/8`, `10/8`, `192.168/16`, `::1`, ...). `X-Forwarded-*` is replaced, never appended.

## CLI

```
usage: echocorn --config PATH
  --config PATH   config file (required)
  -h, --help
  --version
  --about
```

## Production notes

* TLS 1.2+, tune `somaxconn`, file descriptors, monitoring.
* Set `max_request_size`, `request_timeout`, `[ratelimit]` for public services.
