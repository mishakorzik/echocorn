# Echocorn

**Echocorn** is an exceptionally fast, lightweight ASGI server with a custom HTTP/1.1 implementation and first-class HTTP/2 support (powered by the `h2` library). Designed for modern web applications, Echocorn combines high throughput with small resource overhead and includes built-in response compression and hardened HTTP header security.

---

## Key features

* High-performance ASGI server optimized for low-latency workloads
* Native HTTP/1.1 implementation plus built-in HTTP/2 support via `h2`
* Transparent response compression (gzip/deflate/br) to reduce bandwidth usage
* Enhanced HTTP header security (CSP, HSTS, X-Frame-Options, etc.) out of the box
* Minimal dependencies and small memory footprint
* Simple command-line interface for quick deployment

---

## Quick install

Install from PyPI:

```bash
pip install echocorn
```

---

## Quick start

Run your ASGI application (example using a callable named `app` inside `app.py`):

```bash
echocorn --app app:app --port 443
```

Show all available command-line options:

```bash
echocorn --help
```

---

## Example usage

Use Echocorn to serve a FastAPI, Starlette, or any ASGI app. Example with `uvicorn`-style callable:

```bash
# Serve app.app (where `app` is an ASGI application instance)
echocorn --app app:app --host 0.0.0.0 --port 443 --workers 4 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

---

## Configuration & options

Echocorn exposes CLI flags for common server settings such as:

* `--app` — module:callable path to your ASGI application
* `--host` / `--port` — where the server listens
* `--workers` — number of worker processes
* `--certfile`, `--keyfile` — TLS/SSL files for secure connections
* `--compression` — toggle or tune response compression
* `--safe-headers` — enable security headers
* `--domain` — allows requests only if host in headers matches
* `--about` — show about the server

Run `echocorn --help` to see the full set of parameters and defaults.

---

## Security & performance

Echocorn focuses on secure and efficient defaults:

* HTTP header hardening (CSP, HSTS, X-Content-Type-Options, X-Frame-Options) to reduce common web risks
* Built-in compression to reduce latency & bandwidth costs for clients
* Optimised request/response handling path for minimal overhead and maximum throughput

For production use, pair Echocorn with standard hardening measures (firewall rules, TLS best practices, OS-level tuning) and monitor resource usage.

---

## Screenshots

Examples of running Echocorn and request logs:

<img width="48.9%" src="https://raw.githubusercontent.com/mishakorzik/echocorn/refs/heads/main/screenshot_1.jpg"/>
<img width="48.9%" src="https://raw.githubusercontent.com/mishakorzik/echocorn/refs/heads/main/screenshot_2.jpg"/>

---

## Donate

If you find Echocorn useful and want to support development, you can donate here:

[<img title="Donate" src="https://img.shields.io/badge/Donate-Echocorn-blue?style=for-the-badge&logo=github"/>](https://www.buymeacoffee.com/misakorzik)

---

## Community & support

* Telegram: [https://t.me/ubp2q](https://t.me/ubp2q)
* Discord: [https://discord.gg/xwpMuMYW57](https://discord.gg/xwpMuMYW57)

If you find a bug or have questions, open an issue or reach out on Discord.
