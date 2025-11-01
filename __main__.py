#!/usr/bin/env python3
"""
echocorn - Minimal ASGI server implemented fully with asyncio.Protocol
"""
import argparse, asyncio, logging, socket, zlib, os, sys, ssl
from multiprocessing import Process
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

# Optional libs
try:
    import uvloop
except Exception:
    uvloop = None

try:
    import h2.connection
    import h2.config
    import h2.events
    H2_AVAILABLE = True
except Exception:
    H2_AVAILABLE = False

# Add current path
sys.path.insert(0, os.getcwd())

# Params
version = "1.0.0 beta"
author = "Misha Korzhyk"

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("echocorn")

# Constants
SERVER_NAME = "uvloop" if uvloop is not None else "asyncio"
ALLOWED_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'}
H_MAX_HEADER_SIZE = 8192
H2_MAX_FRAME_SIZE = 16384

SAFE_HEADERS = None
BIND_DOMAIN = None

# ----------------------------
# Compression helpers (streaming)
# ----------------------------
class StreamingCompressor:
    def __init__(self, encoding: str):
        if encoding == 'gzip':
            self.compressor = zlib.compressobj(level=6, wbits=31)
        elif encoding == 'deflate':
            self.compressor = zlib.compressobj(level=6, wbits=-zlib.MAX_WBITS)
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")

    async def compress(self, data: bytes) -> bytes:
        return await asyncio.to_thread(self.compressor.compress, data)

    async def flush(self) -> bytes:
        return await asyncio.to_thread(self.compressor.flush)

def _choose_encoding(text: bytes) -> Optional[str]:
    try:
        text = text.decode("latin-1")
    except Exception:
        return None

    for p in [p.strip().split(";", 1)[0].lower() for p in text.split(",") if p.strip()]:
        if p in ("gzip", "deflate"):
            return p
    return None

def _find_accept_encoding(headers: List[Tuple[bytes, bytes]]) -> Optional[str]:
    for name, value in headers:
        if name.lower() == b"accept-encoding":
            return _choose_encoding(value)
    return None

def _is_text_based_response(headers: List[Tuple[bytes, bytes]]) -> bool:
    for name, value in headers:
        if name.lower() == b"content-type":
            try:
                content_type = value.decode("latin-1").lower()
                return any(t in content_type for t in ["text/html", "text/css", "text/javascript", "application/javascript", "application/x-javascript", "text/scss"])
            except Exception:
                continue
    return False

# ----------------------------
# Utilities
# ----------------------------
def import_app(path: str):
    if ":" not in path:
        raise ValueError("app must be module:callable")
    module_name, app_name = path.split(":", 1)
    return getattr(__import__(module_name, fromlist=[app_name]), app_name)

# ----------------------------
# Lifespan
# ----------------------------
async def run_lifespan(app: Callable, timeout: float = 5.0) -> Optional[Any]:
    recv_q: asyncio.Queue = asyncio.Queue()
    started = asyncio.Event()
    stopped = asyncio.Event()
    exc_holder: Dict[str, Optional[Exception]] = {"exc": None}

    async def receive() -> Dict[str, Any]:
        return await recv_q.get()

    async def send(message: Dict[str, Any]):
        t = message.get("type")
        if t == "lifespan.startup.complete":
            started.set()
        elif t == "lifespan.startup.failed":
            exc_holder["exc"] = RuntimeError("lifespan.startup.failed: %r" % message.get("message"))
            started.set()
        elif t == "lifespan.shutdown.complete":
            stopped.set()
        elif t == "lifespan.shutdown.failed":
            exc_holder["exc"] = RuntimeError("lifespan.shutdown.failed: %r" % message.get("message"))
            stopped.set()
        else:
            logger.debug("Lifespan send unknown message: %r", message)

    task = asyncio.create_task(app({"type": "lifespan"}, receive, send))
    recv_q.put_nowait({"type": "lifespan.startup"})

    try:
        await asyncio.wait_for(started.wait(), timeout=timeout)
        logger.info("Lifespan: startup signalled")
    except asyncio.TimeoutError:
        logger.warning("Lifespan startup did not complete within %s seconds; continuing (app may be non-conformant).", timeout)
    except asyncio.CancelledError:
        raise

    if exc_holder["exc"]:
        logger.exception("Lifespan reported an exception during startup: %r", exc_holder["exc"])

    class LifespanCtx:
        async def shutdown(self, timeout_shutdown: float = 5.0):
            try:
                recv_q.put_nowait({"type": "lifespan.shutdown"})
                try:
                    await asyncio.wait_for(stopped.wait(), timeout=timeout_shutdown)
                except asyncio.TimeoutError:
                    logger.warning("Lifespan shutdown did not complete within %s seconds", timeout_shutdown)
            except Exception:
                logger.exception("Exception while requesting lifespan shutdown")
            finally:
                try:
                    task.cancel()
                except Exception:
                    pass
                try:
                    await asyncio.wait_for(task, timeout=1.0)
                except Exception:
                    pass
    return LifespanCtx()

# ----------------------------
# HTTP utilities
# ----------------------------
def http_status_text(status: int) -> str:
    return {
        # 1xx Informational
        100: "Continue",
        101: "Switching Protocols",
        102: "Processing",
        103: "Early Hints",

        # 2xx Success
        200: "OK",
        201: "Created",
        202: "Accepted",
        203: "Non-Authoritative Information",
        204: "No Content",
        205: "Reset Content",
        206: "Partial Content",
        207: "Multi-Status",
        208: "Already Reported",
        226: "IM Used",

        # 3xx Redirection
        300: "Multiple Choices",
        301: "Moved Permanently",
        302: "Found",
        303: "See Other",
        304: "Not Modified",
        305: "Use Proxy",
        306: "(Unused)",
        307: "Temporary Redirect",
        308: "Permanent Redirect",

        # 4xx Client Error
        400: "Bad Request",
        401: "Unauthorized",
        402: "Payment Required",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        406: "Not Acceptable",
        407: "Proxy Authentication Required",
        408: "Request Timeout",
        409: "Conflict",
        410: "Gone",
        411: "Length Required",
        412: "Precondition Failed",
        413: "Payload Too Large",
        414: "URI Too Long",
        415: "Unsupported Media Type",
        416: "Range Not Satisfiable",
        417: "Expectation Failed",
        418: "I'm a teapot",
        421: "Misdirected Request",
        422: "Unprocessable Entity",
        423: "Locked",
        424: "Failed Dependency",
        425: "Too Early",
        426: "Upgrade Required",
        428: "Precondition Required",
        429: "Too Many Requests",
        431: "Request Header Fields Too Large",
        451: "Unavailable For Legal Reasons",

        # 5xx Server Error
        500: "Internal Server Error",
        501: "Not Implemented",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout",
        505: "HTTP Version Not Supported",
        506: "Variant Also Negotiates",
        507: "Insufficient Storage",
        508: "Loop Detected",
        510: "Not Extended",
        511: "Network Authentication Required"}.get(status, "Unknown")

class ASGIH11Request:
    def __init__(self, scope: Dict[str, Any], transport: asyncio.Transport, safe_headers: bool, bind_domain: str):
        self.scope = scope
        self.transport = transport
        self.safe_headers = safe_headers
        self.bind_domain = bind_domain
        self.recv_q: asyncio.Queue = asyncio.Queue()
        self.send_q: asyncio.Queue = asyncio.Queue()
        self.done = asyncio.Event()
        self.task: Optional[asyncio.Task] = None

    async def asgi_receive(self) -> Dict[str, Any]:
        return await self.recv_q.get()

    async def asgi_send(self, message: Dict[str, Any]):
        self.send_q.put_nowait(message)

    async def run_app(self, app: Callable):
        try:
            await app(self.scope, self.asgi_receive, self.asgi_send)
        except Exception:
            logger.exception("Exception in ASGI app (http/1.1)")
            try:
                self.send_q.put_nowait({"type": "http.response.start", "status": 500, "headers": []})
                self.send_q.put_nowait({"type": "http.response.body", "body": b"Internal Server Error", "more_body": False})
            except Exception:
                logger.exception("Failed to queue 500 response")
        finally:
            self.done.set()

class ChunkedDecoder:
    def __init__(self):
        self.buffer = bytearray()
        self.chunk_length = None
        self.state = 'length'  # 'length', 'data', 'trailer'

    def decode(self, data: bytes) -> Tuple[List[bytes], bool]:
        self.buffer.extend(data)
        chunks = []
        finished = False

        while self.buffer:
            if self.state == 'length':
                idx = self.buffer.find(b'\r\n')
                if idx == -1:
                    break
                line = self.buffer[:idx].decode('latin-1')
                del self.buffer[:idx + 2]
                try:
                    self.chunk_length = int(line.split(';', 1)[0].strip(), 16)
                except Exception as e:
                    raise ValueError(f"Invalid chunk length: {line}") from e

                if self.chunk_length == 0:
                    self.state = 'trailer'
                else:
                    self.state = 'data'

            elif self.state == 'data':
                if len(self.buffer) < self.chunk_length + 2:
                    break
                chunks.append(self.buffer[:self.chunk_length])
                del self.buffer[:self.chunk_length + 2]
                self.chunk_length = None
                self.state = 'length'

            elif self.state == 'trailer':
                idx = self.buffer.find(b'\r\n')
                if idx == -1:
                    break
                del self.buffer[:idx + 2]
                finished = True
                break

        return chunks, finished

class H11ProtocolHandler:
    def __init__(self, app: Callable, transport: asyncio.Transport, peername, server_addr, ssl_object, compression_enabled: bool = False, safe_headers: bool = False, bind_domain: str = ""):
        self.app = app
        self.transport = transport
        self.peername = peername
        self.server_addr = server_addr
        self.ssl_object = ssl_object
        self.safe_headers = safe_headers
        self.bind_domain = bind_domain
        self.buffer = bytearray()
        self._parsing = False
        self._closed = False
        self.compression_enabled = compression_enabled
        self.current_request: Optional[ASGIH11Request] = None
        self.chunked_decoder = None
        self.content_length_remaining = None
        self.reading_body = False
        self.chunked = False

    def connection_made(self):
        pass

    def data_received(self, data: bytes):
        self.buffer.extend(data)
        if not self._parsing:
            asyncio.create_task(self._parse_loop())

    async def _parse_loop(self):
        self._parsing = True
        try:
            while self.buffer and not self._closed:
                if not self.reading_body:
                    if len(self.buffer) > H_MAX_HEADER_SIZE:
                        self.transport.write(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                        self._close()
                        return

                    idx = self.buffer.find(b"\r\n\r\n")
                    if idx == -1:
                        break

                    lines = self.buffer[:idx].split(b"\r\n")
                    if not lines:
                        self._close()
                        return

                    parts = lines[0].decode("latin-1").split()
                    if len(parts) < 3:
                        self._close()
                        return

                    method = parts[0].upper()
                    if method not in ALLOWED_METHODS:
                        self.transport.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                        self._close()
                        return

                    raw_path = parts[1]
                    headers: List[Tuple[bytes, bytes]] = []
                    content_length = 0
                    transfer_encoding = ""
                    host = ""

                    for h in lines[1:]:
                        if b": " in h:
                            name, value = h.split(b": ", 1)
                            headers.append((name, value))
                            name = name.lower()
                            if name == b"content-length":
                                try:
                                    content_length = int(value.decode("latin-1"))
                                except ValueError:
                                    pass
                            elif name == b"transfer-encoding":
                                transfer_encoding = value.decode("latin-1").lower()
                            elif name == b"host":
                                host = value.decode("latin-1").lower()

                    if self.bind_domain and host != self.bind_domain:
                        self.transport.write(b"HTTP/1.1 421 Misdirected Request\r\n\r\n")
                        self._close()
                        return

                    path, _, query = raw_path.partition("?")
                    scope = {
                        "type": "http",
                        "http_version": parts[2].split("/")[-1],
                        "asgi": {"version": "3.0"},
                        "method": method,
                        "scheme": "https" if self.ssl_object else "http",
                        "path": path,
                        "raw_path": raw_path.encode("utf-8"),
                        "query_string": query.encode("latin-1"),
                        "headers": headers,
                        "client": self.peername,
                        "server": self.server_addr}

                    self.current_request = ASGIH11Request(scope, self.transport, self.safe_headers, self.bind_domain)
                    self.current_request.task = asyncio.create_task(self.current_request.run_app(self.app))
                    self.chunked = transfer_encoding == "chunked"

                    if self.chunked:
                        self.chunked_decoder = ChunkedDecoder()
                        self.reading_body = True
                        self.current_request.recv_q.put_nowait({
                            "type": "http.request",
                            "body": b"",
                            "more_body": True})

                        del self.buffer[:idx + 4]
                        if self.buffer:
                            await self._process_body_data()

                    elif content_length > 0:
                        self.content_length_remaining = content_length
                        self.reading_body = True
                        self.current_request.recv_q.put_nowait({
                            "type": "http.request",
                            "body": b"",
                            "more_body": True})

                        del self.buffer[:idx + 4]
                        if self.buffer:
                            await self._process_body_data()
                    else:
                        self.current_request.recv_q.put_nowait({
                            "type": "http.request",
                            "body": b"",
                            "more_body": False})

                        del self.buffer[:idx + 4]
                        asyncio.create_task(self._http1_writer_loop(self.current_request))
                        self.current_request = None
                else:
                    await self._process_body_data()
                    break
        except Exception as e:
            logger.exception("Error in parse loop: %s", e)
            self._close()
        finally:
            self._parsing = False

    async def _process_body_data(self):
        if not self.current_request or not self.buffer:
            return

        try:
            if self.chunked and self.chunked_decoder:
                original_length = len(self.buffer)
                chunks, finished = self.chunked_decoder.decode(self.buffer)
                del self.buffer[:original_length - len(self.chunked_decoder.buffer)]
                for chunk in chunks:
                    if chunk:
                        self.current_request.recv_q.put_nowait({
                            "type": "http.request",
                            "body": chunk,
                            "more_body": True})

                if finished:
                    self.current_request.recv_q.put_nowait({
                        "type": "http.request",
                        "body": b"",
                        "more_body": False})

                    asyncio.create_task(self._http1_writer_loop(self.current_request))
                    self.current_request = None
                    self.reading_body = False
                    self.chunked_decoder = None
            elif self.content_length_remaining is not None:
                chunk_size = min(len(self.buffer), self.content_length_remaining)
                if chunk_size > 0:
                    self.current_request.recv_q.put_nowait({
                        "type": "http.request",
                        "body": self.buffer[:chunk_size],
                        "more_body": self.content_length_remaining > 0
                    })
                    del self.buffer[:chunk_size]
                    self.content_length_remaining -= chunk_size
                if self.content_length_remaining <= 0:
                    asyncio.create_task(self._http1_writer_loop(self.current_request))
                    self.current_request = None
                    self.reading_body = False
                    self.content_length_remaining = None
        except Exception as e:
            logger.exception("Error processing body data: %s", e)
            self.buffer.clear()
            self._close()

    def _build_http1_headers(self, status: int, headers: List[Tuple[bytes, bytes]], default_keep_alive: bool) -> bytearray:
        header_lines = bytearray(f"HTTP/1.1 {status} {http_status_text(status)}\r\ndate: {datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')}\r\nserver: {SERVER_NAME}\r\n".encode("latin-1"))
        response_conn_hdr = ""

        for name, value in headers:
            header_lines.extend(name + b": " + value + b"\r\n")
            if name.lower() == b"connection":
                response_conn_hdr = value.decode("latin-1").lower()

        if self.safe_headers:
            header_lines.extend(b"strict-transport-security: max-age=31536000; includeSubDomains; preload\r\ncross-origin-opener-policy: same-origin\r\ncross-origin-embedder-policy: require-corp\r\ncross-origin-resource-policy: same-origin\r\nx-frame-options: SAMEORIGIN\r\nx-xss-protection: 1; mode=block\r\nx-content-type-options: nosniff\r\nreferrer-policy: strict-origin-when-cross-origin\r\npermissions-policy: geolocation=(), camera=(), microphone=()\r\n")
        if not response_conn_hdr:
            if default_keep_alive:
                header_lines.extend(b"Connection: keep-alive\r\n")
            else:
                header_lines.extend(b"Connection: close\r\n")

        header_lines.extend(b"\r\n")
        return header_lines

    async def _http1_writer_loop(self, req: ASGIH11Request):
        conn_hdr = (next((v for k, v in req.scope.get("headers", []) if k.lower() == b"connection"), b"")).lower()
        default_keep_alive = True if str(req.scope.get("http_version", "1.1")).startswith("1.1") else False
        if conn_hdr:
            if b"close" in conn_hdr:
                default_keep_alive = False
            elif b"keep-alive" in conn_hdr:
                default_keep_alive = True

        try:
            headers_sent = False
            first_body = True
            compressor = None
            accept_encoding = None
            use_chunked_encoding = False
            headers = []

            while True:
                try:
                    msg = await asyncio.wait_for(req.send_q.get(), timeout=10.0)
                except asyncio.TimeoutError:
                    logger.warning("App did not respond in time for request %s", req.scope.get("path"))
                    break

                t = msg.get("type")
                if t == "http.response.start":
                    status = msg.get("status", 200)
                    headers = msg.get("headers", [])

                    if self.compression_enabled and _is_text_based_response(headers):
                        accept_encoding = _find_accept_encoding(req.scope.get("headers", []))
                        if accept_encoding in ('gzip', 'deflate'):
                            compressor = StreamingCompressor(accept_encoding)

                    has_content_length = any(name.lower() == b"content-length" for name, value in headers)
                    has_more_body = any(
                        future_msg.get("type") == "http.response.body" and
                        future_msg.get("more_body", False)
                        for future_msg in req.send_q._queue)

                    use_chunked_encoding = has_more_body or not has_content_length
                    if use_chunked_encoding and not any(name.lower() == b"transfer-encoding" for name, value in headers):
                        headers = [(name, value) for name, value in headers if name.lower() != b"content-length"]
                        headers.append((b"transfer-encoding", b"chunked"))

                    if compressor is not None:
                        headers = [(name, value) for name, value in headers if name.lower() != b"content-length"]
                        headers.append((b"content-encoding", accept_encoding.encode("latin-1")))

                    try:
                        self.transport.write(self._build_http1_headers(status, headers, default_keep_alive))
                        headers_sent = True
                    except Exception as e:
                        logger.exception("Failed to write headers: %s", e)
                        break

                elif t == "http.response.body":
                    body = msg.get("body", b"")
                    more = msg.get("more_body", False)

                    if not headers_sent:
                        logger.warning("Received body before headers")
                        break

                    try:
                        if compressor is not None:
                            if body:
                                body = await compressor.compress(body)
                                if body:
                                    if use_chunked_encoding:
                                        self.transport.write(format(len(body), 'x').encode('latin-1') + b"\r\n" + body + b"\r\n")
                                    else:
                                        self.transport.write(body)

                            if not more:
                                final_data = await compressor.flush()
                                if final_data:
                                    if use_chunked_encoding:
                                        self.transport.write(format(len(final_data), 'x').encode('latin-1') + b"\r\n" + final_data + b"\r\n0\r\n\r\n")
                                    else:
                                        self.transport.write(final_data)
                                elif use_chunked_encoding:
                                    self.transport.write(b"0\r\n\r\n")
                        else:
                            if use_chunked_encoding:
                                if body:
                                    self.transport.write(format(len(body), 'x').encode('latin-1') + b"\r\n" + body + b"\r\n")
                                if not more:
                                    self.transport.write(b"0\r\n\r\n")
                            else:
                                if body:
                                    self.transport.write(body)
                    except Exception as e:
                        logger.exception("Failed to write body: %s", e)
                        break

                    if not more:
                        break

        except Exception as e:
            logger.exception("Writer loop exception: %s", e)
        finally:
            if not default_keep_alive:
                self._close()

    def _close(self):
        if not self._closed:
            try:
                self.transport.close()
            except Exception:
                pass
            self._closed = True
            self.buffer.clear()

    def connection_lost(self, exc):
        self._closed = True

class H2ProtocolHandler:
    def __init__(self, app: Callable, transport: asyncio.Transport, peername, server_addr, ssl_object, compression_enabled: bool = False, safe_headers: bool = False, bind_domain: str = ""):
        self.app = app
        self.transport = transport
        self.peername = peername
        self.server_addr = server_addr
        self.ssl_object = ssl_object
        self.safe_headers = safe_headers
        self.bind_domain = bind_domain
        self.conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
        self.streams: Dict[int, Dict[str, Any]] = {}
        self._closed = False
        self.compression_enabled = compression_enabled

    def connection_made(self):
        try:
            self.conn.initiate_connection()
            data = self.conn.data_to_send()
            if data:
                self.transport.write(data)
        except Exception:
            logger.exception("Error initiating h2 connection")

    def data_received(self, data: bytes):
        if self._closed:
            return
        try:
            events = self.conn.receive_data(data)
            for ev in events:
                asyncio.create_task(self.handle_event(ev))
        except Exception:
            logger.exception("h2 receive/parse error")
            self._closed = True
            try:
                self.transport.close()
            except Exception:
                pass

    async def handle_event(self, ev):
        try:
            if isinstance(ev, h2.events.RequestReceived):
                await self.start_request(ev.stream_id, ev.headers)
            elif isinstance(ev, h2.events.DataReceived):
                await self.data_received_stream(ev.stream_id, ev.data, ev.flow_controlled_length)
            elif isinstance(ev, h2.events.StreamEnded):
                await self.stream_ended(ev.stream_id)
            elif isinstance(ev, h2.events.ConnectionTerminated):
                self._closed = True
        except Exception:
            logger.exception("Exception handling h2 event")
        finally:
            data = self.conn.data_to_send()
            if data:
                self.transport.write(data)

    async def start_request(self, stream_id: int, headers):
        if sum(len(name) + len(value) for name, value in headers) > H_MAX_HEADER_SIZE:
            self.conn.send_headers(stream_id, [(":status", "431")], end_stream=True)
            return

        raw_path = "/"
        method = "GET"
        scheme = "https" if self.ssl_object else "http"
        host = ""

        header_list: List[Tuple[bytes, bytes]] = []
        for name, value in headers:
            if name == b":path":
                raw_path = value.decode("latin-1")
            elif name == b":method":
                method = value.decode("latin-1")
                if method.upper() not in ALLOWED_METHODS:
                    self.conn.send_headers(stream_id, [(":status", "405")], end_stream=True)
                    return
            elif name == b":scheme":
                scheme = value.decode("latin-1")
            elif name == b":authority":
                host = value.decode("latin-1").lower()
            else:
                if not name.startswith(b":"):
                    header_list.append((name, value))

        if self.bind_domain and host != self.bind_domain:
            try:
                self.conn.send_headers(stream_id, [(":status", "421")], end_stream=True)
            except Exception as e:
                logger.debug("Failed to send 421 for stream %d: %s", stream_id, e)
            return

        path, _, query = raw_path.partition("?")
        scope = {
            "type": "http",
            "http_version": "2",
            "asgi": {"version": "3.0"},
            "method": method,
            "scheme": scheme,
            "path": path,
            "raw_path": raw_path.encode("utf-8"),
            "query_string": query.encode("latin-1"),
            "headers": header_list,
            "client": self.peername,
            "server": self.server_addr}

        recv_q: asyncio.Queue = asyncio.Queue()
        send_q: asyncio.Queue = asyncio.Queue()
        recv_q.put_nowait({"type": "http.request", "body": b"", "more_body": True})
        self.streams[stream_id] = {"recv": recv_q, "send": send_q}
        asyncio.create_task(self._run_app_for_stream(stream_id, scope, recv_q, send_q))

    async def data_received_stream(self, stream_id: int, data: bytes, flow_len: int):
        s = self.streams.get(stream_id)
        if not s:
            return
        s["recv"].put_nowait({"type": "http.request", "body": data, "more_body": True})
        try:
            self.conn.increment_flow_control_window(flow_len)
        except Exception:
            pass

    async def stream_ended(self, stream_id: int):
        s = self.streams.get(stream_id)
        if not s:
            return
        s["recv"].put_nowait({"type": "http.request", "body": b"", "more_body": False})

    def _send_data_in_frames(self, stream_id: int, data: bytes, end_stream: bool = False):
        if not data:
            if end_stream:
                self.conn.send_data(stream_id, b'', end_stream=True)
            return

        for i in range(0, len(data), H2_MAX_FRAME_SIZE):
            try:
                self.conn.send_data(stream_id, data[i:i + H2_MAX_FRAME_SIZE], end_stream=end_stream and (i + H2_MAX_FRAME_SIZE >= len(data)))
            except Exception as e:
                logger.exception("Failed to send H2 data chunk: %s", e)
                break

    async def _run_app_for_stream(self, stream_id: int, scope, recv_q: asyncio.Queue, send_q: asyncio.Queue):
        async def asgi_receive():
            return await recv_q.get()

        async def asgi_send(message: Dict[str, Any]):
            send_q.put_nowait(message)

        try:
            await self.app(scope, asgi_receive, asgi_send)
        except Exception:
            logger.exception("Exception in ASGI app (h2 stream)")
            try:
                self.conn.send_headers(stream_id, [(":status", "500")], end_stream=True)
                data = self.conn.data_to_send()
                if data:
                    self.transport.write(data)
            except Exception:
                logger.exception("Failed to send 500 over h2")
            return

        compressor = None
        headers_sent = False
        accept_encoding = None

        while True:
            try:
                msg = await asyncio.wait_for(send_q.get(), timeout=10.0)
            except asyncio.TimeoutError:
                break

            t = msg.get("type")
            if t == "http.response.start":
                headers = msg.get("headers", [])
                status = msg.get("status", 200)

                header_lines = [(":status", str(status)), ("date", datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')), ("server", SERVER_NAME)]
                if self.compression_enabled and _is_text_based_response([(n, v) for n, v in headers]):
                    accept_encoding = _find_accept_encoding(scope.get("headers", []))
                    if accept_encoding in ('gzip', 'deflate'):
                        compressor = StreamingCompressor(accept_encoding)
                        headers = [(n, v) for n, v in headers if n.lower() != b"content-length"]
                        header_lines.append(("content-encoding", accept_encoding))

                for name, value in headers:
                    header_lines.append((name.decode("latin-1"), value.decode("latin-1")))

                if self.safe_headers:
                    header_lines.append(("strict-transport-security", "max-age=31536000; includeSubDomains; preload"))
                    header_lines.append(("cross-origin-opener-policy", "same-origin"))
                    header_lines.append(("cross-origin-embedder-policy", "require-corp"))
                    header_lines.append(("cross-origin-resource-policy", "same-origin"))
                    header_lines.append(("x-frame-options", "SAMEORIGIN"))
                    header_lines.append(("x-xss-protection", "1; mode=block"))
                    header_lines.append(("x-content-type-options", "nosniff"))
                    header_lines.append(("referrer-policy", "strict-origin-when-cross-origin"))
                    header_lines.append(("permissions-policy", "geolocation=(), camera=(), microphone=()"))

                try:
                    self.conn.send_headers(stream_id, header_lines)
                    headers_sent = True
                except Exception as e:
                    logger.exception("Failed to send H2 headers: %s", e)

            elif t == "http.response.body":
                body = msg.get("body", b"")
                more = msg.get("more_body", False)

                if not headers_sent:
                    logger.warning("Received body before headers for stream %d", stream_id)
                    try:
                        self.conn.send_headers(stream_id, [(":status", "500")], end_stream=True)
                    except:
                        pass
                    break

                try:
                    if compressor:
                        if body:
                            body = await compressor.compress(body)
                            if body:
                                self._send_data_in_frames(stream_id, body, end_stream=False)
                        if not more:
                            self._send_data_in_frames(stream_id, await compressor.flush(), end_stream=True)
                    else:
                        self._send_data_in_frames(stream_id, body, end_stream=not more)
                except Exception as e:
                    logger.exception("Failed to send H2 data: %s", e)
                    break

            else:
                logger.debug("H2 unknown send msg: %r", msg)

            data_to_send = self.conn.data_to_send()
            if data_to_send:
                try:
                    self.transport.write(data_to_send)
                except Exception as e:
                    logger.exception("Failed to write h2 data to transport: %s", e)

        if not self._closed:
            data_to_send = self.conn.data_to_send()
            if data_to_send:
                try:
                    self.transport.write(data_to_send)
                except Exception as e:
                    logger.exception("Failed to write final h2 data to transport: %s", e)


class ConnectionProtocolFactory:
    def __init__(self, app: Callable, ssl_context: Optional[ssl.SSLContext], compression_enabled: bool = False, safe_headers: bool = False, bind_domain: str = ""):
        self.app = app
        self.ssl_context = ssl_context
        self.compression_enabled = compression_enabled
        self.safe_headers = safe_headers
        self.bind_domain = bind_domain

    def __call__(self):
        return _ConnectionProtocol(self.app, self.ssl_context, self.compression_enabled, self.safe_headers, self.bind_domain)

class _ConnectionProtocol(asyncio.Protocol):
    def __init__(self, app: Callable, ssl_context: Optional[ssl.SSLContext], compression_enabled: bool = False, safe_headers: bool = False, bind_domain: str = ""):
        self.app = app
        self.ssl_context = ssl_context
        self.transport: Optional[asyncio.Transport] = None
        self.peername = None
        self.server_addr = None
        self._handler = None
        self.compression_enabled = compression_enabled
        self.safe_headers = safe_headers
        self.bind_domain = bind_domain

    def connection_made(self, transport: asyncio.Transport):
        self.transport = transport
        sock = transport.get_extra_info("socket")
        self.peername = transport.get_extra_info("peername")
        try:
            self.server_addr = sock.getsockname() if sock is not None else None
        except Exception:
            self.server_addr = None

        ssl_object = transport.get_extra_info("ssl_object")
        negotiated = None
        try:
            negotiated = ssl_object.selected_alpn_protocol() if ssl_object is not None else None
        except Exception:
            pass

        if negotiated == "h2" and H2_AVAILABLE:
            self._handler = H2ProtocolHandler(self.app, transport, self.peername, self.server_addr, ssl_object, compression_enabled=self.compression_enabled, safe_headers=self.safe_headers, bind_domain=self.bind_domain)
        else:
            self._handler = H11ProtocolHandler(self.app, transport, self.peername, self.server_addr, ssl_object, compression_enabled=self.compression_enabled, safe_headers=self.safe_headers, bind_domain=self.bind_domain)

        try:
            self._handler.connection_made()
        except Exception:
            logger.exception("Handler connection_made exception")

    def data_received(self, data: bytes):
        if self._handler:
            try:
                self._handler.data_received(data)
            except Exception:
                logger.exception("Handler data_received exception")

    def eof_received(self):
        if self._handler and hasattr(self._handler, "eof_received"):
            try:
                self._handler.eof_received()
            except Exception:
                logger.exception("Handler eof_received exception")
        return False

    def connection_lost(self, exc):
        if self._handler and hasattr(self._handler, "connection_lost"):
            try:
                self._handler.connection_lost(exc)
            except Exception:
                logger.exception("Handler connection_lost exception")

class ASGIServer:
    def __init__(self, app: Callable, host: str = "", port: int = 8000, certfile: Optional[str] = None, keyfile: Optional[str] = None, workers: int = 1, compression: bool = False, safe_headers: bool = False, bind_domain: str = ""):
        self.app = app
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.workers = max(1, min(workers, (os.cpu_count() or 1) - 1))
        self.compression = compression
        self.safe_headers = safe_headers
        self.bind_domain = bind_domain
        self.ssl_context = self._create_ssl_context(certfile, keyfile) if certfile and keyfile else None

    def _create_ssl_context(self, certfile: str, keyfile: str) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        if hasattr(ssl, "OP_NO_COMPRESSION"):
            context.options |= ssl.OP_NO_COMPRESSION
        if hasattr(ssl, "OP_NO_RENEGOTIATION"):
            context.options |= ssl.OP_NO_RENEGOTIATION
        try:
            context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
        except Exception:
            logger.warning("Failed to set ciphers; platform may not support requested list")
        if hasattr(ssl, "TLSVersion"):
            try:
                context.minimum_version = ssl.TLSVersion.TLSv1_2
            except Exception:
                pass
        try:
            if H2_AVAILABLE:
                context.set_alpn_protocols(["h2", "http/1.1"])
            else:
                context.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass
        return context

    def _create_listen_socket(self) -> socket.socket:
        if not self.host:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 131072)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self.workers > 1 and hasattr(socket, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    logger.info("SO_REUSEPORT set (workers=%d)", self.workers)
                except Exception:
                    logger.exception("Failed to set SO_REUSEPORT")

            if hasattr(socket, "TCP_NODELAY"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if hasattr(socket, "TCP_QUICKACK"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
        except:
            pass

        sock.bind((self.host, self.port))
        sock.listen(1024)
        sock.setblocking(False)
        return sock

    async def serve(self):
        loop = asyncio.get_running_loop()
        sock = self._create_listen_socket()

        server = await loop.create_server(
            ConnectionProtocolFactory(self.app, self.ssl_context, compression_enabled=self.compression, safe_headers=self.safe_headers, bind_domain=self.bind_domain),
            sock=sock,
            ssl=self.ssl_context)

        logger.info("Serving on %s (ssl=%s, workers=%d, compression=%s, safe_headers=%s, bind_domain=%s)", ", ".join(str(s.getsockname()) for s in server.sockets), bool(self.ssl_context), self.workers, self.compression, self.safe_headers, self.bind_domain)

        lifespan_ctx = None
        try:
            lifespan_ctx = await run_lifespan(self.app)
        except Exception:
            logger.exception("Lifespan startup failed (exception) -- continuing to serve (app may initialize lazily)")

        try:
            await server.serve_forever()
        finally:
            if lifespan_ctx is not None:
                try:
                    await lifespan_ctx.shutdown()
                except Exception:
                    logger.exception("Lifespan shutdown failed")

def _run_worker_process(args):
    if uvloop is not None:
        runner = asyncio.Runner(loop_factory=uvloop.new_event_loop)
    else:
        runner = asyncio.Runner()

    try:
        runner.run(ASGIServer(import_app(args.app), host=args.host, port=args.port, certfile=args.certfile, keyfile=args.keyfile, workers=args.workers, compression=args.compression, safe_headers=args.safe_headers, bind_domain=args.domain).serve())
    except KeyboardInterrupt:
        logger.info("Worker pid=%d stopped", os.getpid())
    finally:
        try:
            runner.close()
        except Exception:
            pass

def spawn_workers(args):
    procs: List[Process] = []
    for i in range(args.workers):
        p = Process(target=_run_worker_process, args=(args,), daemon=False)
        p.start()
        logger.info("Started worker pid=%d", p.pid)
        procs.append(p)
    try:
        for p in procs:
            p.join()
    except KeyboardInterrupt:
        logger.info("Stopping workers")
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass

def main():
    parser = argparse.ArgumentParser(prog="echocorn", description="ASGI server implemented with asyncio.Protocol")
    parser.add_argument("--app", type=str, required=True, help="ASGI app module:callable")
    parser.add_argument("--host", type=str, default="")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--about", action="store_true", help="Shows echocorn version and author")
    parser.add_argument("--domain", type=str, default="", help="Allows request only if Host in headers matches")
    parser.add_argument("--certfile", help="TLS cert file")
    parser.add_argument("--keyfile", help="TLS key file")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--safe-headers", action="store_true", help="Add some http security headers")
    parser.add_argument("--compression", action="store_true", help="Allows response compression using gzip or deflate (based on client's Accept-Encoding).")
    args = parser.parse_args()

    if args.about:
        print(f"Version: {version}")
        print(f"Author: {author}")
        sys.exit(1)

    if (args.certfile and not args.keyfile) or (args.keyfile and not args.certfile):
        parser.error("--certfile and --keyfile must be provided together")

    if args.workers > 1 and not hasattr(socket, "SO_REUSEPORT"):
        logger.warning("workers > 1 requested but SO_REUSEPORT not available on this platform; multiple workers may fail to bind")

    if uvloop is not None and args.workers <= 1:
        try:
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        except Exception:
            pass

    if args.workers > 1:
        spawn_workers(args)
    else:
        if uvloop is not None:
            runner = asyncio.Runner(loop_factory=uvloop.new_event_loop)
        else:
            runner = asyncio.Runner()

        try:
            runner.run(ASGIServer(import_app(args.app), host=args.host, port=args.port, certfile=args.certfile, keyfile=args.keyfile, workers=args.workers, compression=args.compression, safe_headers=args.safe_headers, bind_domain=args.domain).serve())
        except KeyboardInterrupt:
            logger.info("Stopped by KeyboardInterrupt")
        finally:
            try:
                runner.close()
            except Exception:
                pass
