"""HTTP/2 protocol handler built on hyper-h2 (RFC 9113).

Why this module looks the way it does
-------------------------------------
``h2`` is a synchronous state machine that must be driven from exactly one
place at a time.  Two rules are therefore enforced here:

1. **All** ``h2`` calls happen on the event loop thread and never interleave
   with an ``await`` in the middle of a state transition.  ``data_received``
   feeds the connection and dispatches every event synchronously, in order.
2. Outbound DATA respects the peer's flow control window.  ``h2.send_data``
   raises :class:`h2.exceptions.FlowControlError` if more than
   ``local_flow_control_window()`` bytes are pushed, so the writer waits for
   ``WindowUpdated`` events before continuing.  This is the main reason the
   previous implementation failed on responses larger than 64 KiB.

Inbound DATA is acknowledged lazily, when the application actually reads it.
That gives real end-to-end backpressure: the receive window closes while the
app is busy instead of buffering unbounded amounts of memory.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions
import h2.settings

from . import utils
from .config import ServerConfig
from .http1 import CONNECTION_PREFACE
from .utils import ASGIRequest, Compressor, Headers

__all__ = ["HTTP2Handler", "CONNECTION_PREFACE"]

ALLOWED_METHODS = utils.ALLOWED_METHODS


class _H2Stream:
    __slots__ = (
        "stream_id",
        "request",
        "closed",
        "request_ended",
        "response_complete",
        "writer_task",
        "unacked",
        "deadline",
        "received",
    )

    def __init__(self, stream_id: int, request: ASGIRequest) -> None:
        self.stream_id = stream_id
        self.request = request
        self.closed = False
        self.request_ended = False
        self.response_complete = False
        self.writer_task: Optional[asyncio.Task] = None
        self.unacked = 0
        self.deadline: Optional[float] = None
        self.received = 0


class HTTP2Handler:
    """Protocol handler for a single HTTP/2 connection."""

    def __init__(
        self,
        app: Callable,
        config: ServerConfig,
        transport: asyncio.Transport,
        peername: Any,
        server_addr: Any,
        ssl_object: Any,
        logger: logging.Logger,
        on_close: Optional[Callable[[], None]] = None,
    ) -> None:
        self.app = app
        self.config = config
        self.transport = transport
        self.peername = peername
        self.server_addr = server_addr
        self.ssl_object = ssl_object
        self.logger = logger
        self.access_logger = logging.getLogger("echocorn.access")
        self._on_close = on_close

        self.conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(
                client_side=False,
                header_encoding=None,
                validate_inbound_headers=True,
                normalize_inbound_headers=True,
                validate_outbound_headers=True,
                normalize_outbound_headers=True,
            )
        )
        self.conn.decoder.max_header_list_size = config.h2_max_header_list_size

        self.streams: Dict[int, _H2Stream] = {}
        self._closed = False
        self._window_event = asyncio.Event()
        self._write_paused = False
        self._resume_event = asyncio.Event()
        self._resume_event.set()
        self._last_activity = time.monotonic()
        self._connected_at = self._last_activity
        self._requests_completed = 0
        self._streams_opened = 0
        self._goaway_received = False
        self._watchdog_task: Optional[asyncio.Task] = None

    # asyncio protocol callbacks.
    def connection_made(self) -> None:
        try:
            self.transport.set_write_buffer_limits(high=256 * 1024, low=64 * 1024)
        except (AttributeError, NotImplementedError):
            pass
        # The request clock starts with the connection, so a peer that opens a
        # TLS session and never finishes a request cannot hold resources.
        self._watchdog_task = asyncio.ensure_future(self._watchdog())
        try:
            self.conn.initiate_connection()
            self._apply_local_settings()
            self._flush()
        except Exception:
            self.logger.exception("failed to initialise h20 connection")
            self._close()

    def data_received(self, data: bytes) -> None:
        if self._closed:
            return
        self._last_activity = time.monotonic()
        try:
            events = self.conn.receive_data(data)
        except h2.exceptions.ProtocolError as exc:
            # h2 has already queued the appropriate GOAWAY frame.
            self.logger.warning("h20 protocol error: %s", exc)
            self._flush()
            self._close()
            return
        except Exception:
            self.logger.exception("Fatal error while parsing h20 data")
            self._close()
            return
        for event in events:
            self._handle_event(event)
        self._flush()

    def eof_received(self) -> bool:
        self._close()
        return False

    def pause_writing(self) -> None:
        self._write_paused = True
        self._resume_event.clear()

    def resume_writing(self) -> None:
        self._write_paused = False
        self._resume_event.set()

    def connection_lost(self, exc: Optional[BaseException]) -> None:
        self._closed = True
        for stream in list(self.streams.values()):
            stream.request.notify_disconnect()
        self._cancel_all()
        self._release()

    def is_idle(self) -> bool:
        """True when the connection has no stream in flight."""
        return not self.streams

    def shutdown(self) -> None:
        if self._closed:
            return
        try:
            self.conn.close_connection()
            self._flush()
        except Exception:
            pass
        self._close()

    # internals
    def _apply_local_settings(self) -> None:
        settings = {
            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: self.config.h2_initial_window_size,
            h2.settings.SettingCodes.MAX_FRAME_SIZE: self.config.h2_max_frame_size,
            h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE: self.config.h2_max_header_list_size,
        }
        if self.config.h2_max_concurrent_streams:
            settings[h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS] = self.config.h2_max_concurrent_streams
        self.conn.update_settings(settings)

    def _release(self) -> None:
        if self._on_close is not None:
            callback, self._on_close = self._on_close, None
            callback()

    def _cancel_all(self) -> None:
        current = asyncio.current_task()
        for stream in list(self.streams.values()):
            for task in (stream.request.app_task, stream.writer_task):
                if task is not None and task is not current and not task.done():
                    task.cancel()
        self.streams.clear()
        watchdog = self._watchdog_task
        if watchdog is not None and watchdog is not current and not watchdog.done():
            watchdog.cancel()

    async def _watchdog(self) -> None:
        """
        Enforce the idle and request deadlines of an HTTP/2 connection.

        HTTP/2 has no per-message timeout of its own, so without this a client
        could open one connection and trickle frames forever. Idle connections
        are closed with GOAWAY; connections that stalled mid-request are reset.
        """
        try:
            while not self._closed:
                await asyncio.sleep(self._next_watch_interval())
                if self._closed:
                    return
                now = time.monotonic()
                request_timeout = self.config.request_timeout
                keep_alive = self.config.keep_alive_timeout

                for stream in list(self.streams.values()):
                    deadline = stream.deadline
                    if deadline is not None and now >= deadline:
                        self._reset_stream(stream, h2.errors.ErrorCodes.CANCEL, "request not completed in time")

                if (
                    not self.streams
                    and keep_alive > 0
                    and now - self._last_activity > keep_alive
                ):
                    self.logger.debug("closing idle h20 connection after %.1fs", keep_alive)
                    self.shutdown()
                    return

                if (
                    not self._streams_opened
                    and request_timeout > 0
                    and now - self._connected_at > request_timeout
                ):
                    # The connection never produced a single stream: a peer that
                    # holds it open without ever starting a request is dropped.
                    # Once a stream exists, its own deadline is what governs,
                    # and the idle timeout takes over when it is gone.
                    self.logger.debug("resetting h20 connection: no request started within %.1fs", request_timeout)
                    self._abort()
                    return
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("unhandled error in h20 watchdog")

    def _next_watch_interval(self) -> float:
        """
        Sleep only until the next deadline instead of polling hard.

        Idle connections are not woken four times a second; a busy connection is
        checked often enough for the request deadline to be enforced promptly.
        """
        now = time.monotonic()
        request_timeout = self.config.request_timeout
        keep_alive = self.config.keep_alive_timeout
        deadlines: List[float] = []

        if self.streams:
            deadlines = [
                stream.deadline - now
                for stream in self.streams.values()
                if stream.deadline is not None
            ]
            if not deadlines:
                # Streams without a deadline (request_timeout disabled) still
                # have to be re-checked soon, so that finishing them brings the
                # idle timeout back into play.
                return 0.5
        elif keep_alive > 0:
            deadlines.append(self._last_activity + keep_alive - now)

        if not self._streams_opened and request_timeout > 0:
            deadlines.append(self._connected_at + request_timeout - now)
        if not deadlines:
            return 5.0
        return max(0.05, min(5.0, min(deadlines)))

    def _abort(self) -> None:
        """Reset the whole connection, used for stalling or abusive peers."""
        if self._closed:
            return
        self._closed = True
        self._cancel_all()
        utils.force_reset(self.transport)
        self._release()

    def _reset_stream(self, stream: _H2Stream, error_code: int, reason: str = "", send_rst: bool = True) -> None:
        """Tear a single stream down, optionally telling the peer why."""
        if stream.closed:
            return
        self.logger.debug("Resetting h20 stream %d (error=%s): %s", stream.stream_id, error_code, reason or "cancelled")
        stream.closed = True
        if send_rst:
            # RFC 9113 section 5.1: never answer RST_STREAM with RST_STREAM.
            self._rst(stream.stream_id, error_code)
        stream.request.notify_disconnect()
        current = asyncio.current_task()
        for task in (stream.request.app_task, stream.writer_task):
            if task is not None and task is not current and not task.done():
                task.cancel()
        self._ack(stream.stream_id, stream.unacked)
        stream.unacked = 0
        self.streams.pop(stream.stream_id, None)

    def _close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._cancel_all()
        try:
            self.transport.close()
        except Exception:
            pass
        self._release()

    async def _wait_writable(self) -> None:
        while self._write_paused and not self._closed:
            self._resume_event.clear()
            if not self._write_paused or self._closed:
                break
            await self._resume_event.wait()

    def _flush(self) -> None:
        if self._closed:
            return
        try:
            data = self.conn.data_to_send()
        except Exception:
            self.logger.exception("failed to buffer h20 output")
            return
        if not data:
            return
        try:
            self.transport.write(data)
        except Exception:
            self._close()

    def _rst(self, stream_id: int, error_code: int = 0) -> None:
        if self._closed:
            return
        try:
            self.conn.reset_stream(stream_id, error_code=error_code)
        except Exception:
            pass
        self._flush()

    # event dispatch
    def _handle_event(self, event: Any) -> None:
        try:
            if isinstance(event, h2.events.RequestReceived):
                self._on_request(event)
            elif isinstance(event, h2.events.DataReceived):
                self._on_data(event)
            elif isinstance(event, h2.events.StreamEnded):
                self._on_stream_ended(event.stream_id)
            elif isinstance(event, h2.events.StreamReset):
                self._on_stream_reset(event.stream_id, event.error_code)
            elif isinstance(event, (h2.events.WindowUpdated, h2.events.RemoteSettingsChanged)):
                # Both can open outbound flow control credit.
                self._window_event.set()
            elif isinstance(event, h2.events.TrailersReceived):
                if event.stream_ended:
                    self._on_stream_ended(event.stream_id)
            elif isinstance(event, h2.events.ConnectionTerminated):
                self._on_connection_terminated(event)
        except Exception:
            self.logger.exception("error while handling h20 event %r", event)

    def _on_connection_terminated(self, event: Any) -> None:
        """
        Handle the peer's GOAWAY frame (RFC 9113 section 6.8).

        Streams at or below ``last_stream_id`` were promised to be processed
        and are allowed to finish; the rest are dropped. The socket is closed
        as soon as nothing is in flight, so a peer that sends GOAWAY and keeps
        the connection open cannot leak a file descriptor.
        """
        self.logger.info("h20 peer sent GOAWAY (last=%s, error=%s)", event.last_stream_id, event.error_code)
        self._goaway_received = True
        if event.error_code != h2.errors.ErrorCodes.NO_ERROR:
            self._close()
            return
        for stream_id, stream in list(self.streams.items()):
            if stream_id > event.last_stream_id:
                self._reset_stream(stream, 0, "refused before GOAWAY", send_rst=False)
        if not self.streams:
            self._close()

    def _on_request(self, event: Any) -> None:
        stream_id = event.stream_id
        if stream_id in self.streams:
            self._rst(stream_id, h2.errors.ErrorCodes.PROTOCOL_ERROR)
            return

        # h2 has already enforced the pseudo-header rules (ordering, duplicates
        # and the :authority/Host match) while decoding the frame.
        pseudo: Dict[bytes, bytes] = {}
        regular: Headers = []
        for name, value in event.headers:
            if name.startswith(b":"):
                pseudo[name] = value
            else:
                regular.append((name, value))

        method = pseudo.get(b":method", b"").upper()
        path = pseudo.get(b":path", b"")
        scheme = pseudo.get(b":scheme", b"")
        authority = pseudo.get(b":authority") or utils.get_header(regular, b"host") or b""

        # The method is known by now, so even these replies stay HEAD safe.
        if len(event.headers) > self.config.max_header_count:
            self._respond_simple(stream_id, 431, b"Too many header fields", method=method)
            return
        if not method:
            self._respond_simple(stream_id, 400, b"Missing :method pseudo-header")
            return
        if method not in ALLOWED_METHODS:
            allow = b", ".join(sorted(ALLOWED_METHODS))
            self._respond_simple(
                stream_id,
                405,
                b"Method Not Allowed",
                extra=[(b"allow", allow)],
                method=method,
            )
            return
        if not path:
            self._respond_simple(stream_id, 400, b"Missing :path pseudo-header", method=method)
            return
        if path != b"*" and not path.startswith(b"/"):
            self._respond_simple(stream_id, 400, b"Invalid :path pseudo-header", method=method)
            return
        if len(path) > utils.MAX_TARGET_LENGTH:
            self._respond_simple(stream_id, 414, b"URI Too Long", method=method)
            return
        if not scheme:
            self._respond_simple(stream_id, 400, b"Missing :scheme pseudo-header", method=method)
            return

        if self.config.bind_domain:
            if utils.authority_host(authority) != utils.authority_host(
                self.config.bind_domain.encode("latin-1", "replace")
            ):
                self._respond_simple(stream_id, 421, b"Misdirected Request", method=method)
                return

        raw_path, _, query = path.partition(b"?")
        decoded_path = utils.decode_path(raw_path)

        scope: Dict[str, Any] = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "2",
            "server": self.server_addr,
            "client": self.peername,
            "scheme": scheme.decode("latin-1", "replace") or (
                "https" if self.ssl_object is not None else "http"
            ),
            "method": method.decode("latin-1", "replace"),
            "root_path": "",
            "path": decoded_path,
            "raw_path": raw_path,
            "query_string": query,
            "headers": regular,
        }

        request = ASGIRequest(
            scope,
            self.logger,
            recv_maxsize=0, # bounded by the flow control window, not by us
            ack_fn=lambda size, sid=stream_id: self._ack(sid, size),
        )
        stream = _H2Stream(stream_id, request)
        self._arm_stream_deadline(stream)
        self.streams[stream_id] = stream
        self._streams_opened += 1
        request.app_task = asyncio.ensure_future(request.run_app(self.app))
        stream.writer_task = asyncio.ensure_future(self._write_response(stream))

    def _on_data(self, event: Any) -> None:
        stream = self.streams.get(event.stream_id)
        flow_size = event.flow_controlled_length
        if stream is None or stream.closed:
            # Nobody will ever consume these bytes: return the credit at once so
            # the connection window does not starve the other streams.
            self._ack(event.stream_id, flow_size)
            return
        # Track the credit we hold before anything can acknowledge it, so the
        # window is never returned twice for the same bytes.
        stream.unacked += flow_size
        if stream.request.finished or not event.data:
            self._ack(event.stream_id, flow_size)
            return
        limit = self.config.max_request_size
        if limit and stream.received + len(event.data) > limit:
            # Answer first (RFC 9113 section 8.1 allows it) so the client sees a
            # reason, then reset the stream to stop the upload. h2 only emits
            # RST_STREAM while the stream is still open, which is correct.
            stream.request.keep_alive = False
            self._respond_simple(event.stream_id, 413, b"Payload Too Large")
            self._reset_stream(stream, h2.errors.ErrorCodes.CANCEL, "request body too large")
            return
        stream.received += len(event.data)
        outcome = stream.request.feed_request({"type": "http.request", "body": event.data, "more_body": True}, flow_size)
        if outcome == utils.FEED_GONE:
            # The application already finished: hand the credit straight back so
            # the connection window keeps serving the other streams.
            self._ack(event.stream_id, flow_size)
        elif outcome == utils.FEED_FULL:  # pragma: no cover - implies recv_maxsize
            # The receive queue for HTTP/2 is unbounded (the flow-control window
            # is what bounds memory), so this can only mean a bug elsewhere:
            # drop the payload and its credit rather than stalling the stream.
            self.logger.error("h20 receive queue is full; dropping %d bytes on stream %d", len(event.data), event.stream_id)
            self._ack(event.stream_id, flow_size)

    def _on_stream_ended(self, stream_id: int) -> None:
        stream = self.streams.get(stream_id)
        if stream is None or stream.closed:
            return
        stream.request_ended = True
        self._requests_completed += 1
        if not stream.request.finished:
            stream.request.feed_request({"type": "http.request", "body": b"", "more_body": False}, 0)
        if stream.response_complete:
            self._finalize(stream)

    def _on_stream_reset(self, stream_id: int, error_code: int = 0) -> None:
        stream = self.streams.get(stream_id)
        if stream is None:
            return
        self.logger.debug("h20 stream %d reset by peer (error=%s)", stream_id, error_code)
        self._reset_stream(stream, h2.errors.ErrorCodes.NO_ERROR, "reset by peer", send_rst=False)

    def _arm_stream_deadline(self, stream: _H2Stream) -> None:
        """
        (Re)start the per-stream request deadline.

        The first window covers receiving the whole request; after that every
        write restarts it, so a response may run as long as it makes progress
        while a stalled stream is reset.
        """
        timeout = self.config.request_timeout
        stream.deadline = (time.monotonic() + timeout if timeout > 0 and not stream.closed else None)

    def _note_progress(self, stream_id: int) -> None:
        stream = self.streams.get(stream_id)
        if stream is not None:
            self._arm_stream_deadline(stream)

    def _ack(self, stream_id: int, size: int) -> None:
        if size <= 0 or self._closed:
            return
        stream = self.streams.get(stream_id)
        if stream is not None:
            stream.unacked = max(0, stream.unacked - size)
        try:
            self.conn.acknowledge_received_data(size, stream_id)
        except Exception:
            return
        self._flush()

    def _finalize(self, stream: _H2Stream) -> None:
        if stream.closed:
            return
        stream.closed = True
        self._ack(stream.stream_id, stream.unacked)
        stream.unacked = 0
        self.streams.pop(stream.stream_id, None)
        if self._goaway_received and not self.streams:
            # The peer is leaving and nothing is in flight any more.
            self._close()

    # response writing
    def _send_headers(self, stream_id: int, headers: List[Tuple[bytes, bytes]], end_stream: bool) -> bool:
        if self._closed:
            return False
        if not headers:
            # An empty header list encodes to zero frames, so an empty trailer
            # section is exactly END_STREAM (and h2 rejects the empty block).
            if end_stream:
                self._end_stream(stream_id)
            return True
        try:
            self.conn.send_headers(stream_id, headers, end_stream=end_stream)
        except h2.exceptions.H2Error as exc:
            self.logger.warning("Cannot send headers on stream %d: %s", stream_id, exc)
            self._rst(stream_id, h2.errors.ErrorCodes.INTERNAL_ERROR)
            return False
        self._flush()
        self._note_progress(stream_id)
        return True

    def _end_stream(self, stream_id: int) -> None:
        if self._closed:
            return
        try:
            self.conn.end_stream(stream_id)
        except h2.exceptions.H2Error as exc:
            self.logger.debug("Cannot end stream %d: %s", stream_id, exc)
            return
        self._flush()

    async def _wait_for_window(self, stream: _H2Stream) -> bool:
        """Wait until the peer grants more outbound flow control credit."""
        while not self._closed and not stream.closed:
            self._window_event.clear()
            try:
                if self.conn.local_flow_control_window(stream.stream_id) > 0:
                    return True
            except (h2.exceptions.StreamClosedError, KeyError):
                return False
            except h2.exceptions.H2Error:
                return False
            await self._window_event.wait()
        return False

    async def _send_data(self, stream: _H2Stream, data: bytes, end_stream: bool) -> bool:
        """Send a DATA payload, honouring the peer's flow control window."""
        if not data:
            if end_stream:
                self._end_stream(stream.stream_id)
            return True
        view = memoryview(data)
        offset = 0
        total = len(view)
        while offset < total:
            if self._closed or stream.closed:
                return False
            try:
                window = self.conn.local_flow_control_window(stream.stream_id)
            except (h2.exceptions.StreamClosedError, KeyError):
                return False
            except h2.exceptions.H2Error:
                return False
            if window <= 0:
                if not await self._wait_for_window(stream):
                    return False
                continue
            chunk_size = min(window, self.conn.max_outbound_frame_size, total - offset)
            chunk = bytes(view[offset : offset + chunk_size])
            offset += chunk_size
            try:
                self.conn.send_data(stream.stream_id, chunk, end_stream=end_stream and offset >= total)
            except h2.exceptions.H2Error as exc:
                self.logger.warning("Cannot send data on stream %d: %s", stream.stream_id, exc)
                return False
            await self._wait_writable()
            self._flush()
            self._note_progress(stream.stream_id)
        return True

    def _respond_simple(self, stream_id: int, status: int, body: bytes = b"", extra: Optional[List[Tuple[bytes, bytes]]] = None, method: bytes = b"") -> None:
        """
        Answer a request that never reached the application.

        The bodies here are a single short line, so they always fit in the
        initial flow-control window and are sent without an extra window check.
        """
        headers: List[Tuple[bytes, bytes]] = [
            (b":status", str(status).encode("latin-1")),
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"content-length", str(len(body)).encode("latin-1")),
            (b"date", utils.format_http_date().encode("latin-1")),
            (b"server", utils.SERVER_HEADER.encode("latin-1")),
        ]
        if extra:
            headers.extend(extra)
        # A HEAD response announces the length but carries no payload.
        if not body or not utils.response_has_body(method.decode("latin-1", "replace") or "GET", status):
            self._send_headers(stream_id, headers, end_stream=True)
            return
        if not self._send_headers(stream_id, headers, end_stream=False):
            return
        try:
            self.conn.send_data(stream_id, body, end_stream=True)
        except h2.exceptions.H2Error:
            pass
        self._flush()

    async def _write_response(self, stream: _H2Stream) -> None:
        request = stream.request
        stream_id = stream.stream_id
        try:
            headers: Headers = []
            compressor: Optional[Compressor] = None
            started = False
            trailers_expected = False
            awaiting_trailers = False
            discard_body = False
            byte_count = 0

            # The per-stream deadline (enforced by the watchdog) covers a
            # response that never starts and one that stalls, so the writer only
            # waits for the next ASGI message here.
            while True:
                message = await request.next_response_message()
                message_type = message.get("type")
                if message_type == "http.response.start":
                    raw_status = int(message["status"])
                    if raw_status < 200:
                        interim = utils.normalize_response_headers(
                            message.get("headers"),
                            lowercase=True,
                            forbidden=utils.H2_FORBIDDEN_HEADERS,
                        )
                        self._send_headers(
                            stream_id,
                            [(b":status", str(raw_status).encode("latin-1")), *interim],
                            end_stream=False,
                        )
                        continue

                    status = raw_status
                    request.status = status
                    headers = utils.normalize_response_headers(
                        message.get("headers"),
                        lowercase=True,
                        forbidden=utils.H2_FORBIDDEN_HEADERS,
                    )
                    has_body = utils.response_has_body(request.scope["method"], status)
                    trailers_expected = bool(message.get("trailers")) and has_body

                    if has_body and self.config.compression:
                        encoding = utils.should_compress(
                            request.scope["method"],
                            status,
                            headers,
                            request.scope["headers"],
                        )
                        if encoding is not None:
                            compressor = Compressor(encoding)
                            headers = [
                                (name, value)
                                for name, value in headers
                                if name.lower() != b"content-length"
                            ]
                            headers.append((b"content-encoding", encoding.encode("latin-1")))

                    if not has_body:
                        drop = utils.bodyless_header_drops(request.scope["method"], status)
                        headers = [
                            (name, value)
                            for name, value in headers
                            if name.lower() not in drop
                        ]

                    response_headers: List[Tuple[bytes, bytes]] = [(b":status", str(status).encode("latin-1"))]
                    if not utils.has_header(headers, b"date"):
                        response_headers.append((b"date", utils.format_http_date().encode("latin-1")))
                    if not utils.has_header(headers, b"server"):
                        response_headers.append((b"server", utils.SERVER_HEADER.encode("latin-1")))
                    response_headers.extend(headers)
                    if self.config.safe_headers:
                        for name, value in utils.SAFE_HEADERS:
                            if not utils.has_header(headers, name):
                                response_headers.append((name, value))

                    if not has_body:
                        # 204/304/HEAD: no payload, terminate in the HEADERS frame
                        # and drain the body messages the application still sends.
                        if not self._send_headers(stream_id, response_headers, end_stream=True):
                            return
                        started = True
                        discard_body = True
                        if not message.get("more_body", True):
                            break
                        continue

                    if not self._send_headers(stream_id, response_headers, end_stream=False):
                        return
                    started = True

                elif message_type == "http.response.body":
                    if not started:
                        self.logger.warning("Ignoring http.response.body before start")
                        continue
                    body = message["body"]
                    more = message["more_body"]
                    if discard_body:
                        if not more:
                            break
                        continue
                    # END_STREAM has to travel with the trailer block when the
                    # application announced trailers (RFC 9113 section 8.1).
                    ends_here = not more and not trailers_expected
                    if compressor is not None:
                        if body:
                            compressed = compressor.compress(body)
                            # Report what actually reaches the wire.
                            byte_count += len(compressed)
                            if not await self._send_data(stream, compressed, end_stream=False):
                                return
                        if not more and not await self._send_data(stream, compressor.flush(), end_stream=ends_here):
                            return
                    else:
                        byte_count += len(body)
                        if not await self._send_data(stream, body, end_stream=ends_here):
                            return

                    if not more:
                        if trailers_expected:
                            awaiting_trailers = True
                            continue
                        break

                elif message_type == "http.response.trailers":
                    if not awaiting_trailers:
                        # The stream never opened a trailer section, so there is
                        # nothing to send; the message still ends the response.
                        if not message.get("more_trailers"):
                            break
                        continue
                    trailer_headers = utils.normalize_response_headers(
                        message.get("headers"),
                        lowercase=True,
                        forbidden=utils.H2_FORBIDDEN_HEADERS,
                    )
                    more_trailers = bool(message.get("more_trailers"))
                    if not self._send_headers(stream_id, trailer_headers, end_stream=not more_trailers):
                        return
                    if not more_trailers:
                        break

            request.bytes_sent = byte_count
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("Error while writing h20 response")
        finally:
            request.mark_finished()
            request.response_complete.set()
            stream.response_complete = True
            if self.config.access_log and request.status is not None:
                utils.access_log(
                    self.access_logger,
                    "h20",
                    request.scope.get("client"),
                    request.scope.get("method", "-"),
                    request.target,
                    request.status,
                    time.monotonic() - request.start_time,
                )
            if stream.request_ended and not stream.closed:
                self._finalize(stream)
            elif not stream.closed:
                # The application answered without reading the whole request
                # body. Hand back the flow-control credit we were holding so
                # the client can finish its upload instead of stalling on a
                # closed window; further DATA is dropped and acknowledged in
                # ``_on_data``. The stream watchdog is the backstop for a peer
                # that then uploads forever.
                self._ack(stream_id, stream.unacked)
