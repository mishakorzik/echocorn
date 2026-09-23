"""
Rate limiting: the sliding window, the one-per-window peak and the lockout.

The limiter counts requests per client address.  With ``workers = 1`` it counts
in memory; with more workers every one of them counts into the same table in
shared memory, and that is what most of this file is about: the table is exact,
it is one allowance for the whole server, and neither a held mutex nor a table
too small for the traffic may take a request down with it.

``429 Too Many Requests`` is RFC 6585 section 4, the ``Retry-After`` header
RFC 9110 section 10.2.3.
"""

from __future__ import annotations

import base64
import logging
import multiprocessing
import os
import pathlib
import random
import threading
import time
import zlib
from multiprocessing import shared_memory

import pytest

from conftest import H2Client, ServerThread, build_request, read_response
from echocorn import ServerConfig
from echocorn.config import ConfigError, load_settings
from echocorn.ratelimit import (
    LOCK_TIMEOUT,
    MIN_SLOTS,
    LocalCounters,
    RateLimiter,
    SharedCounters,
    client_key,
    pack_client,
    retry_after_seconds,
    slot_count,
    slot_size,
)

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load(tmp_path, text):
    path = tmp_path / "echocorn.toml"
    path.write_text(text, encoding="utf-8")
    return load_settings(path)


# The limiter itself
def test_the_plain_allowance_is_per_window():
    limiter = RateLimiter(requests=3, peak=0, window=10.0, ban=0.0)
    assert [limiter.check("a", now=0.1 * index) for index in range(3)] == [None, None, None]
    assert limiter.check("a", now=0.4) is not None
    # The window slides, so a client gets its allowance back over time.
    assert limiter.check("a", now=10.2) is None


def test_the_peak_is_one_burst_per_window():
    limiter = RateLimiter(requests=2, peak=4, window=10.0, ban=0.0)
    assert limiter.check("a", 0.0) is None
    assert limiter.check("a", 0.1) is None
    assert limiter.check("a", 0.2) is None  # the one burst of this window
    assert limiter.check("a", 0.3) is not None  # never a second one
    # A new window hands the burst back.
    assert limiter.check("a", 10.5) is None
    assert limiter.check("a", 10.6) is None
    assert limiter.check("a", 10.7) is None


def test_a_peak_of_zero_means_no_burst():
    limiter = RateLimiter(requests=2, peak=0, window=10.0, ban=0.0)
    assert limiter.peak == 2
    assert limiter.check("a", 0.0) is None
    assert limiter.check("a", 0.1) is None
    assert limiter.check("a", 0.2) is not None


def test_clients_are_counted_on_their_own():
    limiter = RateLimiter(requests=1, peak=1, window=10.0, ban=0.0)
    assert limiter.check("a", 0.0) is None
    assert limiter.check("b", 0.0) is None
    assert limiter.check("a", 0.1) is not None


def test_a_refused_client_is_banned_for_the_configured_time():
    limiter = RateLimiter(requests=1, peak=2, window=5.0, ban=30.0)
    assert limiter.check("a", 0.0) is None
    assert limiter.check("a", 0.1) is None  # the burst
    assert limiter.check("a", 0.2) == pytest.approx(30.0)
    # Every further request during the lockout is refused, and the wait it is
    # told about counts down.
    assert limiter.check("a", 5.0) == pytest.approx(25.2)
    assert limiter.check("a", 29.0) == pytest.approx(1.2)
    # The lockout is over; the window it started in is long gone, so the client
    # starts again with a full allowance.
    assert limiter.check("a", 30.5) is None
    assert limiter.check("a", 30.6) is None


def test_without_a_lockout_the_retry_waits_for_the_window_to_slide():
    limiter = RateLimiter(requests=1, peak=1, window=2.0, ban=0.0)
    assert limiter.check("a", 0.0) is None
    assert limiter.check("a", 0.5) == pytest.approx(1.5)
    assert limiter.check("a", 2.5) is None


def test_counters_of_quiet_clients_are_forgotten():
    limiter = RateLimiter(requests=5, peak=5, window=1.0, ban=0.0)
    for index in range(100):
        limiter.check("client-%d" % index, now=index * 0.001)
    assert len(limiter._hits) == 100
    limiter.check("somebody", now=10.0)
    assert len(limiter._hits) == 1


def test_client_key_is_the_address_without_its_port():
    assert client_key(("127.0.0.1", 51234)) == "127.0.0.1"
    assert client_key(("::1", 51234, 0, 0)) == "::1"
    assert client_key(None) == "-"


def test_retry_after_is_whole_seconds_and_never_zero():
    assert retry_after_seconds(0.0) == 1
    assert retry_after_seconds(0.1) == 1
    assert retry_after_seconds(1.0) == 1
    assert retry_after_seconds(59.2) == 60


def test_the_limiter_is_built_from_the_configuration():
    assert RateLimiter.from_config(ServerConfig()) is None
    limiter = RateLimiter.from_config(
        ServerConfig(ratelimit_enabled=True, ratelimit_requests=4, ratelimit_peak=0, ratelimit_window=1.0, ratelimit_ban=0.0)
    )
    assert (limiter.requests, limiter.peak, limiter.window, limiter.ban) == (4, 4, 1.0, 0.0)


# Configuration
def test_the_ratelimit_section_is_read(tmp_path):
    settings = _load(
        tmp_path,
        'app = "a:b"\n'
        "\n[ratelimit]\n"
        "enabled = true\n"
        "requests = 5\n"
        "peak = 8\n"
        "window = 2.5\n"
        "ban = 15\n",
    )
    config = settings.config
    assert config.ratelimit_enabled is True
    assert config.ratelimit_requests == 5
    assert config.ratelimit_peak == 8
    assert config.ratelimit_window == 2.5
    assert config.ratelimit_ban == 15.0


def test_the_defaults_are_the_documented_example():
    config = ServerConfig()
    assert (
        config.ratelimit_enabled,
        config.ratelimit_requests,
        config.ratelimit_peak,
        config.ratelimit_window,
        config.ratelimit_ban,
        config.ratelimit_shards,
        config.ratelimit_cache_size,
    ) == (False, 10, 12, 7.0, 60.0, 64, 128)


def test_the_shipped_example_documents_them():
    """The example is what an operator copies, so it spells the knobs out."""
    example = (ROOT / "echocorn.toml").read_text(encoding="utf-8")
    assert "[ratelimit]" in example
    for key in ("enabled", "requests", "peak", "window", "ban", "shards", "cache_size"):
        assert "\n%s = " % key in example


def test_the_sharing_knobs_are_read(tmp_path):
    settings = _load(
        tmp_path,
        'app = "a:b"\n'
        "\n[ratelimit]\n"
        "enabled = true\n"
        "shards = 8\n"
        "cache_size = 16\n",
    )
    assert settings.config.ratelimit_shards == 8
    assert settings.config.ratelimit_cache_size == 16


@pytest.mark.parametrize("line", ["state_file = \"counters.db\"", "sync_interval = 0.5"])
def test_the_file_settings_are_gone(tmp_path, line):
    """The counters live in shared memory now, so the file keys are unknown."""
    with pytest.raises(ConfigError):
        _load(tmp_path, 'app = "a:b"\n[ratelimit]\n' + line + "\n")


@pytest.mark.parametrize(
    "line, message",
    [
        ("requests = 0", "ratelimit_requests must be positive"),
        ("peak = 3", "ratelimit_peak must be at least ratelimit_requests"),
        ("window = 0", "ratelimit_window must be positive"),
        ("ban = -1", "ratelimit_ban must not be negative"),
        ("shards = 0", "ratelimit_shards must be positive"),
        ("cache_size = 0", "ratelimit_cache_size must be at least one megabyte"),
    ],
)
def test_invalid_ratelimit_values_are_reported(tmp_path, line, message):
    with pytest.raises(ConfigError) as excinfo:
        _load(tmp_path, 'app = "a:b"\n[ratelimit]\nenabled = true\n' + line + "\n")
    assert message in str(excinfo.value)


def test_a_peak_that_cannot_fit_the_cache_is_refused(tmp_path):
    """A slot holds one timestamp per request of the allowance."""
    with pytest.raises(ConfigError) as excinfo:
        _load(
            tmp_path,
            'app = "a:b"\n\n[ratelimit]\nenabled = true\npeak = 100000\ncache_size = 1\n',
        )
    assert "too small for ratelimit_peak" in str(excinfo.value)


# The shared table
def _shared_config(tmp_path, **overrides):
    """A configuration whose workers count into one table in shared memory."""
    options = dict(
        ratelimit_enabled=True,
        ratelimit_requests=3,
        ratelimit_peak=0,
        ratelimit_window=60.0,
        ratelimit_ban=0.0,
        ratelimit_shards=4,
        ratelimit_cache_size=1,
        workers=2,
    )
    options.update(overrides)
    return ServerConfig(**options)


def _small_table(slots=MIN_SLOTS, shards=1, **overrides):
    """A table of our own, small enough to fill up on purpose."""
    options = dict(
        requests=2,
        peak=0,
        window=10.0,
        ban=0.0,
        slots=slots,
        shards=shards,
    )
    options.update(overrides)
    counters = SharedCounters(**options)
    name = "echocorn-test-%d-%s" % (os.getpid(), os.urandom(4).hex())
    counters.shm = shared_memory.SharedMemory(
        create=True, size=counters.size * counters.slots, name=name
    )
    counters.name = name
    counters.owned = True
    counters.locks = [multiprocessing.Lock() for _ in range(counters.shards)]
    assert counters.start()
    return counters


def _used_slots(counters):
    """How many slots of the table hold a client."""
    used = 0
    for index in range(counters.slots):
        if counters._head.unpack_from(counters.buf, index * counters.size)[0]:
            used += 1
    return used


def _slot_of(counters, client):
    """Index and offset of the slot a client is in, or None."""
    digest = zlib.crc32(pack_client(client))
    for step in range(16):
        index = (digest + step) % counters.slots
        at = index * counters.size
        length, key, *_rest = counters._head.unpack_from(counters.buf, at)
        if length and key[:length] == pack_client(client):
            return at
    return None


def test_pack_client_keeps_ipv4_and_ipv6_apart():
    assert pack_client("127.0.0.1") == b"\x7f\x00\x00\x01"
    assert len(pack_client("2001:db8::1")) == 16
    assert pack_client("unix-socket-peer") == b"unix-socket-peer"
    # A name too long for the slot is truncated, never confused with an address.
    assert len(pack_client("x" * 40)) == 16


def test_one_worker_has_nothing_to_share(tmp_path):
    assert RateLimiter.from_config(_shared_config(tmp_path, workers=1)).shared is None


def test_the_table_is_sized_from_the_configuration(tmp_path):
    config = _shared_config(tmp_path, ratelimit_shards=8, ratelimit_cache_size=2)
    counters = SharedCounters.create(config)
    try:
        assert counters.shards == 8
        assert counters.slots == slot_count(2, 3)
        assert counters.size == slot_size(3)
        # The table uses the memory it was given, and not more (the segment is
        # allocated in whole pages, so it rounds up a little).
        assert counters.shm.size >= counters.slots * counters.size
        assert counters.shm.size <= 2 * 1024 * 1024
        assert counters.shm.size > 2 * 1024 * 1024 - counters.size - 4096
    finally:
        counters.close()


def test_the_shared_and_the_local_limiter_decide_alike():
    """
    The two implementations of the window must not drift apart.

    Random traffic through both, with the same clock, has to produce the same
    decision and the same wait for every single request.
    """
    rng = random.Random(20260923)
    clients = ["203.0.113.%d" % index for index in range(5)]
    settings = dict(requests=3, peak=5, window=4.0, ban=2.0)
    local = LocalCounters(**settings)
    table = _small_table(slots=MIN_SLOTS, shards=4, **settings)
    try:
        now = 100.0
        for _ in range(4000):
            now += rng.choice([0.001, 0.01, 0.4, 1.5, 3.0])
            client = rng.choice(clients)
            assert table.consume(client, now) == local.consume(client, now), (client, now)
    finally:
        table.close()


def test_the_window_of_a_slot_wraps_around():
    """
    The timestamps of a window are a ring, and it has to survive filling up.

    A client that hammers through its allowance fills the ring and then keeps
    arriving while it is full: every request then has to age something out of
    the front, write itself at the back and wrap past the ring's end, without
    ever losing count of the window.  The in-memory limiter decides the same
    sequence request by request, so any drift shows up as a mismatch.
    """
    settings = dict(requests=4, peak=4, window=2.0, ban=0.0)
    local = LocalCounters(**settings)
    table = _small_table(slots=MIN_SLOTS, shards=1, **settings)
    ring = table.peak + 1
    try:
        now = 50.0
        served = 0
        # Three full rings' worth of requests from one client, close enough
        # together that nothing ages out of the first two.
        for _ in range(3 * ring):
            now += 0.01
            decision = table.consume("192.0.2.7", now)
            assert decision == local.consume("192.0.2.7", now)
            served += decision is None
        # A request must be counted because it was served, and the client must
        # not be served more than the allowance plus its one burst.
        assert served == settings["peak"]
        # Now let the window slide while the ring is full: every refusal ages
        # out exactly one old request and lets exactly one new one in.
        for _ in range(ring):
            now += 0.25
            assert table.consume("192.0.2.7", now) == local.consume("192.0.2.7", now)
        # Long after everybody stopped, the slot goes back to being empty.
        now += 60.0
        assert table.consume("192.0.2.7", now) is None
        assert local.consume("192.0.2.7", now) is None
    finally:
        table.close()


def test_an_identity_is_kept_apart_from_its_neighbours():
    """Two addresses sharing a slot index are told apart, not counted together."""
    table = _small_table(slots=MIN_SLOTS)
    try:
        mask = table.slots - 1
        by_slot = {}
        for index in range(1, 5000):
            client = "198.51.100.%d" % index
            by_slot.setdefault(zlib.crc32(pack_client(client)) & mask, client)
            if len(by_slot) == 6:
                break
        # Six clients whose hashes collide into as few indices as possible: the
        # table must still count every one of them on its own.
        for client in by_slot.values():
            assert table.consume(client, 500.0) is None
            assert table.consume(client, 500.1) is None
            assert table.consume(client, 500.2) is not None
    finally:
        table.close()


def test_the_counters_of_the_whole_server_are_one_set(tmp_path):
    """Two limiters, one table: the second never gets its own allowance."""
    config = _shared_config(tmp_path)
    counters = SharedCounters.create(config)
    try:
        counters.start()
        first = RateLimiter.from_config(config, counters)
        second = RateLimiter.from_config(config, counters)
        assert [first.check("203.0.113.7") for _ in range(3)] == [None, None, None]
        assert second.check("203.0.113.7") is not None
        assert first.check("203.0.113.7") is not None
    finally:
        counters.close()


def _hammer(name, locks, config, client, ops, queue):
    """One worker process: count as fast as it can and report what it was told."""
    counters = SharedCounters.attach(name, locks, config)
    assert counters.start()
    try:
        served = 0
        for _ in range(ops):
            if counters.consume(client, time.time()) is None:
                served += 1
    finally:
        counters.close()
    queue.put(served)


def test_two_processes_share_one_allowance(tmp_path):
    """The point of the whole design, with two real processes."""
    config = _shared_config(tmp_path, ratelimit_requests=50, ratelimit_peak=0)
    counters = SharedCounters.create(config)
    counters.start()
    # The default context, which is the one the table's mutexes were made in and
    # the one the server starts its workers with.
    queue = multiprocessing.Queue()
    processes = [
        multiprocessing.Process(
            target=_hammer,
            args=(counters.name, counters.locks, config, "192.0.2.44", 300, queue),
        )
        for _ in range(2)
    ]
    try:
        for process in processes:
            process.start()
        # A worker that died shows up as a failing test here instead of a suite
        # that never ends.
        served = 0
        for _ in processes:
            served += queue.get(timeout=60)
        for process in processes:
            process.join(timeout=60)
            assert process.exitcode == 0
    finally:
        counters.close()
    assert served == 50, "600 requests from two processes served %d, not one allowance" % served


def test_a_worker_that_cannot_take_the_mutex_counts_on_its_own():
    """A held mutex must cost a request its exactness, never its answer."""
    table = _small_table(slots=MIN_SLOTS, shards=1, requests=1, peak=0, ban=0.0)
    try:
        table.consume("203.0.113.1", 100.0)         # fill the window
        held = threading.Event()
        released = threading.Event()

        def hold():
            with table.locks[0]:
                held.set()
                released.wait(5.0)

        thread = threading.Thread(target=hold, daemon=True)
        thread.start()
        held.wait(5.0)
        started = time.perf_counter()
        # However long somebody holds the mutex, the request is answered.
        assert table.consume("203.0.113.2", 100.0) is None
        waited = time.perf_counter() - started
        # ... and the allowance is still enforced while it is answered alone.
        assert table.consume("203.0.113.2", 100.1) is not None
        released.set()
        thread.join(5.0)
        assert waited >= LOCK_TIMEOUT * 0.9
        assert table.stats["timeouts"] == 2
        assert table.stats["decisions"] == 3
        # With the mutex free again the client is counted in the table, which
        # never saw those two requests: that is what the fallback costs.
        assert table.consume("203.0.113.2", 100.2) is None
    finally:
        table.close()


def test_a_full_run_of_slots_falls_back_to_counting_in_this_process():
    table = _small_table(slots=MIN_SLOTS, shards=1)
    try:
        # Fill four indices in a row with four different clients, then ask for a
        # fifth that hashes to the first of them: every probe is taken.
        occupied = []
        for want in range(4):
            for index in range(1, 200000):
                candidate = "10.9.%d.%d" % (want, index)
                if candidate in occupied:
                    continue
                if zlib.crc32(pack_client(candidate)) % table.slots == want:
                    occupied.append(candidate)
                    assert table.consume(candidate, 100.0) is None
                    break
            else:  # pragma: no cover - the search always finds one
                raise AssertionError("no client hashes to slot %d" % want)
        for index in range(1, 200000):
            intruder = "10.10.0.%d" % index
            if zlib.crc32(pack_client(intruder)) % table.slots == 0:
                break
        assert table.consume(intruder, 100.0) is None
        assert table.stats["overflow"] == 1
        # The intruder is counted in this process, so it is still limited.
        assert table.consume(intruder, 100.1) is None
        assert table.consume(intruder, 100.2) is not None
    finally:
        table.close()


def test_the_table_empties_itself_of_clients_that_stopped():
    table = _small_table(slots=MIN_SLOTS, shards=1, requests=1, peak=0)
    table.sweep_every = 1                              # as if a day had passed
    table.sweep_step = 16
    try:
        table.consume("203.0.113.1", 100.0)
        assert _used_slots(table) == 1
        at = _slot_of(table, "203.0.113.1")
        assert at is not None
        # The window is long over, so the sweeps that come with the next
        # requests free the slot instead of remembering the address forever.
        for step in range(MIN_SLOTS):
            table.consume("192.0.2.7", 1000.0 + step)
        assert table.stats["swept"] >= 1
        assert table._head.unpack_from(table.buf, at)[0] == 0
        assert _used_slots(table) == 1                 # only the client still asking
    finally:
        table.close()


# End to end
def _rate_limited(**overrides):
    """A server whose allowance is two requests plus one burst of three."""
    options = dict(
        ratelimit_enabled=True,
        ratelimit_requests=2,
        ratelimit_peak=3,
        ratelimit_window=0.5,
        ratelimit_ban=0.5,
    )
    options.update(overrides)
    return ServerThread(**options)


def _get(server, target="/"):
    connection = server.connect()
    try:
        connection.sendall(build_request(target=target, host="localhost"))
        return read_response(connection)
    finally:
        connection.close()


def test_http1_answers_429_with_a_retry_after():
    with _rate_limited() as server:
        assert [_get(server).status for _ in range(3)] == [200, 200, 200]
        refused = _get(server)
        assert refused.status == 429
        assert refused.header(b"retry-after") == b"1"
        # The refusal closes the connection: the body of a request that was
        # never dispatched has not been read.
        assert refused.header(b"connection") == b"close"
        assert _get(server).status == 429
        # Once the lockout is over the client is served again.
        time.sleep(0.6)
        assert _get(server).status == 200


def test_a_refused_request_never_reaches_the_application():
    seen = []

    async def counting_app(scope, receive, send):
        if scope["type"] != "http":
            return
        seen.append(scope["path"])
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain"), (b"content-length", b"2")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    with ServerThread(
        counting_app,
        ratelimit_enabled=True,
        ratelimit_requests=1,
        ratelimit_peak=1,
        ratelimit_window=1.0,
        ratelimit_ban=1.0,
    ) as server:
        assert _get(server).status == 200
        assert _get(server).status == 429
        assert _get(server).status == 429
    assert seen == ["/"]


def test_rate_limiting_off_never_refuses():
    with ServerThread(ratelimit_enabled=False) as server:
        assert [_get(server).status for _ in range(25)] == [200] * 25


def test_the_serving_loop_shares_the_counters_and_leaves_nothing_behind(tmp_path, caplog):
    """A server that asks for several workers builds one table and removes it."""
    options = dict(
        ratelimit_enabled=True,
        ratelimit_requests=3,
        ratelimit_peak=0,
        ratelimit_window=60.0,
        ratelimit_ban=60.0,
        ratelimit_cache_size=1,
        ratelimit_shards=2,
        workers=2,
    )
    with caplog.at_level(logging.DEBUG, logger="echocorn.server"):
        with ServerThread(**options) as server:
            counters = server.server.shared_counters
            assert counters is not None and counters.running
            assert counters.slots >= MIN_SLOTS
            name = counters.name
            assert [_get(server).status for _ in range(3)] == [200, 200, 200]
            assert _get(server).status == 429
            assert counters.stats["decisions"] == 4
    # The process that created the table removed it again.
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            shared_memory.SharedMemory(name=name).close()
        except OSError:
            break
        time.sleep(0.05)
    else:  # pragma: no cover - only when the segment really leaks
        raise AssertionError("the shared table of %s is still there" % name)


def test_http2_refuses_the_stream_and_keeps_the_connection():
    with _rate_limited() as server:
        with H2Client(server) as client:
            for _ in range(3):
                assert client.wait(client.request("/")).status == 200
            refused = client.wait(client.request("/"))
            assert refused.status == 429
            assert refused.header(b"retry-after") == b"1"
            # A refused stream must not take the connection down with it.
            assert client.goaway is None
            assert client.resets == []
            time.sleep(0.6)
            assert client.wait(client.request("/")).status == 200


def test_a_rate_limited_websocket_upgrade_is_answered_with_429():
    with _rate_limited(ratelimit_requests=1, ratelimit_peak=1) as server:
        assert _get(server).status == 200
        connection = server.connect()
        try:
            connection.sendall(
                build_request(
                    target="/ws",
                    host="localhost",
                    headers=[
                        ("Upgrade", "websocket"),
                        ("Connection", "Upgrade"),
                        ("Sec-WebSocket-Key", base64.b64encode(bytes(range(16))).decode()),
                        ("Sec-WebSocket-Version", "13"),
                    ],
                )
            )
            response = read_response(connection)
        finally:
            connection.close()
    assert response.status == 429
    assert response.header(b"retry-after") == b"1"
