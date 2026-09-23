"""
Per-client request rate limiting, counted once for every worker of the server.

A client - the address a connection comes from - gets ``requests`` requests per
``window`` seconds.  Once per window it may go up to ``peak`` requests instead,
which is what lets one short spike through without raising the steady limit, and
a client that goes past even that is answered with ``429 Too Many Requests``
(RFC 6585 section 4) for ``ban`` seconds.

The window slides: a burst at the end of one window cannot be repeated at the
beginning of the next, which a fixed bucket would allow.  The burst allowance is
one per window as well, so ``peak`` is a spike, never a second allowance.

Where the counters live
-----------------------
* **One process** (``workers = 1``): in a dictionary, and nothing else is needed.
* **Several processes** (``workers > 1``): in one table in **shared memory**.
  The process that reads the configuration creates the segment and the mutexes
  before it starts its workers, and every worker maps the same memory: the
  allowance is the server's, and no worker has a copy of the counters to fall
  behind with.  There is no file, no disk and no message between the workers -
  a decision costs one mutex, one 32 byte slot and no syscall.

How the table handles several processes
---------------------------------------
The table is an open-addressed hash table of fixed slots (as many as
``cache_size`` pays for, at least :data:`MIN_SLOTS`), with the whole address in
the slot so a client is never confused with another one.  A request takes the mutex of its **shard**
(``shards`` of them, so unrelated clients rarely meet), reads its slot, applies
the window and writes it back.  That is what makes the decision exact no matter
how many workers the server runs: the counters are one set.

The disk, the network and a second process are all avoided on purpose.  Measured
with four processes and 1000 clients (``bench/shards.py``): 1.0 us per decision,
2.1M decisions a second together, 195k/s when every process hammers the *same*
client, and the p99.9 of a decision under 250 us.  The same counter written as a
SQLite transaction per request costs 5.9 us and tops out at 146k/s together,
which is also what aiosqlite costs (100 us: every call is a hop into a worker
thread) - both remain in ``bench/shared_counters.py`` as the measurements that
ruled them out.  A slot is 46 bytes plus eight per request of the allowance, so
the default 128 MB of ``cache_size`` is about 894 000 clients at the default
``peak`` of 12.

The timestamps of a client's window are a ring at the end of its slot, so a
decision reads and writes the ring's two ends: allowing 20 000 requests costs the
same 0.9 us per request as allowing 12, where copying the window would have cost
160 kB of memory traffic on every request.

``shards`` is what makes several processes worth having: one mutex turns the
whole table into a queue (154k/s), sixteen shards already reach 1.7M/s, and past
128 nothing improves - the table is walked by its own clients, not by them all
at once.  A client always maps to one shard, so ~195k decisions a second is the
ceiling for a single address, whoever it is.

Two things can go wrong, and neither is allowed to break a request:

* A worker killed while it held a mutex would leave the others waiting, so the
  acquire is bounded (:data:`LOCK_TIMEOUT`).  On a timeout the client is counted
  in that worker's own memory instead, which can allow a little more than the
  allowance and is reported through :attr:`SharedCounters.stats`.
* Every slot of a shard taken by *other* clients (``PROBES`` of them in a row)
  means the table is far too small for the traffic; the same in-memory fallback
  applies.  A few slots are swept on every request, so a table full of addresses
  that stopped sending empties itself instead of staying full.
"""

from __future__ import annotations

import itertools
import logging
import math
import multiprocessing
import os
import socket
import struct
import time
import zlib
from collections import deque
from multiprocessing import shared_memory

__all__ = [
    "LocalCounters",
    "RateLimiter",
    "SharedCounters",
    "client_key",
    "retry_after_seconds",
]

logger = logging.getLogger("echocorn.ratelimit")

#: How many slots a client's address may be looked for before the table counts
#: as full for it.  Four is enough at any sane load factor and keeps the request
#: path at a constant cost.
PROBES = 4

#: Seconds a mutex may be held before the request stops waiting for it.  A
#: holder only ever does arithmetic on a slot, so anything longer means a worker
#: died with the mutex in its hand.  Windows gets a longer bound because its
#: mutexes are kernel objects that a busy process is scheduled out of very
#: differently: measured there, a millisecond is short enough to be hit by
#: ordinary contention (and every hit means a decision counted per worker).
LOCK_TIMEOUT = 0.005 if os.name == "nt" else 0.001

#: Requests between two sweeps of the table, and slots examined by one.  A
#: sweep is housekeeping, not a decision, so it is spread thin: at these numbers
#: a table the size of the default one is walked in seconds under traffic and
#: costs a request nothing measurable.
SWEEP_EVERY = 64
SWEEP_STEP = 4

#: The smallest table worth having.  Fewer slots than this and the probes of
#: :data:`PROBES` would run into each other, so the count is a floor, not a
#: suggestion - a huge ``peak`` in a small ``cache_size`` is refused at startup
#: rather than served badly.
MIN_SLOTS = 256

#: What one client costs in the in-memory counters, so ``cache_size`` megabytes
#: can be turned into a number of addresses for the one-process limiter.
BYTES_PER_CLIENT = 256

#: One slot: the address, when its window and lockout end, the one burst of the
#: window, how many requests are counted, and where the oldest of them sits in
#: the ring of ``peak + 1`` timestamps that follows the head.  A decision reads
#: and writes the two ends of that ring, so its cost does not depend on how many
#: requests the client is allowed.
SLOT_HEAD = "<B16sddII5x"
SLOT_HEAD_SIZE = struct.calcsize(SLOT_HEAD)

#: One timestamp, in the ring after the head.
SLOT_TIMESTAMP = "d"


def slot_size(peak: int) -> int:
    """Bytes one client costs: the head, plus every timestamp that can matter."""
    return SLOT_HEAD_SIZE + struct.calcsize(SLOT_TIMESTAMP) * (peak + 1)


def slot_count(cache_size_mb: int, peak: int) -> int:
    """How many clients fit in ``cache_size_mb`` megabytes (never fewer than
    :data:`MIN_SLOTS`, which is what the probing on the request path needs)."""
    budget = max(1, int(cache_size_mb)) * 1024 * 1024
    return max(MIN_SLOTS, budget // slot_size(peak))


def effective_peak(requests: int, peak: int) -> int:
    """``peak`` as the limiter understands it: a spike, never below the limit."""
    requests = max(1, int(requests))
    return requests if peak < requests else int(peak)


def client_key(peername: object) -> str:
    """Return the address a request is counted against (``"-"`` when unknown)."""
    if not peername:
        return "-"
    return str(peername[0])


def retry_after_seconds(wait: float) -> int:
    """
    Whole seconds to advertise in ``Retry-After`` (RFC 9110 section 10.2.3).

    The delay-seconds form is used rather than an HTTP-date: it needs no clock
    agreement and is what every client understands.  A refused request always
    waits at least one second, so the header never says "retry now".
    """
    return max(1, int(math.ceil(wait)))


def pack_client(key: str) -> bytes:
    """
    The address as bytes: four for IPv4, sixteen for IPv6.

    Anything that is not an address (a Unix socket peer, an unexpected name) is
    stored as up to sixteen bytes of its text, which is all the slot has room
    for; the length is kept beside it so those are never confused with IPv4.
    """
    if ":" in key:
        try:
            return socket.inet_pton(socket.AF_INET6, key)
        except OSError:
            return key.encode("latin-1", "replace")[:16]
    try:
        return socket.inet_pton(socket.AF_INET, key)
    except OSError:
        return key.encode("latin-1", "replace")[:16]


class LocalCounters:
    """
    The sliding window of one process, in a dictionary.

    ``requests`` is the allowance per ``window`` seconds, ``peak`` how far a
    single burst inside one window may go (0 or anything below ``requests``
    means "no burst"), and ``ban`` how long a client that went past the burst is
    refused (0 disables the lockout, so the client is only held back until the
    window slides past its oldest request).
    """

    __slots__ = (
        "requests",
        "peak",
        "window",
        "ban",
        "_hits",
        "_bursts",
        "_bans",
        "_next_sweep",
        "_capacity",
    )

    #: How many clients may be remembered at once before the oldest is dropped.
    DEFAULT_CAPACITY = 128 * 1024 * 1024 // BYTES_PER_CLIENT

    def __init__(self, requests: int, peak: int, window: float, ban: float, *, capacity: int | None = None) -> None:
        self.requests = max(1, int(requests))
        self.peak = effective_peak(self.requests, int(peak))
        self.window = float(window) if window > 0 else 1.0
        self.ban = max(0.0, float(ban))
        #: client -> timestamps of its requests inside the current window.
        self._hits: dict[str, deque[float]] = {}
        #: client -> when it last used its one burst of the window.
        self._bursts: dict[str, float] = {}
        #: client -> when its lockout ends.
        self._bans: dict[str, float] = {}
        self._next_sweep = 0.0
        self._capacity = max(1024, int(capacity)) if capacity else self.DEFAULT_CAPACITY

    def consume(self, client: str, now: float) -> float | None:
        """
        Count one request of ``client``.

        Returns ``None`` when the request may be served, otherwise how many
        seconds the client has to wait: the caller answers ``429`` with that as
        its ``Retry-After``.  The request is counted either way, except while a
        lockout is in force - those refusals are deliberately not recorded, so a
        client that hammers through its lockout starts from a clean window once
        it is over instead of being refused all over again.
        """
        banned_until = self._bans.get(client)
        if banned_until is not None:
            if now < banned_until:
                return banned_until - now
            del self._bans[client]

        self._maybe_sweep(now)
        hits = self._hits.get(client)
        if hits is None:
            if len(self._hits) >= self._capacity:
                self._evict_oldest()
            hits = self._hits[client] = deque()

        edge = now - self.window
        while hits and hits[0] <= edge:
            hits.popleft()
        # A client that is already over its allowance is refused whatever it
        # does next, so remembering more of its requests could not change a
        # decision - and would let a fast one grow this deque without bound.
        if len(hits) < self.peak + 1:
            hits.append(now)
        count = len(hits)

        if count <= self.requests:
            return None

        if count <= self.peak:
            burst = self._bursts.get(client)
            if burst is None or now - burst >= self.window:
                # One burst per window: the peak is what a single spike may
                # reach, not a second, larger allowance.
                self._bursts[client] = now
                return None

        return self._refuse(client, now, hits)

    def _refuse(self, client: str, now: float, hits: deque[float]) -> float:
        """Record the refusal and return how long the client has to wait."""
        if self.ban > 0:
            self._bans[client] = now + self.ban
            return self.ban
        # Without a lockout the client is simply held back until the oldest
        # request of its window ages out and the window has room again.
        return max(0.0, hits[0] + self.window - now) if hits else 0.0

    def _evict_oldest(self) -> None:
        """
        Drop the counters of the client that has been known for the longest.

        A client under a lockout is skipped as long as there is anything else to
        drop: forgetting a lockout would let it straight back in.
        """
        chosen: str | None = None
        for client in itertools.islice(self._hits, 64):
            if client not in self._bans:
                chosen = client
                break
        if chosen is None:
            chosen = next(iter(self._hits), None)
        if chosen is None:
            return
        del self._hits[chosen]
        self._bursts.pop(chosen, None)
        self._bans.pop(chosen, None)

    def _maybe_sweep(self, now: float) -> None:
        """
        Forget clients whose window, burst and lockout have all expired.

        Without this the counters of every address that ever connected would
        stay in memory for the lifetime of the process.  The sweep runs at most
        once per window - never once per request, even under a flood - and a
        crowded table only makes it run at least once a second.
        """
        if now < self._next_sweep and len(self._hits) < 8192:
            return
        self._next_sweep = now + max(self.window, 1.0)
        edge = now - self.window
        for client in [name for name, hits in self._hits.items() if not hits or hits[-1] <= edge]:
            del self._hits[client]
        for client in [name for name, burst in self._bursts.items() if now - burst >= self.window]:
            del self._bursts[client]
        for client in [name for name, until in self._bans.items() if now >= until]:
            del self._bans[client]


class SharedCounters:
    """
    The rate limit counters of every worker, in one shared memory table.

    The master (:meth:`create`) builds the segment and the shard mutexes and
    hands both to its workers, which attach to them by name (:meth:`attach`).
    A worker that dies with a mutex in its hand cannot block the others for
    longer than :data:`LOCK_TIMEOUT`; the request is then counted in that
    worker's own memory, which keeps the server serving and is reported through
    :attr:`stats`.
    """

    def __init__(self, *, window: float, requests: int, peak: int, ban: float, slots: int, shards: int, name: str | None = None, shm: object = None, locks: list[object] | None = None, owned: bool = False) -> None:
        self.window = float(window) if window > 0 else 1.0
        self.requests = max(1, int(requests))
        self.peak = effective_peak(self.requests, int(peak))
        self.ban = max(0.0, float(ban))
        self.slots = max(MIN_SLOTS, int(slots))
        self.shards = max(1, int(shards))
        self.size = slot_size(self.peak)
        self.name = name
        self.owned = owned
        self.shm = shm
        self.buf: object = None
        self.locks: list[object] = locks if locks is not None else []
        #: Clients counted in this process because the table was not usable for
        #: them at that moment (a held mutex, or a shard run of full slots).
        self.local = LocalCounters(self.requests, self.peak, self.window, self.ban)
        #: What went wrong, so an operator can see a degraded limiter.
        self.stats: dict[str, int] = {
            "timeouts": 0,
            "overflow": 0,
            "swept": 0,
            "decisions": 0,
        }
        self._warned = 0
        #: One timestamp at a time: the window is a ring, so a decision touches
        #: only its ends.  (A formatter per window size used to be kept ready
        #: instead, which cost ``peak + 1`` structs per worker - hundreds of
        #: kilobytes each for a large allowance - and still copied the whole
        #: window on every request.)
        self._timestamp = struct.Struct("<" + SLOT_TIMESTAMP)
        self._head = struct.Struct(SLOT_HEAD)
        #: How often and how much this table sweeps itself (see :meth:`_sweep`).
        self.sweep_every = SWEEP_EVERY
        self.sweep_step = SWEEP_STEP
        self._sweep_cursor = 0
        self._since_sweep = 0

    # Lifecycle
    @classmethod
    def create(cls, config: object, *, name: str | None = None) -> "SharedCounters":
        """Create the table this server's workers will count into."""
        peak = effective_peak(config.ratelimit_requests, config.ratelimit_peak)
        slots = slot_count(config.ratelimit_cache_size, peak)
        size = slot_size(peak)
        name = name or "echocorn-rl-%d-%s" % (os.getpid(), os.urandom(4).hex())
        try:
            shm = shared_memory.SharedMemory(create=True, size=size * slots, name=name)
        except OSError:
            # A segment left behind by a dead master with the same name (the
            # name carries the pid and four random bytes): remove it rather than
            # count into somebody else's memory.
            try:
                stale = shared_memory.SharedMemory(name=name)
                stale.close()
                stale.unlink()
            except OSError:  # pragma: no cover - it went away by itself
                pass
            shm = shared_memory.SharedMemory(create=True, size=size * slots, name=name)
        locks = [multiprocessing.Lock() for _ in range(max(1, int(config.ratelimit_shards)))]
        return cls(
            window=config.ratelimit_window,
            requests=config.ratelimit_requests,
            peak=peak,
            ban=config.ratelimit_ban,
            slots=slots,
            shards=len(locks),
            name=name,
            shm=shm,
            locks=locks,
            owned=True,
        )

    @classmethod
    def attach(cls, name: str, locks: list[object], config: object) -> "SharedCounters":
        """Map the table a master created, as one of its workers."""
        peak = effective_peak(config.ratelimit_requests, config.ratelimit_peak)
        slots = slot_count(config.ratelimit_cache_size, peak)
        size = slot_size(peak)
        shm = shared_memory.SharedMemory(name=name)
        # The segment is allocated in whole pages, so it is never smaller than
        # asked for and often a little larger.
        if shm.size < size * slots:
            shm.close()
            raise ValueError("the shared rate limit table is %d bytes, expected at least %d" % (shm.size, size * slots))
        return cls(
            window=config.ratelimit_window,
            requests=config.ratelimit_requests,
            peak=peak,
            ban=config.ratelimit_ban,
            slots=slots,
            shards=len(locks),
            name=name,
            shm=shm,
            locks=list(locks),
            owned=False,
        )

    def start(self) -> bool:
        """
        Map the segment into this process.

        Returns False when the memory cannot be mapped at all, which leaves the
        caller counting per worker instead of refusing to serve.
        """
        if self.shm is None:
            return False
        try:
            self.buf = self.shm.buf
        except Exception:  # pragma: no cover - depends on the platform
            return False
        return True

    @property
    def running(self) -> bool:
        """True once the table is mapped and usable."""
        return self.buf is not None

    def close(self) -> None:
        """Unmap the table, and remove it when this process created it."""
        self.buf = None
        shm, self.shm = self.shm, None
        if shm is None:
            return
        try:
            shm.close()
        except Exception:
            pass
        if self.owned:
            try:
                shm.unlink()
            except Exception:
                pass

    # The request path
    def consume(self, client: str, now: float) -> float | None:
        """
        Count one request, exactly once for the whole server.

        ``None`` allows the request; anything else is how long the client has to
        wait.  The shard mutex is held for the arithmetic on one slot and
        nothing more - no allocation, no syscall, no copy of the table.
        """
        buf = self.buf
        if buf is None:
            return self.local.consume(client, now)
        self.stats["decisions"] += 1
        packed = pack_client(client)
        digest = zlib.crc32(packed)
        head = self._head
        wanted = len(packed)
        for step in range(PROBES):
            index = (digest + step) % self.slots
            at = index * self.size
            lock = self.locks[index % self.shards]
            if not lock.acquire(timeout=LOCK_TIMEOUT):
                self._degrade("timeouts", "a mutex was held for over %.0f ms" % (LOCK_TIMEOUT * 1000))
                return self.local.consume(client, now)
            try:
                length, key, ban_until, burst, count, oldest = head.unpack_from(buf, at)
                if length == 0:
                    # A free slot: this client's window starts here.
                    result = self._decide(buf, at, packed, 0, 0.0, 0.0, 0, now)
                    break
                if length == wanted and key[:wanted] == packed:
                    result = self._decide(buf, at, packed, count, ban_until, burst, oldest, now)
                    break
            finally:
                lock.release()
        else:
            # Every slot of the run belongs to somebody else: the table is far
            # too small for the traffic, so this process counts on its own.
            self._degrade("overflow", "every slot of a run is taken (%d probes)" % PROBES)
            return self.local.consume(client, now)
        self._since_sweep += 1
        if self._since_sweep >= self.sweep_every:
            self._since_sweep = 0
            self._sweep(now)
        return result

    def _decide(self, buf: object, at: int, packed: bytes, count: int, ban_until: float, burst: float, oldest: int, now: float) -> float | None:
        """
        Apply the window to one slot, exactly as :meth:`LocalCounters.consume`.

        The timestamps of the window are a ring of ``peak + 1`` doubles after
        the head, ``oldest`` being where its first one sits.  A request drops
        what aged out from the front, writes itself at the back, and reads the
        same two ends again for the decision - so the work is the same whether
        the client is allowed two requests or two thousand, which is what keeps
        a large allowance from turning every request into a copy of the window.

        The two implementations must not drift apart, and a test drives both
        with the same sequence of requests and compares every decision and every
        wait.
        """
        if ban_until and now < ban_until:
            return ban_until - now

        timestamp = self._timestamp
        ring = self.peak + 1
        base = at + SLOT_HEAD_SIZE
        edge = now - self.window
        while count and timestamp.unpack_from(buf, base + oldest * 8)[0] <= edge:
            oldest = (oldest + 1) % ring
            count -= 1
        # A client that is already over its allowance is refused whatever it
        # does next, so a full ring is left as it is instead of making room.
        if count < ring:
            timestamp.pack_into(buf, base + ((oldest + count) % ring) * 8, now)
            count += 1

        wait: float | None = None
        if count <= self.requests:
            pass
        elif count <= self.peak and (not burst or now - burst >= self.window):
            # One burst per window: the peak is what a single spike may reach,
            # not a second, larger allowance.
            burst = now
        elif self.ban > 0:
            ban_until = now + self.ban
            wait = self.ban
        else:
            # Without a lockout the client is simply held back until the oldest
            # request of its window ages out and the window has room again.
            wait = max(0.0, timestamp.unpack_from(buf, base + oldest * 8)[0] + self.window - now) if count else 0.0

        self._head.pack_into(buf, at, len(packed), packed, ban_until, burst, count, oldest)
        return wait

    def _sweep(self, now: float) -> None:
        """
        Clear a couple of slots that have aged out, so the table cannot fill up.

        Called once every :attr:`sweep_every` requests, after the request's own
        mutex is released: this walks the table one index at a time, takes the
        mutex of the shard it is about to look at, and gives up at once if
        somebody else has it (the slot is simply visited on a later pass).  A
        table the size of the default one is walked in seconds under traffic,
        and nothing is swept at all when the server is idle.
        """
        buf = self.buf
        if buf is None:  # pragma: no cover - close() only runs at shutdown
            return
        edge = now - self.window
        for _ in range(self.sweep_step):
            index = self._sweep_cursor
            self._sweep_cursor = (index + 1) % self.slots
            lock = self.locks[index % self.shards]
            if not lock.acquire(False):
                continue
            try:
                at = index * self.size
                length, _key, ban_until, _burst, count, oldest = self._head.unpack_from(buf, at)
                if not length:
                    continue
                if ban_until and ban_until > now:
                    continue
                if count:
                    # The newest request of the window is the one behind the
                    # oldest, wraparound and all.
                    ring = self.peak + 1
                    last = self._timestamp.unpack_from(buf, at + SLOT_HEAD_SIZE + ((oldest + count - 1) % ring) * 8)[0]
                    if last > edge:
                        continue
                self._head.pack_into(buf, at, 0, b"", 0.0, 0.0, 0, 0)
                self.stats["swept"] += 1
            finally:
                lock.release()

    def _degrade(self, kind: str, reason: str) -> None:
        """Report that a request was counted in this process alone."""
        self.stats[kind] += 1
        if self._warned < 1:
            self._warned += 1
            logger.warning(
                "The shared rate limit table could not be used (%s); that request, and any "
                "other one like it, is counted in this worker alone",
                reason,
            )


class RateLimiter:
    """
    The limiter of one worker: the counters, wherever they live.

    ``workers = 1`` counts in memory and nothing is shared.  With more workers
    the master builds a :class:`SharedCounters` table, every worker attaches to
    it, and the allowance is the server's instead of one per process.
    """

    __slots__ = ("requests", "peak", "window", "ban", "shared", "local", "_clock")

    def __init__(self, requests: int, peak: int, window: float, ban: float, *, shared: SharedCounters | None = None, capacity: int | None = None) -> None:
        self.requests = max(1, int(requests))
        self.peak = effective_peak(self.requests, int(peak))
        self.window = float(window) if window > 0 else 1.0
        self.ban = max(0.0, float(ban))
        self.shared = shared
        self.local = shared.local if shared is not None else LocalCounters(self.requests, self.peak, self.window, self.ban, capacity=capacity)
        # Within one process the monotonic clock is the right one (it cannot
        # jump); counters in shared memory need a clock every process agrees on,
        # so a shared limiter reads the wall clock instead.
        self._clock = time.time if shared is not None else time.monotonic

    @property
    def _hits(self) -> dict[str, deque[float]]:
        """The window of this process (empty while the counters are shared)."""
        return self.local._hits

    @classmethod
    def from_config(cls, config: object, shared: SharedCounters | None = None) -> "RateLimiter" | None:
        """
        Build the limiter a configuration asks for, or ``None`` when off.

        The shared table itself is created by whoever starts the workers (see
        :func:`echocorn.server.main`): this only decides whether to count with
        one.  A single worker has nothing to share, so it never gets one.
        """
        if not config.ratelimit_enabled:
            return None
        cache_size = int(getattr(config, "ratelimit_cache_size", 0) or 0)
        capacity = max(1024, cache_size * 1024 * 1024 // BYTES_PER_CLIENT) if cache_size else None
        return cls(
            config.ratelimit_requests,
            config.ratelimit_peak,
            config.ratelimit_window,
            config.ratelimit_ban,
            shared=shared,
            capacity=capacity,
        )

    def start(self) -> bool:
        """Make the shared table usable, when there is one."""
        if self.shared is None:
            return True
        return self.shared.start()

    def close(self) -> None:
        """Stop using the shared counters, when there are any."""
        if self.shared is not None:
            self.shared.close()

    def check(self, client: str, now: float | None = None) -> float | None:
        """
        Count one request of ``client``.

        Returns ``None`` when the request may be served, otherwise how many
        seconds the client has to wait: the caller answers ``429`` with that as
        its ``Retry-After``.
        """
        if now is None:
            now = self._clock()
        if self.shared is not None and self.shared.buf is not None:
            return self.shared.consume(client, now)
        return self.local.consume(client, now)
