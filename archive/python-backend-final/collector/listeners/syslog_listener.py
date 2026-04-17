"""
UDP + TCP syslog listener for the live ingestion layer.

Binds to a configurable port (default 5514 — non-privileged) and feeds
every received line into the collector ``Pipeline``.  Designed for
high-throughput ingestion (target: 10 000+ events/sec).

Architecture
------------

  ┌──────────┐   ┌──────────┐
  │  UDP rx  │   │  TCP rx  │  (socket threads — fast, no parsing)
  └────┬─────┘   └────┬─────┘
       │              │
       ▼              ▼
  ┌────────────────────────┐
  │   RateLimiter check    │   per-IP token bucket
  └────────────┬───────────┘
               │ (allowed)
               ▼
  ┌────────────────────────┐
  │  queue.Queue (50 000)  │   raw line strings
  └──────────┬─────────────┘
             │
             ▼
  ┌──────────────────────┐
  │  Consumer thread     │   pipeline.process_line() + buffer()
  └──────────┬───────────┘
             │
             ▼
  ┌──────────────────────┐
  │  Flush timer / batch │   pipeline.flush(db)
  └──────────────────────┘

Network I/O (UDP recv / TCP read) is decoupled from CPU-bound parsing
via an in-process queue.  When the queue is full the listener
increments ``dropped_count`` instead of blocking — back-pressure
from the parser must never stall the socket threads.

A ``RateLimiter`` (token-bucket per source IP) sits in front of the
queue so a single noisy device cannot drown out everyone else.

TCP connections are served via a ``ThreadPoolExecutor`` (default 20
workers) instead of one-thread-per-connection, capping resource usage
under connection storms.

Usage::

    from collector.listeners.syslog_listener import SyslogListener

    listener = SyslogListener(pipeline=pipe, db_factory=get_db, port=5514)
    listener.start()   # spawns daemon threads
    ...
    listener.stop()    # graceful shutdown
"""
from __future__ import annotations

import collections
import logging
import queue
import socket
import socketserver
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

from collector.pipeline import Pipeline

logger = logging.getLogger("collector.syslog")

# Defaults
DEFAULT_PORT = 5514
DEFAULT_BIND = "0.0.0.0"
DEFAULT_FLUSH_INTERVAL = 1.0       # seconds
DEFAULT_BATCH_SIZE = 100           # flush when buffer reaches this
DEFAULT_QUEUE_SIZE = 50_000        # max queued raw lines
DEFAULT_TCP_WORKERS = 20           # ThreadPoolExecutor size
DEFAULT_MAX_EPS = 5000             # global events-per-second cap
DEFAULT_PER_IP_MAX_EPS = 500       # per source-IP events-per-second cap


# ── Token-bucket rate limiter ────────────────────────────────────────────────

class RateLimiter:
    """Per-IP token-bucket rate limiter.

    Each source IP gets its own bucket that refills at ``per_ip_max_eps``
    tokens per second.  A global bucket caps total throughput across all
    IPs at ``max_eps``.

    Thread-safe: all state is guarded by ``_lock``.
    """

    def __init__(
        self,
        max_eps: int = DEFAULT_MAX_EPS,
        per_ip_max_eps: int = DEFAULT_PER_IP_MAX_EPS,
    ):
        self.max_eps = max_eps
        self.per_ip_max_eps = per_ip_max_eps
        self._lock = threading.Lock()
        # Per-IP buckets: {ip: [tokens_remaining, last_refill_time]}
        self._buckets: dict = collections.defaultdict(lambda: [0.0, 0.0])
        # Global bucket
        self._global_tokens = float(max_eps)
        self._global_last = time.monotonic()

    def allow(self, ip: str) -> bool:
        """Return True if *ip* is within both its per-IP and the global
        rate limit.  Consumes one token from each bucket on success."""
        now = time.monotonic()
        with self._lock:
            # Refill global bucket
            elapsed_g = now - self._global_last
            self._global_tokens = min(
                float(self.max_eps),
                self._global_tokens + elapsed_g * self.max_eps,
            )
            self._global_last = now
            if self._global_tokens < 1.0:
                return False

            # Refill per-IP bucket
            bucket = self._buckets[ip]
            if bucket[1] == 0.0:
                # First time seeing this IP — initialise
                bucket[0] = float(self.per_ip_max_eps)
                bucket[1] = now
            else:
                elapsed_ip = now - bucket[1]
                bucket[0] = min(
                    float(self.per_ip_max_eps),
                    bucket[0] + elapsed_ip * self.per_ip_max_eps,
                )
                bucket[1] = now

            if bucket[0] < 1.0:
                return False

            # Consume tokens
            self._global_tokens -= 1.0
            bucket[0] -= 1.0
            return True


# ── Syslog listener ──────────────────────────────────────────────────────────

class SyslogListener:
    """Manages UDP + TCP syslog receivers, rate limiter, processing queue,
    and a periodic flush timer.

    Parameters
    ----------
    pipeline : Pipeline
        The shared Pipeline instance that lines are fed into.
    db_factory : callable
        A zero-arg callable that returns a new SQLAlchemy Session (e.g.
        ``database.SessionLocal``).  Each flush cycle opens and closes
        its own session so we don't hold a long-lived connection.
    host : str
        Bind address (default "0.0.0.0").
    port : int
        Listen port (default 5514).
    flush_interval : float
        Seconds between periodic buffer flushes.
    batch_size : int
        Flush immediately when the buffer reaches this size.
    queue_size : int
        Max raw lines the processing queue can hold before dropping.
    tcp_workers : int
        Number of threads in the TCP connection pool.
    max_eps : int
        Global events-per-second cap.
    per_ip_max_eps : int
        Per source-IP events-per-second cap.
    """

    def __init__(
        self,
        pipeline: Pipeline,
        db_factory: Callable,
        host: str = DEFAULT_BIND,
        port: int = DEFAULT_PORT,
        flush_interval: float = DEFAULT_FLUSH_INTERVAL,
        batch_size: int = DEFAULT_BATCH_SIZE,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        tcp_workers: int = DEFAULT_TCP_WORKERS,
        max_eps: int = DEFAULT_MAX_EPS,
        per_ip_max_eps: int = DEFAULT_PER_IP_MAX_EPS,
    ):
        self.pipeline = pipeline
        self.db_factory = db_factory
        self.host = host
        self.port = port
        self.flush_interval = flush_interval
        self.batch_size = batch_size

        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._dropped_count = 0
        self._dropped_lock = threading.Lock()
        self._rate_limited_count = 0
        self._rate_limited_lock = threading.Lock()

        self.rate_limiter = RateLimiter(
            max_eps=max_eps,
            per_ip_max_eps=per_ip_max_eps,
        )

        self._tcp_workers = tcp_workers
        self._udp_server: Optional[socketserver.BaseServer] = None
        self._tcp_server: Optional[socketserver.BaseServer] = None
        self._consumer_thread: Optional[threading.Thread] = None
        self._flush_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start both listeners, the consumer thread, and the flush timer."""
        if self._running:
            return
        self._running = True

        # Consumer thread (reads from queue → pipeline)
        self._consumer_thread = threading.Thread(
            target=self._consume_loop,
            name="syslog-consumer",
            daemon=True,
        )
        self._consumer_thread.start()

        # UDP listener
        self._udp_server = _UDPServer(
            (self.host, self.port),
            _UDPHandler,
            listener=self,
        )
        t_udp = threading.Thread(
            target=self._udp_server.serve_forever,
            name="syslog-udp",
            daemon=True,
        )
        t_udp.start()
        logger.info("Syslog UDP listener started on %s:%d", self.host, self.port)

        # TCP listener (ThreadPoolExecutor-backed)
        self._tcp_server = _TCPServer(
            (self.host, self.port),
            _TCPHandler,
            listener=self,
            max_workers=self._tcp_workers,
        )
        self._tcp_server.socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1,
        )
        t_tcp = threading.Thread(
            target=self._tcp_server.serve_forever,
            name="syslog-tcp",
            daemon=True,
        )
        t_tcp.start()
        logger.info("Syslog TCP listener started on %s:%d", self.host, self.port)

        # Periodic flush timer
        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            name="syslog-flush",
            daemon=True,
        )
        self._flush_thread.start()

    def stop(self) -> None:
        """Gracefully shut down listeners, drain the queue, and flush."""
        self._running = False
        if self._udp_server:
            self._udp_server.shutdown()
            self._udp_server = None
        if self._tcp_server:
            self._tcp_server.shutdown()
            self._tcp_server = None
        # Drain remaining queue items
        self._drain_queue()
        # Final flush
        self._do_flush()
        logger.info("Syslog listener stopped")

    @property
    def running(self) -> bool:
        return self._running

    @property
    def dropped_count(self) -> int:
        return self._dropped_count

    @property
    def rate_limited_count(self) -> int:
        return self._rate_limited_count

    # ── Line ingestion (called by socket handlers) ───────────────────────────

    def ingest(self, line: str, source_ip: str = "0.0.0.0") -> None:
        """Check the rate limiter, then enqueue a raw syslog line.

        Non-blocking: if rate-limited or the queue is full the line is
        skipped and the appropriate counter is incremented.
        """
        if not self.rate_limiter.allow(source_ip):
            with self._rate_limited_lock:
                self._rate_limited_count += 1
            return
        try:
            self._queue.put_nowait(line)
        except queue.Full:
            with self._dropped_lock:
                self._dropped_count += 1

    # ── Consumer (queue → pipeline) ──────────────────────────────────────────

    def _consume_loop(self) -> None:
        """Drain the queue, parse each line, and buffer the result."""
        while self._running:
            try:
                line = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            self._process_one(line)
            # Check batch threshold after each line
            if self.pipeline.buffer_size >= self.batch_size:
                self._do_flush()

    def _drain_queue(self) -> None:
        """Process any remaining items after the listener has stopped."""
        while True:
            try:
                line = self._queue.get_nowait()
            except queue.Empty:
                break
            self._process_one(line)

    def _process_one(self, line: str) -> None:
        event = self.pipeline.process_line(line)
        if event is None:
            return
        with self._lock:
            self.pipeline.buffer(event)

    # ── Flush ────────────────────────────────────────────────────────────────

    def _flush_loop(self) -> None:
        while self._running:
            time.sleep(self.flush_interval)
            self._do_flush()

    def _do_flush(self) -> None:
        with self._lock:
            if self.pipeline.buffer_size == 0:
                return
            db = self.db_factory()
            try:
                n = self.pipeline.flush(db)
                if n:
                    logger.debug("Flushed %d events to DB", n)
            except Exception:
                logger.exception("Failed to flush events to DB")
                db.rollback()
            finally:
                db.close()


# ── socketserver subclasses ──────────────────────────────────────────────────

class _UDPServer(socketserver.UDPServer):
    allow_reuse_address = True

    def __init__(self, addr, handler, *, listener):
        self.listener = listener
        super().__init__(addr, handler)


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        try:
            line = data.decode("utf-8", errors="replace").strip()
        except Exception:
            return
        if line:
            src_ip = self.client_address[0] if self.client_address else "0.0.0.0"
            self.server.listener.ingest(line, source_ip=src_ip)


class _TCPServer(socketserver.TCPServer):
    """TCP server backed by a shared ``ThreadPoolExecutor`` instead of
    one-thread-per-connection.

    ``process_request`` submits the handler to the pool; the pool size
    caps concurrent connections.  ``shutdown_request`` is still called
    by the base class after the handler returns.
    """
    allow_reuse_address = True

    def __init__(self, addr, handler, *, listener, max_workers):
        self.listener = listener
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="syslog-tcp",
        )
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        self._pool.submit(self.process_request_thread, request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

    def server_close(self):
        super().server_close()
        self._pool.shutdown(wait=False)


class _TCPHandler(socketserver.StreamRequestHandler):
    """Handle one TCP syslog connection (newline-delimited lines)."""

    def handle(self):
        src_ip = self.client_address[0] if self.client_address else "0.0.0.0"
        for raw in self.rfile:
            try:
                line = raw.decode("utf-8", errors="replace").strip()
            except Exception:
                continue
            if line:
                self.server.listener.ingest(line, source_ip=src_ip)
