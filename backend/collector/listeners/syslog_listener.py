"""
UDP + TCP syslog listener for the live ingestion layer.

Binds to a configurable port (default 5514 — non-privileged) and feeds
every received line into the collector ``Pipeline``.  Runs as a pair of
daemon threads (one for UDP, one for TCP) so the main FastAPI process
stays responsive.

Design notes:

- **UDP** is the primary path — most firewalls default to UDP syslog.
  Each datagram is one log line.
- **TCP** handles devices that send RFC 6587 octet-counted or newline-
  delimited syslog over a persistent connection.  Each connection is
  served in its own short-lived thread (acceptable at the expected
  throughput of < 10k events/sec).
- The listener does NOT parse — it hands raw lines to ``Pipeline``.
- A ``flush_interval`` timer fires periodically to push the pipeline's
  in-memory buffer to the database even when inbound traffic is slow.

Usage::

    from collector.listeners.syslog_listener import SyslogListener

    listener = SyslogListener(pipeline=pipe, db_factory=get_db, port=5514)
    listener.start()   # spawns daemon threads
    ...
    listener.stop()    # graceful shutdown
"""
from __future__ import annotations

import logging
import socket
import socketserver
import threading
import time
from typing import Callable, Optional

from collector.pipeline import Pipeline

logger = logging.getLogger("collector.syslog")

# Defaults
DEFAULT_PORT = 5514
DEFAULT_BIND = "0.0.0.0"
DEFAULT_FLUSH_INTERVAL = 1.0   # seconds
DEFAULT_BATCH_SIZE = 100       # flush when buffer reaches this


class SyslogListener:
    """Manages UDP + TCP syslog receivers and a periodic flush timer.

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
    """

    def __init__(
        self,
        pipeline: Pipeline,
        db_factory: Callable,
        host: str = DEFAULT_BIND,
        port: int = DEFAULT_PORT,
        flush_interval: float = DEFAULT_FLUSH_INTERVAL,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ):
        self.pipeline = pipeline
        self.db_factory = db_factory
        self.host = host
        self.port = port
        self.flush_interval = flush_interval
        self.batch_size = batch_size

        self._udp_server: Optional[socketserver.BaseServer] = None
        self._tcp_server: Optional[socketserver.BaseServer] = None
        self._flush_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start both listeners and the flush timer as daemon threads."""
        if self._running:
            return
        self._running = True

        # UDP listener
        self._udp_server = _UDPServer(
            (self.host, self.port),
            _UDPHandler,
            pipeline=self.pipeline,
            listener=self,
        )
        t_udp = threading.Thread(
            target=self._udp_server.serve_forever,
            name="syslog-udp",
            daemon=True,
        )
        t_udp.start()
        logger.info("Syslog UDP listener started on %s:%d", self.host, self.port)

        # TCP listener
        self._tcp_server = _TCPServer(
            (self.host, self.port),
            _TCPHandler,
            pipeline=self.pipeline,
            listener=self,
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
        """Gracefully shut down listeners and flush remaining buffer."""
        self._running = False
        if self._udp_server:
            self._udp_server.shutdown()
            self._udp_server = None
        if self._tcp_server:
            self._tcp_server.shutdown()
            self._tcp_server = None
        # Final flush
        self._do_flush()
        logger.info("Syslog listener stopped")

    @property
    def running(self) -> bool:
        return self._running

    # ── Line ingestion (called by handlers) ──────────────────────────────────

    def ingest(self, line: str) -> None:
        """Process one raw syslog line and buffer the result."""
        event = self.pipeline.process_line(line)
        if event is None:
            return
        with self._lock:
            self.pipeline.buffer(event)
        if self.pipeline.buffer_size >= self.batch_size:
            self._do_flush()

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
# We attach the Pipeline + SyslogListener references to the server instance
# so the request handlers can access them without globals.

class _UDPServer(socketserver.UDPServer):
    allow_reuse_address = True

    def __init__(self, addr, handler, *, pipeline, listener):
        self.pipeline = pipeline
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
            self.server.listener.ingest(line)


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, *, pipeline, listener):
        self.pipeline = pipeline
        self.listener = listener
        super().__init__(addr, handler)


class _TCPHandler(socketserver.StreamRequestHandler):
    """Handle one TCP syslog connection (newline-delimited lines)."""

    def handle(self):
        for raw in self.rfile:
            try:
                line = raw.decode("utf-8", errors="replace").strip()
            except Exception:
                continue
            if line:
                self.server.listener.ingest(line)
