"""
Targeted PCAP capture triggered by the intelligence layer.

When an anomalous src-dst pair is detected (by intelligence scanning or
high/critical incident creation), this module starts a short ``tcpdump``
capture for that specific traffic pair and auto-ingests the resulting
PCAP file through the analysis pipeline.

Thread-safe: multiple triggers can run concurrently up to
``max_concurrent``.
"""
from __future__ import annotations

import logging
import os
import subprocess
import threading
import uuid
from datetime import datetime
from typing import Dict, Optional

logger = logging.getLogger("pcap_trigger")


class PcapTrigger:
    """Manages targeted PCAP captures via tcpdump subprocesses."""

    def __init__(
        self,
        capture_dir: str,
        interface: str,
        duration_seconds: int = 30,
        max_concurrent: int = 5,
    ):
        self.capture_dir = capture_dir
        self.interface = interface
        self.duration_seconds = duration_seconds
        self.max_concurrent = max_concurrent
        self._active: Dict[str, subprocess.Popen] = {}
        self._lock = threading.Lock()

        os.makedirs(capture_dir, exist_ok=True)

    def trigger(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: Optional[int] = None,
        reason: str = "",
    ) -> Optional[str]:
        """Start a targeted PCAP capture for the given IP pair.

        Returns the filepath of the capture, or None if skipped
        (duplicate, limit reached, or no interface configured).
        """
        if not self.interface:
            logger.debug("PCAP trigger skipped — no interface configured")
            return None

        trigger_key = f"{src_ip}_{dst_ip}_{dst_port or 'any'}"

        with self._lock:
            if trigger_key in self._active:
                logger.debug("PCAP trigger skipped — already capturing for %s", trigger_key)
                return None

            if len(self._active) >= self.max_concurrent:
                logger.debug("PCAP trigger skipped — max concurrent (%d) reached", self.max_concurrent)
                return None

            # Build BPF filter
            if dst_port:
                bpf = f"host {src_ip} and host {dst_ip} and port {dst_port}"
            else:
                bpf = f"host {src_ip} and host {dst_ip}"

            # Build filename
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            safe_src = src_ip.replace(".", "-")
            safe_dst = dst_ip.replace(".", "-")
            filename = f"triggered_{safe_src}_{safe_dst}_{ts}.pcap"
            filepath = os.path.join(self.capture_dir, filename)

            # Start tcpdump
            cmd = [
                "tcpdump",
                "-i", self.interface,
                "-w", filepath,
                "-G", str(self.duration_seconds),
                "-W", "1",
                bpf,
            ]

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
            except FileNotFoundError:
                logger.error("tcpdump not found — PCAP trigger disabled")
                return None
            except Exception as e:
                logger.error("Failed to start tcpdump: %s", e)
                return None

            self._active[trigger_key] = proc

        logger.info(
            "PCAP trigger started: %s → %s (port=%s, reason=%s, file=%s)",
            src_ip, dst_ip, dst_port or "any", reason or "auto", filename,
        )

        # Monitor thread — waits for subprocess to finish
        monitor = threading.Thread(
            target=self._monitor,
            args=(trigger_key, proc, filepath, src_ip, dst_ip, reason),
            name=f"pcap-monitor-{trigger_key}",
            daemon=True,
        )
        monitor.start()

        return filepath

    def _monitor(
        self,
        trigger_key: str,
        proc: subprocess.Popen,
        filepath: str,
        src_ip: str,
        dst_ip: str,
        reason: str,
    ) -> None:
        """Wait for the tcpdump process to finish, then clean up."""
        try:
            proc.wait()
        except Exception:
            pass
        finally:
            with self._lock:
                self._active.pop(trigger_key, None)

        self._on_capture_complete(filepath, src_ip, dst_ip, reason)

    def _on_capture_complete(
        self,
        filepath: str,
        src_ip: str,
        dst_ip: str,
        reason: str,
    ) -> None:
        """Process a completed capture file — auto-ingest if non-empty."""
        if not os.path.exists(filepath):
            logger.warning("Triggered PCAP file not found: %s", filepath)
            return

        size = os.path.getsize(filepath)
        if size == 0:
            logger.info("Triggered PCAP is empty (no matching traffic), removing: %s", filepath)
            os.remove(filepath)
            return

        logger.info(
            "Triggered PCAP complete: %s (%d bytes) — auto-ingesting",
            filepath, size,
        )

        # Auto-ingest through the analysis pipeline
        try:
            from database import AnalysisModel, SessionLocal
            from jobs.queue import enqueue

            analysis_id = str(uuid.uuid4())
            db = SessionLocal()
            try:
                analysis = AnalysisModel(
                    id=analysis_id,
                    user_id=1,  # admin
                    filename=os.path.basename(filepath),
                    file_path=filepath,
                    status="pending",
                )
                db.add(analysis)
                db.commit()
                enqueue(db, analysis_id)
                logger.info("Auto-ingested triggered PCAP: %s (analysis=%s)", filepath, analysis_id)

                # Link analysis to originating incident
                _link_to_incident(db, analysis_id, src_ip)
            except Exception:
                db.rollback()
                logger.exception("Failed to auto-ingest PCAP: %s", filepath)
            finally:
                db.close()
        except Exception:
            logger.exception("Failed to import analysis modules for auto-ingest")

    def stats(self) -> dict:
        """Return current trigger statistics."""
        with self._lock:
            return {
                "active_captures": len(self._active),
                "max_concurrent": self.max_concurrent,
                "interface": self.interface,
                "duration_seconds": self.duration_seconds,
            }


def _link_to_incident(db, analysis_id: str, src_ip: str) -> None:
    """Link a triggered PCAP analysis to the originating open/investigating incident."""
    import json as _json
    from database import LiveIncidentModel

    try:
        incident = (
            db.query(LiveIncidentModel)
            .filter(
                LiveIncidentModel.source_ip == src_ip,
                LiveIncidentModel.status.in_(("open", "investigating")),
            )
            .order_by(LiveIncidentModel.last_seen.desc())
            .first()
        )
        if not incident:
            return

        # Append analysis_id to linked list
        existing_ids = _json.loads(incident.linked_pcap_analysis_ids or "[]")
        if analysis_id not in existing_ids:
            existing_ids.append(analysis_id)
            incident.linked_pcap_analysis_ids = _json.dumps(existing_ids)

        # Increment counter
        incident.pcap_trigger_count = (incident.pcap_trigger_count or 0) + 1

        # Update activity summary
        from datetime import datetime as _dt
        ts = _dt.utcnow().strftime("%H:%M:%S")
        incident.last_activity_summary = (
            f"{incident.last_activity_summary or ''} "
            f"(PCAP captured at {ts})"
        ).strip()

        db.commit()
        logger.info(
            "Linked analysis %s to incident %d (source_ip=%s)",
            analysis_id, incident.id, src_ip,
        )
    except Exception:
        logger.exception("Failed to link analysis %s to incident", analysis_id)
