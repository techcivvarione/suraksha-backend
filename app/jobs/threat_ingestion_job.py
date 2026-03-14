from __future__ import annotations

import logging
import threading

from app.services.threat_intel_service import ingest_threat_events

logger = logging.getLogger(__name__)

_worker_thread: threading.Thread | None = None
_stop_event = threading.Event()


def run_threat_ingestion_once() -> None:
    result = ingest_threat_events()
    logger.info(
        "threat_ingestion inserted=%s abuseipdb=%s spamhaus=%s fallback=%s",
        result.inserted,
        result.abuseipdb_count,
        result.spamhaus_count,
        result.fallback_count,
    )


def start_threat_ingestion_worker() -> None:
    global _worker_thread
    if _worker_thread and _worker_thread.is_alive():
        return
    _stop_event.clear()
    _worker_thread = threading.Thread(target=_worker_loop, name="threat-ingestion", daemon=True)
    _worker_thread.start()


def stop_threat_ingestion_worker() -> None:
    _stop_event.set()


def _worker_loop() -> None:
    while not _stop_event.is_set():
        try:
            run_threat_ingestion_once()
        except Exception:
            logger.exception("threat_ingestion_failed")
        _stop_event.wait(300)
