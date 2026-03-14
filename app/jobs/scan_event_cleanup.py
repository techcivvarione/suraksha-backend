from __future__ import annotations

import logging
import threading
from sqlalchemy import text

from app.db import SessionLocal

logger = logging.getLogger(__name__)

_cleanup_thread: threading.Thread | None = None
_stop_event = threading.Event()


def cleanup_scan_events() -> int:
    db = SessionLocal()
    try:
        result = db.execute(
            text(
                """
                DELETE FROM scan_events
                WHERE created_at < now() - interval '10 minutes'
                """
            )
        )
        db.commit()
        return int(result.rowcount or 0)
    finally:
        db.close()


def start_scan_event_cleanup_worker() -> None:
    global _cleanup_thread
    if _cleanup_thread and _cleanup_thread.is_alive():
        return
    _stop_event.clear()
    _cleanup_thread = threading.Thread(target=_cleanup_loop, name="scan-event-cleanup", daemon=True)
    _cleanup_thread.start()


def stop_scan_event_cleanup_worker() -> None:
    _stop_event.set()


def _cleanup_loop() -> None:
    while not _stop_event.is_set():
        try:
            deleted = cleanup_scan_events()
            if deleted:
                logger.info("scan_event_cleanup_deleted=%s", deleted)
        except Exception:
            logger.exception("scan_event_cleanup_failed")
        _stop_event.wait(120)
