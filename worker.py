from __future__ import annotations

import logging
import time

from sqlalchemy import text

from app.core.logging_setup import configure_logging
from app.core.monitoring import init_sentry
from app.db import SessionLocal
from app.services.redis_store import distributed_lock
from app.services.threat_intel_service import ingest_threat_events


configure_logging()
init_sentry()
logger = logging.getLogger(__name__)


def _cleanup_scan_events() -> int:
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


def run_forever() -> None:
    last_cleanup = 0.0
    last_ingestion = 0.0

    while True:
        now = time.monotonic()

        if now - last_cleanup >= 120:
            deleted = _cleanup_scan_events()
            if deleted:
                logger.info("scan_event_cleanup_completed", extra={"deleted": deleted})
            last_cleanup = now

        if now - last_ingestion >= 300:
            with distributed_lock("worker:threat-ingestion", ttl_seconds=240) as acquired:
                if acquired:
                    result = ingest_threat_events()
                    logger.info(
                        "threat_ingestion_completed",
                        extra={
                            "inserted": result.inserted,
                            "abuseipdb_count": result.abuseipdb_count,
                            "spamhaus_count": result.spamhaus_count,
                            "fallback_count": result.fallback_count,
                        },
                    )
                else:
                    logger.info("threat_ingestion_skipped_lock_held")
            last_ingestion = now

        time.sleep(1)


if __name__ == "__main__":
    run_forever()
