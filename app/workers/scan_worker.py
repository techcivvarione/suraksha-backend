from __future__ import annotations

import logging
import time

from app.db import SessionLocal
from app.services.scan_jobs import claim_next_pending_job, ensure_scan_jobs_table, process_scan_job

logger = logging.getLogger(__name__)


class ScanWorker:
    def __init__(self, idle_sleep_seconds: float = 2.0):
        self.idle_sleep_seconds = idle_sleep_seconds

    def run_once(self) -> bool:
        db = SessionLocal()
        try:
            job = claim_next_pending_job(db)
            if not job:
                return False
            logger.info("scan_job_claimed", extra={"job_id": str(job.id), "scan_type": job.scan_type})
            process_scan_job(db, job)
            return True
        except Exception:
            logger.exception("scan_worker_run_once_error")
            return False
        finally:
            db.close()

    def run_forever(self) -> None:
        ensure_scan_jobs_table()
        logger.info("scan_worker_loop_started", extra={"idle_sleep_seconds": self.idle_sleep_seconds})
        while True:
            try:
                processed = self.run_once()
            except Exception:
                logger.exception("scan_worker_loop_error")
                processed = False
            if not processed:
                time.sleep(self.idle_sleep_seconds)
