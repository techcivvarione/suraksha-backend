from __future__ import annotations

import json
import logging
import multiprocessing
import os
import tempfile
import time
import uuid
from pathlib import Path
from queue import Empty as _QueueEmpty

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import engine
from app.models.scan_job import ScanJob
from app.models.user import User
from app.services.alert_rate_limiter import AlertRateLimiterError, enforce_alert_limits
from app.services.scan_logger import log_scan_event
from app.services.security_alerts import create_alert_event, dispatch_plan_alerts
from app.services.security_plan_limits import allows_realtime_alerts
from app.services.storage_service import delete_file, download_file

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Timing and size limits
# ---------------------------------------------------------------------------
# Wall-clock budget for the child detection process.  Keep this low enough
# that the job is always marked "failed" BEFORE the frontend's polling window
# expires (see POLL_MAX_ATTEMPTS / POLL_INTERVAL_MS in ScanRepositoryImpl.kt).
#
# Budget breakdown (worst case):
#   worker pick-up delay       ≤ 2 s
#   file download              ≤ 2 s
#   subprocess spawn (spawn)   ≤ 2 s
#   detection timeout below  → 15 s
#   DB commit                  ≤ 1 s
#   ─────────────────────────────────
#   total                      ≤ 22 s   < frontend 25 s window (10 × 2.5 s)
_DETECTION_TIMEOUT_SECONDS = 15

# Reject files larger than this before even writing to disk.  The route layer
# already enforces 10 MB at upload time; this is a defence-in-depth guard.
_MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB

# Grace period after SIGTERM before we escalate to SIGKILL.
_KILL_GRACE_SECONDS = 3

# Fields that must be present in every result dict returned by the child
# process.  If any are absent the payload is treated as a failure so the
# frontend never receives a partially-populated result card.
_REQUIRED_RESULT_FIELDS: frozenset[str] = frozenset({
    "risk_score",
    "risk_level",
    "confidence",
    "reasons",
    "recommendation",
})


def _scan_failure_payload() -> dict:
    """Return a complete, UI-safe result for any job that could not be processed.

    Every field that the frontend ScanMapper / ScanJobResult parser reads must be
    present so the app never renders null values or "UNKNOWN" risk levels.
    """
    return {
        "status": "failed",
        "error_code": "SCAN_FAILED",
        "message": "Scan could not complete",
        "risk_score": 0,
        "score": 0,
        "risk_level": "LOW",        # score 0 → LOW; never emit "UNKNOWN"
        "confidence": 0.5,          # conservative — we genuinely don't know
        "ai_probability": 0.0,
        "reasons": ["Scan could not complete in time"],
        "signals": ["Scan could not complete in time"],
        "recommendation": "Try again with a smaller or different file",
        "ai_explanation": None,
        "ocr_text_preview": None,
    }

_SCAN_TYPE_TO_ENDPOINT = {
    "image": "/scan/reality/image",
    "video": "/scan/reality/video",
    "audio": "/scan/reality/audio",
}

_SCAN_TYPE_TO_MIME = {
    "image": {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".webp": "image/webp",
    },
    "video": {
        ".mp4": "video/mp4",
        ".webm": "video/webm",
    },
    "audio": {
        ".mp3": "audio/mpeg",
        ".wav": "audio/wav",
    },
}


def ensure_scan_jobs_table() -> None:
    ScanJob.__table__.create(bind=engine, checkfirst=True)


def create_scan_job(db: Session, *, user_id, file_path: str, scan_type: str) -> ScanJob:
    ensure_scan_jobs_table()
    job = ScanJob(
        user_id=uuid.UUID(str(user_id)),
        file_path=file_path,
        scan_type=scan_type,
        status="pending",
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def get_scan_job_for_user(db: Session, *, job_id: str, user_id) -> ScanJob | None:
    ensure_scan_jobs_table()
    return (
        db.query(ScanJob)
        .filter(ScanJob.id == uuid.UUID(str(job_id)), ScanJob.user_id == uuid.UUID(str(user_id)))
        .first()
    )


def claim_next_pending_job(db: Session) -> ScanJob | None:
    ensure_scan_jobs_table()
    with db.begin():
        job = (
            db.query(ScanJob)
            .filter(ScanJob.status == "pending")
            .order_by(ScanJob.created_at.asc())
            .with_for_update(skip_locked=True)
            .first()
        )
        if not job:
            return None
        job.status = "processing"
        db.add(job)
    db.refresh(job)
    return job


def process_scan_job(db: Session, job: ScanJob) -> None:
    started_at = time.monotonic()
    logger.info(
        "scan_job_start",
        extra={"job_id": str(job.id), "scan_type": job.scan_type, "user_id": str(job.user_id)},
    )
    temp_path = None
    # Tracks whether "completed" has been successfully committed to the DB.
    # Guarded by the finally-style pattern below so that a failure in
    # post-processing (alerts, scan-event logging) never overwrites an
    # already-committed "completed" row with "failed".
    _wrote_final_status = False
    try:
        media_bytes = download_file(job.file_path)

        # Reject files that are too large before spending time on analysis.
        if len(media_bytes) > _MAX_FILE_BYTES:
            raise ValueError(
                f"File too large: {len(media_bytes):,} bytes "
                f"(limit {_MAX_FILE_BYTES // (1024 * 1024)} MB)"
            )

        temp_path = _write_temp_media(job, media_bytes)

        # Spawn a child process for detection.  The process can be hard-killed
        # on timeout (unlike a thread).  TimeoutError is re-raised and caught
        # by the outer except block which marks the job as "failed".
        try:
            result = _run_detection_with_timeout(job, temp_path)
        except TimeoutError:
            elapsed = time.monotonic() - started_at
            logger.warning(
                "scan_job_timeout",
                extra={
                    "job_id": str(job.id),
                    "scan_type": job.scan_type,
                    "elapsed_seconds": round(elapsed, 2),
                    "timeout_seconds": _DETECTION_TIMEOUT_SECONDS,
                },
            )
            raise  # escalate to the outer except → marks job as failed

        payload = json.dumps(result)

        with db.begin():
            job.status = "completed"
            job.result_json = payload
            db.add(job)
            _insert_scan_history(db, job=job, result=result)
        # Only set the flag AFTER the transaction commits successfully.
        # If _insert_scan_history() or the commit itself raises, the
        # transaction rolls back and _wrote_final_status stays False,
        # so the except block will correctly write "failed".
        _wrote_final_status = True

        elapsed = time.monotonic() - started_at
        logger.info(
            "scan_job_complete",
            extra={
                "job_id": str(job.id),
                "scan_type": job.scan_type,
                "risk_score": result.get("risk_score"),
                "risk_level": result.get("risk_level"),
                "provider_used": result.get("provider_used"),
                "elapsed_seconds": round(elapsed, 2),
            },
        )

        _trigger_realtime_alerts(db, job=job, result=result)

        log_scan_event(
            scan_id=job.id,
            user_id=str(job.user_id),
            scan_type=result["analysis_type"],
            risk_score=int(result["risk_score"]),
            endpoint=_SCAN_TYPE_TO_ENDPOINT[job.scan_type],
            media_size=_file_size(temp_path),
            provider_used=result.get("provider_used"),
        )
    except Exception as exc:
        elapsed = time.monotonic() - started_at
        if _wrote_final_status:
            # "completed" was already committed.  A post-processing error
            # (alerts, scan-event log, etc.) must NOT overwrite it with
            # "failed" — the client already has the correct result.
            logger.exception(
                "scan_job_post_processing_failed",
                extra={
                    "job_id": str(job.id),
                    "scan_type": job.scan_type,
                    "error": str(exc),
                    "elapsed_seconds": round(elapsed, 2),
                },
            )
        else:
            # Detection or pre-processing failed; guarantee "failed" in DB.
            # The nested try/except ensures a DB outage here cannot leave the
            # job stuck in "processing" indefinitely.
            logger.exception(
                "scan_job_failed",
                extra={
                    "job_id": str(job.id),
                    "scan_type": job.scan_type,
                    "error": str(exc),
                    "elapsed_seconds": round(elapsed, 2),
                },
            )
            try:
                with db.begin():
                    job.status = "failed"
                    job.result_json = json.dumps(_scan_failure_payload())
                    db.add(job)
            except Exception:
                logger.exception(
                    "scan_job_status_update_failed",
                    extra={"job_id": str(job.id)},
                )
    finally:
        try:
            delete_file(job.file_path)
        except Exception:
            logger.warning("scan_job_object_cleanup_failed", extra={"job_id": str(job.id), "object_key": job.file_path})
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                logger.warning("scan_job_file_cleanup_failed", extra={"job_id": str(job.id), "file_path": temp_path})


def _run_detection_with_timeout(job: ScanJob, file_path: str) -> dict:
    """Spawn a child process to run detection; hard-kill it if it exceeds the timeout.

    Why a process instead of a thread
    ----------------------------------
    Python threads cannot be forcefully stopped from outside.  A thread running
    cv2 / librosa / OpenAI can block indefinitely even after
    ``future.cancel()`` or ``TimeoutError`` is raised by the caller.  This
    means a hung thread-based approach leaves the job stuck in "processing"
    state despite the timeout guard appearing to fire.

    An OS process can be terminated with SIGTERM → SIGKILL, which guarantees:
    * No CPU/memory leak after timeout
    * No zombie processes (we call ``proc.join()`` after every exit path)
    * The DB is updated to "failed" exactly once, within the timeout budget

    Spawn vs fork
    -------------
    We use the ``spawn`` start method explicitly so the child starts with a
    clean Python interpreter.  This avoids ``fork``-induced deadlocks that can
    occur when forking from a multithreaded process (the worker daemon thread
    that calls this function runs alongside SQLAlchemy pool threads, uvicorn
    worker threads, etc.).
    """
    from app.workers.detection_process import run as _detection_run

    ctx = multiprocessing.get_context("spawn")
    result_queue: multiprocessing.Queue = ctx.Queue()

    proc = ctx.Process(
        target=_detection_run,
        args=(str(job.id), job.scan_type, file_path, result_queue),
        name=f"scan-detect-{job.id}",
        daemon=True,
    )

    detect_start = time.monotonic()
    proc.start()
    proc.join(timeout=_DETECTION_TIMEOUT_SECONDS)
    detect_elapsed = time.monotonic() - detect_start

    if proc.is_alive():
        # ----------------------------------------------------------------
        # Hard kill: SIGTERM first, then SIGKILL if process doesn't stop.
        #
        # Capture pid NOW — proc.close() below invalidates all proc attributes
        # (CPython raises ValueError: process object is closed on access).
        # ----------------------------------------------------------------
        _timeout_pid = proc.pid
        logger.warning(
            "scan_detect_process_timeout_kill",
            extra={
                "job_id": str(job.id),
                "scan_type": job.scan_type,
                "elapsed_seconds": round(detect_elapsed, 2),
                "timeout_seconds": _DETECTION_TIMEOUT_SECONDS,
                "pid": _timeout_pid,
            },
        )
        proc.terminate()
        proc.join(_KILL_GRACE_SECONDS)

        if proc.is_alive():
            logger.warning(
                "scan_detect_process_force_kill",
                extra={"job_id": str(job.id), "pid": _timeout_pid},
            )
            proc.kill()
            proc.join(1)

        # Reap zombie if the process has now exited; if it somehow survived
        # SIGKILL (not possible on Linux/Mac, extremely rare on Windows)
        # we skip close() and let the daemon flag handle cleanup on exit.
        if not proc.is_alive():
            proc.close()

        raise TimeoutError(
            f"Detection process killed after {_DETECTION_TIMEOUT_SECONDS}s "
            f"(pid={_timeout_pid})"
        )

    # ----------------------------------------------------------------
    # Process exited within the timeout — classify exit and read result.
    #
    # IMPORTANT: capture pid/exitcode BEFORE proc.close().
    # CPython's Process.close() sets an internal _closed flag; every
    # subsequent property access calls _check_closed() which raises
    # ValueError: process object is closed.
    # ----------------------------------------------------------------
    _pid = proc.pid
    _exitcode = proc.exitcode
    exit_outcome = "normal" if _exitcode == 0 else "crash"
    logger.info(
        "scan_detect_process_exited",
        extra={
            "job_id": str(job.id),
            "scan_type": job.scan_type,
            "pid": _pid,
            "exitcode": _exitcode,
            "exit_outcome": exit_outcome,          # "normal" | "crash"
            "elapsed_seconds": round(detect_elapsed, 2),
        },
    )
    proc.close()  # release OS resources; do NOT access proc attributes after this

    if _exitcode != 0:
        # Non-zero exit: process crashed (OOM, segfault, unhandled C-level
        # error).  detection_process.run() is supposed to catch everything and
        # push an ("error", …) tuple, but if the crash happened before that
        # (e.g. during import), the queue will be empty and the exit code is
        # our only signal.
        raise RuntimeError(
            f"Detection process crashed with exit code {_exitcode} (pid={_pid})"
        )

    # ----------------------------------------------------------------
    # Read result from queue.
    #
    # WHY get(timeout=2) instead of get_nowait():
    # multiprocessing.Queue uses an internal feeder thread to move bytes
    # from the child's put() call through the OS pipe to the parent's
    # in-memory buffer.  After proc.join() returns the bytes are in the
    # pipe but may not yet have been moved into the parent's buffer.
    # get_nowait() fires before that transfer completes on loaded systems.
    # get(timeout=2) gives the reader thread a 2-second window — well
    # within the budget since the child has already exited.
    #
    # NOTE: Queue.empty() is explicitly documented as unreliable for
    # multiprocessing queues (the docs say "Because of multithreading/
    # multiprocessing semantics, this is not reliable") and is NOT used.
    # ----------------------------------------------------------------
    try:
        tag, payload = result_queue.get(timeout=2)
    except _QueueEmpty:
        raise RuntimeError(
            f"Detection process (pid={_pid}, exitcode={_exitcode}) "
            "exited cleanly but produced no result in the queue"
        )

    if tag == "error":
        raise RuntimeError(f"Detection failed inside child process: {payload}")

    # ----------------------------------------------------------------
    # Validate that the payload contains every field the frontend needs.
    # A missing field means detection_process.run() produced an incomplete
    # result — treat this as a failure rather than returning a half-empty
    # result card to the user.
    # ----------------------------------------------------------------
    missing = _REQUIRED_RESULT_FIELDS - payload.keys()
    if missing:
        raise RuntimeError(
            f"Detection result is missing required fields: {sorted(missing)}"
        )

    return payload  # complete result dict built by detection_process.run()


def _insert_scan_history(db: Session, *, job: ScanJob, result: dict) -> None:
    db.execute(
        text(
            """
            INSERT INTO scan_history (
                id,
                user_id,
                input_text,
                risk,
                score,
                reasons,
                scan_type,
                created_at
            )
            VALUES (
                :id,
                :user_id,
                :input_text,
                :risk,
                :score,
                :reasons,
                :scan_type,
                now()
            )
            """
        ),
        {
            "id": str(job.id),
            "user_id": str(job.user_id),
            "input_text": f"{job.scan_type.upper()}_FILE_REDACTED",
            "risk": str(result["risk_level"]).lower(),
            "score": int(result["risk_score"]),
            "reasons": json.dumps(result.get("signals") or result.get("reasons") or []),
            "scan_type": result["analysis_type"],
        },
    )


def _file_size(path: str) -> int | None:
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def _write_temp_media(job: ScanJob, media_bytes: bytes) -> str:
    extension = _extension_for(job.file_path, job.scan_type)
    fd, path = tempfile.mkstemp(prefix="gosuraksha_scan_", suffix=extension)
    with os.fdopen(fd, "wb") as handle:
        handle.write(media_bytes)
    return path


def _extension_for(file_key: str, scan_type: str) -> str:
    extension = Path(file_key).suffix.lower()
    if extension:
        return extension
    return next(iter(_SCAN_TYPE_TO_MIME[scan_type].keys()))


def _trigger_realtime_alerts(db: Session, *, job: ScanJob, result: dict) -> None:
    risk_score = int(result.get("risk_score") or 0)
    if risk_score < 70:
        return

    user = db.query(User).filter(User.id == job.user_id).first()
    if not user or not allows_realtime_alerts(user.plan):
        return

    try:
        enforce_alert_limits(db, str(user.id), None, None)
        event = create_alert_event(
            db=db,
            user_id=user.id,
            trigger_type=f"{job.scan_type.upper()}_HIGH_RISK_SCAN",
            analysis_type=job.scan_type.upper(),
            risk_score=risk_score,
            media_hash=str(job.id).replace("-", ""),
        )
        dispatch_plan_alerts(
            db=db,
            user=user,
            trigger_type=f"{job.scan_type.upper()}_HIGH_RISK_SCAN",
            risk_score=risk_score,
            scan_id=str(job.id),
            alert_event_id=event.id,
        )
        event.status = "SENT"
        db.add(event)
        db.commit()
    except AlertRateLimiterError:
        logger.info("scan_job_realtime_alert_rate_limited", extra={"job_id": str(job.id), "user_id": str(job.user_id)})
    except Exception:
        logger.exception("scan_job_realtime_alert_failed", extra={"job_id": str(job.id), "user_id": str(job.user_id)})
