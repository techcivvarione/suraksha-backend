"""Subprocess entry-point for reality-scan detection.

This module is intentionally kept free of module-level heavy imports
(no DB connections, no model pre-loading, no global objects) so that
spawning a child process via ``multiprocessing.get_context("spawn").Process``
is nearly instant.

All expensive imports (cv2, librosa, PIL, RealityDetectionEngine …) are
deferred to the ``run()`` body, which executes only inside the child.
The parent process never calls ``run()`` directly.

Why this is a separate module and not a function in scan_jobs.py
---------------------------------------------------------------
With the ``spawn`` start method, the child re-imports the target function's
module from scratch.  If ``run`` lived in ``scan_jobs``, the child would also
execute ``scan_jobs``'s module-level statement::

    _engine = RealityDetectionEngine()

…creating three detector objects that are immediately discarded.  Keeping
the entry-point here avoids that double-initialisation entirely.

AI explanation is intentionally NOT generated here.
The parent (scan_jobs.py / API layer) may append it asynchronously after the
scan completes, but it must never block or slow the detection subprocess.
"""
from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Lightweight lookup tables (no imports needed).
# Values mirror ScanType enum strings so ``analysis_type`` in the result dict
# is identical to what ScanType.REALITY_*.value would produce.
# ---------------------------------------------------------------------------
_ANALYSIS_TYPE: dict[str, str] = {
    "image": "REALITY_IMAGE",
    "video": "REALITY_VIDEO",
    "audio": "REALITY_AUDIO",
}

_MIME_MAP: dict[str, dict[str, str]] = {
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

# ---------------------------------------------------------------------------
# Early-exit thresholds.
# If the model's ai_probability is above HIGH_THRESHOLD or below LOW_THRESHOLD
# there is no ambiguity — skip expensive post-processing (OCR) and return
# immediately with the corresponding risk level.
# ---------------------------------------------------------------------------
_EARLY_EXIT_HIGH_THRESHOLD = 0.85
_EARLY_EXIT_LOW_THRESHOLD = 0.15

# OCR is only useful in the "uncertain" band where text context may help a
# human reviewer make a decision.  Skip it outside that band.
_OCR_BAND_LOW = 0.30
_OCR_BAND_HIGH = 0.70


def _infer_mime(file_path: str, scan_type: str) -> str:
    ext = Path(file_path).suffix.lower()
    mime = _MIME_MAP.get(scan_type, {}).get(ext)
    if not mime:
        raise ValueError(f"Unsupported extension {ext!r} for scan_type={scan_type!r}")
    return mime


def _default_signal(scan_type: str, probability: float) -> str:
    labels = {"image": "Synthetic", "video": "Deepfake", "audio": "Voice synthesis"}
    return f"{labels.get(scan_type, 'Synthetic')} probability {probability:.2f}"


def _recommendation(scan_type: str, risk_level: str) -> str:
    if risk_level == "LOW":
        return {
            "image": "No strong manipulation signs detected.",
            "video": "No strong deepfake indicators detected.",
            "audio": "No strong synthetic indicators detected.",
        }.get(scan_type, "No strong indicators detected.")
    return {
        "image": "Treat with caution; verify source.",
        "video": "Do not trust this video without independent verification.",
        "audio": "Do not trust this audio without verification.",
    }.get(scan_type, "Treat with caution.")


def run(
    job_id: str,
    scan_type: str,
    file_path: str,
    result_queue,  # multiprocessing.Queue — typed loosely to avoid module-level import
) -> None:
    """Execute in the child process; push one item to *result_queue* before returning.

    The contract with the parent is strict:

    * Success  → ``result_queue.put(("ok",   result_dict))``
    * Failure  → ``result_queue.put(("error", error_message))``

    The function must NEVER raise — if it did, the parent would block on
    ``result_queue.get()`` forever (or until the process is killed, after
    which ``get_nowait`` would raise ``Empty`` — handled by the parent).

    Performance notes
    -----------------
    * Images are thumbnailed to 512 px (fast_mode=True in ImageDetector).
    * Video frame sampling is capped at 7 frames (fast_mode=True in FrameAnalyzer).
    * Early exit: probability ≥ 0.85 → HIGH risk returned immediately.
    * Early exit: probability ≤ 0.15 → LOW risk returned immediately.
    * OCR: only performed in the uncertain band 0.30 – 0.70 (images only).
    * AI explanation: NOT generated here; no OpenAI call inside the subprocess.
    """
    try:
        # ----------------------------------------------------------------
        # Heavy imports — paid once per child process.
        # ----------------------------------------------------------------
        from app.services.reality_detection import RealityDetectionEngine
        from app.services.ocr_service import OCRException, extract_text_from_image

        engine = RealityDetectionEngine()
        mime_type = _infer_mime(file_path, scan_type)

        if scan_type == "image":
            outcome = engine.analyze_image(file_path, mime_type, fast_mode=True)
        elif scan_type == "video":
            outcome = engine.analyze_video(file_path, mime_type, fast_mode=True)
        elif scan_type == "audio":
            outcome = engine.analyze_audio(file_path, mime_type, fast_mode=True)
        else:
            raise ValueError(f"Unsupported scan type: {scan_type!r}")

        probability = float(outcome.ai_probability)

        # ----------------------------------------------------------------
        # Early-exit: unambiguous HIGH / LOW — skip post-processing.
        # ----------------------------------------------------------------
        if probability >= _EARLY_EXIT_HIGH_THRESHOLD:
            risk_level = "HIGH"
        elif probability <= _EARLY_EXIT_LOW_THRESHOLD:
            risk_level = "LOW"
        else:
            risk_level = outcome.risk_level or "MEDIUM"

        signals: list[str] = (
            list(outcome.signals) if outcome.signals else [_default_signal(scan_type, probability)]
        )

        # ----------------------------------------------------------------
        # Conditional OCR preview (images only, uncertain band only).
        # Skipped entirely for early-exit cases and non-image scan types.
        # ----------------------------------------------------------------
        ocr_preview: str | None = None
        if scan_type == "image" and _OCR_BAND_LOW <= probability <= _OCR_BAND_HIGH:
            try:
                with open(file_path, "rb") as fh:
                    raw_text = extract_text_from_image(fh.read()).strip()
                ocr_preview = raw_text[:300] if raw_text else None
            except (OCRException, Exception):
                pass  # OCR failure must never abort the scan

        result_dict = {
            "scan_id": job_id,
            "analysis_type": _ANALYSIS_TYPE[scan_type],
            "risk_score": int(outcome.risk_score),
            "risk_level": risk_level,
            "confidence": probability,
            "ai_probability": probability,
            "risk": risk_level,
            "signals": signals,
            "reasons": signals,
            "recommendation": _recommendation(scan_type, risk_level),
            "provider_used": "internal-hybrid",
            "ocr_text_preview": ocr_preview,
            # ai_explanation intentionally omitted — not generated in subprocess.
            # The API layer or a background task may append it separately.
        }
        # Guard the put() itself: if pickling fails (non-serialisable value
        # sneaks in) or the pipe is broken we fall back to an error signal,
        # and if that also fails we exit with code 1 so the parent detects
        # a crash via proc.exitcode rather than hanging on get(timeout=2).
        try:
            result_queue.put(("ok", result_dict))
        except Exception as put_exc:
            try:
                result_queue.put(("error", f"Result serialisation failed: {put_exc}"))
            except Exception:
                import sys
                sys.exit(1)

    except Exception as exc:
        # Always send *something* so the parent's get(timeout=2) never
        # expires due to a missing result.  If the queue write itself fails
        # (broken pipe, serialisation error), exit with code 1 so the parent
        # can distinguish a clean-but-empty queue from a genuine crash.
        try:
            result_queue.put(("error", str(exc)))
        except Exception:
            import sys
            sys.exit(1)
