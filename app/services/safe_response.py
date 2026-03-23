"""
safe_response.py
================
Central safe-fallback helpers used by every scan route and middleware.

Rules
-----
- NEVER raise an exception.
- ALWAYS return a usable, user-friendly payload.
- All helpers are pure functions with no I/O.
"""
from __future__ import annotations

import uuid
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Generic scan fallback (used by /scan/email, /scan/threat, /scan/image)
# ---------------------------------------------------------------------------

_SAFE_RISK_SCORE  = 50
_SAFE_RISK_LEVEL  = "MEDIUM"
_SAFE_SUMMARY     = "We couldn't fully analyze this safely. Please be cautious."
_SAFE_HIGHLIGHTS  = ["Analysis could not be completed"]
_SAFE_RECOMMEND   = "Avoid clicking links or sharing sensitive data."


def safe_scan_response(
    *,
    scan_id: Optional[uuid.UUID] = None,
    analysis_type: str = "UNKNOWN",
    endpoint: str = "unknown",
) -> dict:
    """
    Return a safe MEDIUM-risk fallback dict that satisfies ScanResponse schema.
    Caller can return this directly from any route handler.
    """
    logger.warning(
        "safe_scan_response_used",
        extra={"endpoint": endpoint, "analysis_type": analysis_type},
    )
    return {
        "scan_id":       str(scan_id or uuid.uuid4()),
        "analysis_type": analysis_type,
        "risk_score":    _SAFE_RISK_SCORE,
        "score":         _SAFE_RISK_SCORE,
        "risk_level":    _SAFE_RISK_LEVEL,
        "status":        "completed",
        "confidence":    0.5,
        "reasons":       _SAFE_HIGHLIGHTS,
        "recommendation": _SAFE_RECOMMEND,
        # Extra fields used by /scan/image
        "summary":       _SAFE_SUMMARY,
        "highlights":    _SAFE_HIGHLIGHTS,
        "technical_signals": [],
        "confidence_label":  "Low",
    }


# ---------------------------------------------------------------------------
# QR-specific fallback — satisfies QrAnalyzeResponse schema
# ---------------------------------------------------------------------------

def safe_qr_response(*, reason: str = "Analysis unavailable") -> dict:
    """
    Return a safe MEDIUM-risk fallback dict that satisfies QrAnalyzeResponse.
    """
    logger.warning("safe_qr_response_used", extra={"reason": reason})
    return {
        "qr_hash":           "0" * 64,
        "risk_score":        _SAFE_RISK_SCORE,
        "risk_level":        _SAFE_RISK_LEVEL,
        "detected_type":     "UNKNOWN",
        "reasons":           [reason, "Please verify the QR code source before proceeding."],
        "recommended_action": _SAFE_RECOMMEND,
        "is_flagged":        False,
        "is_payment":        False,
        "merchant_name":     None,
        "upi_id":            None,
        "amount":            None,
        "summary":           _SAFE_SUMMARY,
    }


# ---------------------------------------------------------------------------
# QR report fallback — satisfies QrReportResponse schema
# ---------------------------------------------------------------------------

def safe_qr_report_response() -> dict:
    """Return a safe fallback for /qr/report failures."""
    logger.warning("safe_qr_report_response_used")
    return {
        "qr_hash":        "0" * 64,
        "message":        "Report received. We'll review it shortly.",
        "reported_count": 0,
        "is_flagged":     False,
    }


# ---------------------------------------------------------------------------
# Middleware-level fallback (used when the entire request pipeline crashes)
# ---------------------------------------------------------------------------

def safe_middleware_response() -> dict:
    """
    Minimal JSON body returned by the security middleware when call_next()
    itself throws.  Status code is always 200 — the app never returns 500.
    """
    return {
        "success": False,
        "error":   "INTERNAL_SAFE_ERROR",
        "message": "Something went wrong. Please try again.",
    }
