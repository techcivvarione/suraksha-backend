import logging
import uuid

logger = logging.getLogger(__name__)


def log_scan_event(
    scan_id: uuid.UUID,
    user_id: str,
    scan_type: str,
    risk_score: int,
    endpoint: str | None = None,
    plan: str | None = None,
    media_size: int | None = None,
    provider_used: str | None = None,
):
    """
    Structured audit log without raw input.
    """
    logger.info(
        "scan_event",
        extra={
            "scan_id": str(scan_id),
            "user_id": user_id,
            "scan_type": scan_type,
            "risk_score": risk_score,
            "endpoint": endpoint,
            "plan": plan,
            "media_size": media_size,
            "provider_used": provider_used,
        },
    )
