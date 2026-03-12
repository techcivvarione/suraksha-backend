from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def log_alert_event(
    *,
    alert_event_id: int | None,
    user_id: str,
    trigger_type: str,
    delivery_method: str,
    status: str,
) -> None:
    logger.info(
        "alert_event_delivery",
        extra={
            "alert_event_id": alert_event_id,
            "user_id": user_id,
            "trigger_type": trigger_type,
            "delivery_method": delivery_method,
            "status": status,
        },
    )
