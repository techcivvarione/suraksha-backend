from __future__ import annotations

import logging
from pathlib import Path

import firebase_admin
from firebase_admin import credentials, messaging

logger = logging.getLogger(__name__)

_SERVICE_ACCOUNT_PATH = (
    Path(__file__).resolve().parents[1] / "credentials" / "firebase_service_account.json"
)


def _initialize_firebase() -> None:
    if firebase_admin._apps:
        return
    if not _SERVICE_ACCOUNT_PATH.exists():
        raise RuntimeError(
            f"Firebase service account file not found at {_SERVICE_ACCOUNT_PATH}"
        )
    cred = credentials.Certificate(str(_SERVICE_ACCOUNT_PATH))
    firebase_admin.initialize_app(cred)


def send_push_notification(
    token: str,
    title: str,
    body: str,
    data: dict | None = None,
) -> str:
    _initialize_firebase()
    payload = {str(key): str(value) for key, value in (data or {}).items()}
    message = messaging.Message(
        token=token,
        notification=messaging.Notification(title=title, body=body),
        data=payload,
    )
    message_id = messaging.send(message)
    logger.info(
        "firebase_push_sent",
        extra={"token_prefix": token[:12], "message_id": message_id},
    )
    return message_id
