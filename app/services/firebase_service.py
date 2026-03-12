from __future__ import annotations

import json
import logging
import os

import firebase_admin
from firebase_admin import credentials, messaging

logger = logging.getLogger(__name__)

_SERVICE_ACCOUNT_ENV = "FIREBASE_SERVICE_ACCOUNT_JSON"


def _initialize_firebase() -> None:
    if firebase_admin._apps:
        return
    raw_credentials = os.getenv(_SERVICE_ACCOUNT_ENV, "").strip()
    if not raw_credentials:
        raise RuntimeError(
            f"Firebase service account JSON not found in environment variable {_SERVICE_ACCOUNT_ENV}"
        )
    try:
        credential_payload = json.loads(raw_credentials)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Invalid Firebase service account JSON in environment variable {_SERVICE_ACCOUNT_ENV}"
        ) from exc
    cred = credentials.Certificate(credential_payload)
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
