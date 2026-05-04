from __future__ import annotations

import json
import logging
import os

try:
    import firebase_admin
    from firebase_admin import credentials, messaging
except ImportError:  # pragma: no cover
    firebase_admin = None
    credentials = None
    messaging = None

logger = logging.getLogger(__name__)

firebase_app = None


def get_firebase():
    global firebase_app

    if firebase_admin is None or credentials is None:
        raise RuntimeError("firebase_admin is not installed")

    if firebase_app is not None:
        return firebase_app
    if firebase_admin._apps:
        firebase_app = firebase_admin.get_app()
        return firebase_app

    raw_credentials = os.environ.get("FIREBASE_SERVICE_ACCOUNT", "").strip()
    if not raw_credentials:
        raise RuntimeError("FIREBASE_SERVICE_ACCOUNT environment variable missing")
    try:
        service_account_info = json.loads(raw_credentials)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Invalid FIREBASE_SERVICE_ACCOUNT JSON") from exc
    cred = credentials.Certificate(service_account_info)
    firebase_app = firebase_admin.initialize_app(cred)
    logger.info("firebase_admin_initialized")
    return firebase_app


def send_push_notification(
    token: str,
    title: str,
    body: str,
    data: dict | None = None,
) -> str:
    if messaging is None:
        raise RuntimeError("firebase_admin is not installed")
    get_firebase()
    payload = {str(key): str(value) for key, value in (data or {}).items()}
    message = messaging.Message(token=token, notification=messaging.Notification(title=title, body=body), data=payload)
    message_id = messaging.send(message)
    logger.info("firebase_push_sent", extra={"message_id": message_id})
    return message_id
