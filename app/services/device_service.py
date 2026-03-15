from __future__ import annotations

import uuid

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import engine
from app.models.user_device import UserDevice


def ensure_user_devices_table() -> None:
    UserDevice.__table__.create(bind=engine, checkfirst=True)


def register_device(user_id: str, device_token: str, device_type: str, db: Session) -> None:
    ensure_user_devices_table()

    existing = db.execute(
        text(
            """
            SELECT user_id
            FROM user_devices
            WHERE device_token = :device_token
            LIMIT 1
            """
        ),
        {"device_token": device_token},
    ).first()
    if existing and str(existing[0]) != str(user_id):
        raise HTTPException(status_code=409, detail="Device token is already registered to another account")

    db.execute(
        text(
            """
            INSERT INTO user_devices (
                id,
                user_id,
                device_token,
                device_type,
                created_at,
                updated_at
            )
            VALUES (
                CAST(:id AS uuid),
                CAST(:user_id AS uuid),
                :device_token,
                :device_type,
                now(),
                now()
            )
            ON CONFLICT (device_token)
            DO UPDATE SET
                user_id = EXCLUDED.user_id,
                device_type = EXCLUDED.device_type,
                updated_at = now()
            WHERE user_devices.user_id = EXCLUDED.user_id
            """
        ),
        {
            "id": str(uuid.uuid4()),
            "user_id": str(user_id),
            "device_token": device_token,
            "device_type": device_type,
        },
    )
    db.commit()
