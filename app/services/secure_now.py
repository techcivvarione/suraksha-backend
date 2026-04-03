from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session


SECURE_NOW_TEMPLATES: dict[str, tuple[str, str, str]] = {
    "THREAT": ("SCAM_MESSAGE", "Ignore scam message", "Do not reply, click links, or share details from this suspicious message."),
    "EMAIL": ("SCAM_EMAIL", "Ignore the suspicious email", "Do not open links or attachments. Verify through the official website or app."),
    "IMAGE": ("FAKE_MEDIA", "Do not trust this media", "Avoid forwarding or acting on this suspicious image or media result."),
    "QR": ("RISKY_QR", "Do not scan or pay via this QR", "Use the official merchant app or verify the payment handle before paying."),
    "PASSWORD": ("WEAK_PASSWORD", "Change password", "Create a strong, unique password and avoid reusing it anywhere else."),
    "SOS": ("CYBER_SOS", "Start Cyber SOS now", "Contact your bank, block risky activity, and follow the urgent protection steps immediately."),
}


def create_secure_item(
    db: Session,
    *,
    user_id,
    item_type: str,
    title: str,
    description: str,
    risk_level: str = "high",
    source_scan_id: str | None = None,
) -> dict:
    item_id = str(uuid.uuid4())
    db.execute(
        text(
            """
            INSERT INTO secure_now_items (
                id,
                user_id,
                source_scan_id,
                type,
                title,
                description,
                status,
                risk_level,
                auto_created,
                created_at
            )
            VALUES (
                CAST(:id AS uuid),
                CAST(:user_id AS uuid),
                CAST(NULLIF(:source_scan_id, '') AS uuid),
                :type,
                :title,
                :description,
                'PENDING',
                :risk_level,
                true,
                now()
            )
            ON CONFLICT DO NOTHING
            """
        ),
        {
            "id": item_id,
            "user_id": str(user_id),
            "source_scan_id": source_scan_id or "",
            "type": item_type,
            "title": title,
            "description": description,
            "risk_level": risk_level,
        },
    )
    db.commit()
    return {
        "id": item_id,
        "type": item_type,
        "title": title,
        "description": description,
        "status": "PENDING",
        "risk_level": risk_level,
    }


def create_secure_item_for_scan(
    db: Session,
    *,
    user_id,
    analysis_type: str,
    risk_score: int,
    source_scan_id: str | None = None,
) -> dict | None:
    if int(risk_score or 0) < 70:
        return None

    item_type, title, description = SECURE_NOW_TEMPLATES.get(
        str(analysis_type or "").upper(),
        ("HIGH_RISK_ACTION", "Review this threat now", "Do not act on the risky content until you verify it through an official source."),
    )

    return create_secure_item(
        db,
        user_id=user_id,
        item_type=item_type,
        title=title,
        description=description,
        risk_level="high",
        source_scan_id=source_scan_id,
    )
