from fastapi import APIRouter, Depends
from pydantic import BaseModel
from datetime import datetime
import uuid

from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user

router = APIRouter(prefix="/alerts", tags=["Alerts"])


# ---------- MODELS ----------
class SubscribeRequest(BaseModel):
    categories: list[str]


# ---------- HELPERS ----------
def severity_for(category: str, alert_type: str) -> str:
    if alert_type == "history":
        return "HIGH"
    if category.lower() in ["cyber", "cyber crime", "ai", "govt"]:
        return "HIGH"
    if category.lower() in ["banking", "upi", "finance"]:
        return "MEDIUM"
    return "LOW"


# ---------- ROUTES ----------
@router.post("/subscribe")
def subscribe_alerts(
    payload: SubscribeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # 🔴 REMOVE OLD SUBSCRIPTIONS (FIXED)
    db.execute(
        text("""
            DELETE FROM alert_subscriptions
            WHERE user_id = CAST(:uid AS uuid)
        """),
        {"uid": str(current_user.id)},
    )

    # 🟢 INSERT NEW SUBSCRIPTIONS
    for category in payload.categories:
        db.execute(
            text("""
                INSERT INTO alert_subscriptions (
                    id, user_id, category, created_at
                )
                VALUES (
                    :id, CAST(:uid AS uuid), :cat, now()
                )
                ON CONFLICT DO NOTHING
            """),
            {
                "id": str(uuid.uuid4()),
                "uid": str(current_user.id),
                "cat": category,
            },
        )

    db.commit()
    return {"status": "subscribed", "categories": payload.categories}


@router.get("/")
def get_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = db.execute(
        text("""
            SELECT *
            FROM alerts
            WHERE user_id = CAST(:uid AS uuid)
            ORDER BY
                CASE severity
                    WHEN 'HIGH' THEN 1
                    WHEN 'MEDIUM' THEN 2
                    ELSE 3
                END,
                created_at DESC
        """),
        {"uid": str(current_user.id)},
    ).mappings().all()

    return {"count": len(rows), "alerts": rows}


@router.get("/refresh")
def refresh_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    created = 0

    # ---------- SUBSCRIPTIONS ----------
    subs = db.execute(
        text("""
            SELECT category
            FROM alert_subscriptions
            WHERE user_id = CAST(:uid AS uuid)
        """),
        {"uid": str(current_user.id)},
    ).scalars().all()

    if not subs:
        return {"status": "no_subscriptions", "new_alerts_created": 0}

    # ---------- NEWS → ALERTS ----------
    news_rows = db.execute(
        text("""
            SELECT id, headline, matter, category, source
            FROM news
            WHERE category = ANY(:cats)
            ORDER BY published_at DESC
            LIMIT 50
        """),
        {"cats": subs},
    ).mappings().all()

    for news in news_rows:
        exists = db.execute(
            text("""
                SELECT 1 FROM alerts
                WHERE user_id = CAST(:uid AS uuid)
                  AND source = :src
            """),
            {"uid": str(current_user.id), "src": news["source"]},
        ).first()

        if not exists:
            db.execute(
                text("""
                    INSERT INTO alerts (
                        id, user_id, type, title, message,
                        category, severity, source, read, created_at
                    )
                    VALUES (
                        :id, CAST(:uid AS uuid), 'news',
                        :title, :msg,
                        :cat, :sev, :src, false, now()
                    )
                """),
                {
                    "id": str(uuid.uuid4()),
                    "uid": str(current_user.id),
                    "title": news["headline"],
                    "msg": news["matter"],
                    "cat": news["category"],
                    "sev": severity_for(news["category"], "news"),
                    "src": news["source"],
                },
            )
            created += 1

    # ---------- HISTORY → ALERTS ----------
    rows = db.execute(
        text("""
            SELECT input_text
            FROM scan_history
            WHERE user_id = CAST(:uid AS uuid)
        """),
        {"uid": str(current_user.id)},
    ).scalars().all()

    keyword_count = {}
    for text_val in rows:
        t = text_val.lower()
        for k in ["otp", "upi", "bank", "lottery", "job"]:
            if k in t:
                keyword_count[k] = keyword_count.get(k, 0) + 1

    for k, count in keyword_count.items():
        if count >= 2:
            src = f"history-{k}"
            exists = db.execute(
                text("""
                    SELECT 1 FROM alerts
                    WHERE user_id = CAST(:uid AS uuid)
                      AND source = :src
                """),
                {"uid": str(current_user.id), "src": src},
            ).first()

            if not exists:
                db.execute(
                    text("""
                        INSERT INTO alerts (
                            id, user_id, type, title, message,
                            category, severity, source, read, created_at
                        )
                        VALUES (
                            :id, CAST(:uid AS uuid), 'history',
                            'Repeated scam pattern detected',
                            :msg,
                            'Personal Risk', 'HIGH',
                            :src, false, now()
                        )
                    """),
                    {
                        "id": str(uuid.uuid4()),
                        "uid": str(current_user.id),
                        "msg": f"You have repeatedly encountered {k.upper()} related scams.",
                        "src": src,
                    },
                )
                created += 1

    db.commit()
    return {"status": "refreshed", "new_alerts_created": created}


@router.get("/summary")
def alert_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = db.execute(
        text("""
            SELECT severity, COUNT(*)
            FROM alerts
            WHERE user_id = CAST(:uid AS uuid)
              AND read = false
            GROUP BY severity
        """),
        {"uid": str(current_user.id)},
    ).all()

    summary = {"high": 0, "medium": 0, "low": 0}
    for sev, count in rows:
        summary[sev.lower()] = count

    risk = "Low"
    if summary["high"] > 0:
        risk = "High"
    elif summary["medium"] > 0:
        risk = "Medium"

    return {
        "risk_level_today": risk,
        "unread_alerts": summary,
        "generated_at": datetime.utcnow(),
    }
