from fastapi import APIRouter, Depends
from pydantic import BaseModel
from datetime import datetime
import uuid

from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user


router = APIRouter(prefix="/alerts", tags=["Alerts"])


# ---------- models ----------
class SubscribeRequest(BaseModel):
    categories: list[str]


# ---------- helpers ----------
def severity_for(category: str, alert_type: str) -> str:
    if alert_type == "history":
        return "HIGH"
    if category.lower() in ["cyber", "cyber crime", "ai", "govt"]:
        return "HIGH"
    if category.lower() in ["banking", "upi", "finance"]:
        return "MEDIUM"
    return "LOW"


# ---------- routes ----------
@router.post("/subscribe")
def subscribe_alerts(
    payload: SubscribeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    db.execute(
        "delete from alert_subscriptions where user_id = :uid",
        {"uid": str(current_user.id)},
    )

    for category in payload.categories:
        db.execute(
            """
            insert into alert_subscriptions (id, user_id, category, created_at)
            values (:id, :uid, :cat, now())
            on conflict do nothing
            """,
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
        """
        select *
        from alerts
        where user_id = :uid
        order by
            case severity
                when 'HIGH' then 1
                when 'MEDIUM' then 2
                else 3
            end,
            created_at desc
        """,
        {"uid": str(current_user.id)},
    ).mappings().all()

    return {"count": len(rows), "alerts": rows}


@router.get("/refresh")
def refresh_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    created = 0

    # ---- subscriptions ----
    subs = db.execute(
        "select category from alert_subscriptions where user_id = :uid",
        {"uid": str(current_user.id)},
    ).scalars().all()

    if not subs:
        return {"status": "no_subscriptions", "new_alerts_created": 0}

    # ---- NEWS → ALERTS (DB BASED, NOT RSS) ----
    news_rows = db.execute(
        """
        select id, headline, matter, category, source
        from news
        where category = any(:cats)
        order by published_at desc
        limit 50
        """,
        {"cats": subs},
    ).mappings().all()

    for news in news_rows:
        exists = db.execute(
            """
            select 1 from alerts
            where user_id = :uid and source = :src
            """,
            {"uid": str(current_user.id), "src": news["source"]},
        ).first()

        if not exists:
            db.execute(
                """
                insert into alerts (
                    id, user_id, type, title, message,
                    category, severity, source, read, created_at
                )
                values (
                    :id, :uid, 'news', :title, :msg,
                    :cat, :sev, :src, false, now()
                )
                """,
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

    # ---- HISTORY → ALERTS (UNCHANGED LOGIC) ----
    rows = db.execute(
        """
        select input_text
        from scan_history
        where user_id = :uid
        """,
        {"uid": str(current_user.id)},
    ).scalars().all()

    keyword_count = {}
    for text in rows:
        t = text.lower()
        for k in ["otp", "upi", "bank", "lottery", "job"]:
            if k in t:
                keyword_count[k] = keyword_count.get(k, 0) + 1

    for k, count in keyword_count.items():
        if count >= 2:
            src = f"history-{k}"
            exists = db.execute(
                """
                select 1 from alerts
                where user_id = :uid and source = :src
                """,
                {"uid": str(current_user.id), "src": src},
            ).first()

            if not exists:
                db.execute(
                    """
                    insert into alerts (
                        id, user_id, type, title, message,
                        category, severity, source, read, created_at
                    )
                    values (
                        :id, :uid, 'history',
                        'Repeated scam pattern detected',
                        :msg,
                        'Personal Risk', 'HIGH',
                        :src, false, now()
                    )
                    """,
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
        """
        select severity, count(*)
        from alerts
        where user_id = :uid and read = false
        group by severity
        """,
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
