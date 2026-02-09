from sqlalchemy.orm import Session
from sqlalchemy import text
import hashlib
from datetime import datetime


def _generate_card_id(name: str, user_id: str):
    initial = name[0].upper() if name else "X"
    h = hashlib.sha1(user_id.encode()).hexdigest()[:6].upper()
    year = datetime.utcnow().year % 100
    return f"CC-{year:02d}-{initial}-{h}"


def get_cyber_card(db: Session, user_id: str):
    user = db.execute(
        text("SELECT name, plan FROM users WHERE id = CAST(:uid AS uuid)"),
        {"uid": user_id},
    ).mappings().first()

    if not user:
        return None

    card = db.execute(
        text("""
            SELECT score, max_score, risk_level, signals, score_month
            FROM cyber_card_scores
            WHERE user_id = CAST(:uid AS uuid)
            ORDER BY score_month DESC
            LIMIT 1
        """),
        {"uid": user_id},
    ).mappings().first()

    if not card:
        return None

    return {
        "card_id": _generate_card_id(user["name"], user_id),
        "name": user["name"],
        "is_paid": user["plan"] == "PAID",
        **card,
    }
