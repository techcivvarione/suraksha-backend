from datetime import date, timedelta
from sqlalchemy import text
from app.db import SessionLocal

LOOKBACK_DAYS = 30

def calculate_score(rows):
    score = 100
    high = medium = low = 0

    for r in rows:
        if r["risk"] == "high":
            high += r["count"]
        elif r["risk"] == "medium":
            medium += r["count"]
        elif r["risk"] == "low":
            low += r["count"]

    score -= high * 15
    score -= medium * 8

    total = high + medium + low
    if total == 0:
        score -= 30

    score = max(0, min(100, score))

    if score >= 80:
        level = "low"
    elif score >= 50:
        level = "medium"
    else:
        level = "high"

    return score, level, high, medium, low, total


def main():
    db = SessionLocal()
    today = date.today()
    since = today - timedelta(days=LOOKBACK_DAYS)

    users = db.execute(text("SELECT id FROM users")).mappings().all()

    for user in users:
        rows = db.execute(
            text("""
                SELECT risk, COUNT(*) AS count
                FROM scan_history
                WHERE user_id = CAST(:uid AS uuid)
                  AND created_at >= :since
                GROUP BY risk
            """),
            {"uid": str(user["id"]), "since": since},
        ).mappings().all()

        score, level, high, medium, low, total = calculate_score(rows)

        db.execute(
            text("""
                INSERT INTO daily_security_scores (
                    user_id, score, level,
                    high_risk, medium_risk, low_risk,
                    total_scans, score_date
                )
                VALUES (
                    :uid, :score, :level,
                    :high, :medium, :low,
                    :total, :date
                )
                ON CONFLICT (user_id, score_date)
                DO UPDATE SET
                    score = EXCLUDED.score,
                    level = EXCLUDED.level,
                    high_risk = EXCLUDED.high_risk,
                    medium_risk = EXCLUDED.medium_risk,
                    low_risk = EXCLUDED.low_risk,
                    total_scans = EXCLUDED.total_scans
            """),
            {
                "uid": str(user["id"]),
                "score": score,
                "level": level,
                "high": high,
                "medium": medium,
                "low": low,
                "total": total,
                "date": today,
            },
        )

    db.commit()
    db.close()
