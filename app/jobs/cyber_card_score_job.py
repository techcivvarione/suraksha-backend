import json
import uuid
from datetime import datetime, timedelta

from sqlalchemy import text

from app.db import SessionLocal
from app.services.cyber_card_constants import get_risk_level

BASE_SCORE = 600
MIN_SCORE = 300
MAX_SCORE = 999


def run_cyber_card_score_job():
    db = SessionLocal()

    users = db.execute(text("SELECT id FROM users")).mappings().all()

    month_start = db.execute(
        text(
            """
            SELECT date_trunc(
                'month',
                now() AT TIME ZONE 'Asia/Kolkata'
            )
            """
        )
    ).scalar()

    eligibility_window_end = month_start + timedelta(days=5)

    for user in users:
        uid = str(user["id"])
        score = BASE_SCORE

        signals = {
            "email_scan_count": 0,
            "password_scan_count": 0,
            "email_breaches": 0,
            "password_breaches": 0,
            "scan_reward_points": 0,
            "ocr_bonus": 0,
            "scam_reports": 0,
            "eligibility": "ELIGIBLE",
            "lock_reason": None,
        }

        email_done = db.execute(
            text(
                """
                SELECT COUNT(*) FROM scan_history
                WHERE user_id = CAST(:uid AS uuid)
                  AND scan_type = 'EMAIL'
                  AND created_at >= :start
                  AND created_at < :end
                """
            ),
            {
                "uid": uid,
                "start": month_start,
                "end": eligibility_window_end,
            },
        ).scalar() or 0

        password_done = db.execute(
            text(
                """
                SELECT COUNT(*) FROM scan_history
                WHERE user_id = CAST(:uid AS uuid)
                  AND scan_type = 'PASSWORD'
                  AND created_at >= :start
                  AND created_at < :end
                """
            ),
            {
                "uid": uid,
                "start": month_start,
                "end": eligibility_window_end,
            },
        ).scalar() or 0

        if email_done == 0 or password_done == 0:
            signals["eligibility"] = "LOCKED_THIS_MONTH"
            signals["lock_reason"] = "Mandatory Email/Password scan missed (1-5)"

            db.execute(
                text(
                    """
                    INSERT INTO cyber_card_scores (
                        id, user_id, score, max_score,
                        risk_level, signals, score_month
                    )
                    VALUES (
                        :id, :uid, :score, :max,
                        'Locked', CAST(:signals AS jsonb),
                        :month
                    )
                    ON CONFLICT (user_id, score_month)
                    DO UPDATE SET
                        score = EXCLUDED.score,
                        risk_level = EXCLUDED.risk_level,
                        signals = EXCLUDED.signals,
                        created_at = now()
                    """
                ),
                {
                    "id": str(uuid.uuid4()),
                    "uid": uid,
                    "score": BASE_SCORE,
                    "max": MAX_SCORE,
                    "signals": json.dumps(signals),
                    "month": month_start,
                },
            )
            continue

        email_scan_count = db.execute(
            text(
                """
                SELECT COUNT(*) FROM scan_history
                WHERE user_id = CAST(:uid AS uuid)
                  AND scan_type = 'EMAIL'
                  AND created_at >= :start
                """
            ),
            {"uid": uid, "start": month_start},
        ).scalar() or 0

        signals["email_scan_count"] = email_scan_count
        signals["email_breaches"] = email_scan_count

        if email_scan_count == 0:
            score += 25
        elif email_scan_count <= 3:
            score -= 30
        elif email_scan_count <= 6:
            score -= 60
        elif email_scan_count <= 10:
            score -= 100
        elif email_scan_count <= 50:
            score -= 180
        else:
            score -= 300

        password_scan_count = db.execute(
            text(
                """
                SELECT COUNT(*) FROM scan_history
                WHERE user_id = CAST(:uid AS uuid)
                  AND scan_type = 'PASSWORD'
                  AND created_at >= :start
                """
            ),
            {"uid": uid, "start": month_start},
        ).scalar() or 0

        signals["password_scan_count"] = password_scan_count
        signals["password_breaches"] = password_scan_count

        if password_scan_count == 0:
            score += 30
        elif password_scan_count <= 3:
            score -= 50
        elif password_scan_count <= 6:
            score -= 100
        elif password_scan_count <= 10:
            score -= 180
        else:
            score -= 300

        scan_rows = db.execute(
            text(
                """
                SELECT risk, COUNT(*)
                FROM scan_history
                WHERE user_id = CAST(:uid AS uuid)
                  AND scan_type = 'THREAT'
                  AND created_at >= :start
                GROUP BY risk
                """
            ),
            {"uid": uid, "start": month_start},
        ).mappings().all()

        reward = 0
        for row in scan_rows:
            if row["risk"] == "low":
                reward += row["count"] * 1
            elif row["risk"] == "medium":
                reward += row["count"] * 2
            elif row["risk"] == "high":
                reward += row["count"] * 3

        reward = min(reward, 50)
        score += reward
        signals["scan_reward_points"] = reward

        ocr_count = db.execute(
            text(
                """
                SELECT COUNT(*) FROM scan_history
                WHERE user_id = CAST(:uid AS uuid)
                  AND scan_type = 'OCR'
                  AND created_at >= :start
                """
            ),
            {"uid": uid, "start": month_start},
        ).scalar() or 0

        ocr_bonus = min(ocr_count * 5, 15)
        score += ocr_bonus
        signals["ocr_bonus"] = ocr_bonus

        scam_reports = db.execute(
            text(
                """
                SELECT COUNT(*) FROM scam_reports
                WHERE user_id = CAST(:uid AS uuid)
                  AND created_at >= :start
                """
            ),
            {"uid": uid, "start": month_start},
        ).scalar() or 0

        if scam_reports > 0:
            score -= 300
            signals["scam_reports"] = scam_reports

        score = max(MIN_SCORE, min(score, MAX_SCORE))
        risk_level = get_risk_level(score)

        db.execute(
            text(
                """
                INSERT INTO cyber_card_scores (
                    id, user_id, score, max_score,
                    risk_level, signals, score_month
                )
                VALUES (
                    :id, :uid, :score, :max,
                    :level, CAST(:signals AS jsonb),
                    :month
                )
                ON CONFLICT (user_id, score_month)
                DO UPDATE SET
                    score = EXCLUDED.score,
                    risk_level = EXCLUDED.risk_level,
                    signals = EXCLUDED.signals,
                    created_at = now()
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "uid": uid,
                "score": score,
                "max": MAX_SCORE,
                "level": risk_level,
                "signals": json.dumps(signals),
                "month": month_start,
            },
        )

    db.commit()
    db.close()
