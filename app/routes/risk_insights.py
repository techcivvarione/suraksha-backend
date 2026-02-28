from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import Feature
from app.db import get_db
from app.dependencies.access import require_feature
from app.models.user import User

router = APIRouter(prefix="/risk", tags=["Risk Insights"])

SUSPICIOUS_KEYWORDS = [
    "otp", "upi", "bank", "refund", "lottery",
    "job", "offer", "kyc", "payment", "verify"
]


@router.get("/insights")
def paid_risk_insights(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_feature(Feature.RISK_INSIGHTS)
    ),
):
    rows = db.execute(
        text(
            """
            SELECT
                DATE(created_at) AS day,
                risk,
                COUNT(*) AS count
            FROM scan_history
            WHERE user_id = CAST(:uid AS uuid)
              AND created_at >= NOW() - INTERVAL '30 days'
            GROUP BY day, risk
            ORDER BY day
        """
        ),
        {"uid": str(current_user.id)},
    ).mappings().all()

    risk_days = {}
    for row in rows:
        day = str(row["day"])
        if day not in risk_days:
            risk_days[day] = {"high": 0, "medium": 0, "low": 0}
        risk_days[day][row["risk"]] += row["count"]

    peak_risk_days = sorted(
        risk_days.items(),
        key=lambda item: item[1]["high"],
        reverse=True,
    )[:3]

    texts = db.execute(
        text(
            """
            SELECT input_text
            FROM scan_history
            WHERE user_id = CAST(:uid AS uuid)
              AND created_at >= NOW() - INTERVAL '30 days'
        """
        ),
        {"uid": str(current_user.id)},
    ).scalars().all()

    keyword_hits = Counter()

    for text_value in texts:
        if not text_value:
            continue
        lowered = text_value.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in lowered:
                keyword_hits[keyword] += 1

    top_keywords = keyword_hits.most_common(5)

    recommendations = []

    if keyword_hits.get("otp", 0) >= 2:
        recommendations.append(
            "You frequently encounter OTP-related scams. Never share OTPs with anyone."
        )

    if keyword_hits.get("upi", 0) >= 2:
        recommendations.append(
            "Repeated UPI scam patterns detected. Avoid approving unknown collect requests."
        )

    if not recommendations:
        recommendations.append(
            "Your recent activity looks relatively safe. Stay cautious and continue scanning."
        )

    return {
        "window": "30_days",
        "summary": {
            "peak_risk_days": [
                {
                    "date": day,
                    "high": stats["high"],
                    "medium": stats["medium"],
                    "low": stats["low"],
                }
                for day, stats in peak_risk_days
            ],
            "top_scam_keywords": [
                {"keyword": keyword, "count": count}
                for keyword, count in top_keywords
            ],
        },
        "recommendations": recommendations,
    }
