from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from collections import Counter

from app.db import get_db
from app.routes.auth import get_current_user
from app.models.user import User

router = APIRouter(prefix="/risk", tags=["Risk Insights"])

SUSPICIOUS_KEYWORDS = [
    "otp", "upi", "bank", "refund", "lottery",
    "job", "offer", "kyc", "payment", "verify"
]


@router.get("/insights")
def paid_risk_insights(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # 🔐 PAID ONLY
    if current_user.plan != "PAID":
        raise HTTPException(
            status_code=403,
            detail={
                "upgrade_required": True,
                "message": "Upgrade to access advanced risk insights",
                "features": [
                    "Behavioral scam patterns",
                    "Risk timeline analysis",
                    "Personalized security recommendations"
                ],
            },
        )

    # ------------------------------
    # 1️⃣ RISK DISTRIBUTION BY DAY
    # ------------------------------
    rows = db.execute(
        text("""
            SELECT
                DATE(created_at) AS day,
                risk,
                COUNT(*) AS count
            FROM scan_history
            WHERE user_id = CAST(:uid AS uuid)
              AND created_at >= NOW() - INTERVAL '30 days'
            GROUP BY day, risk
            ORDER BY day
        """),
        {"uid": str(current_user.id)},
    ).mappings().all()

    risk_days = {}
    for r in rows:
        day = str(r["day"])
        if day not in risk_days:
            risk_days[day] = {"high": 0, "medium": 0, "low": 0}
        risk_days[day][r["risk"]] += r["count"]

    peak_risk_days = sorted(
        risk_days.items(),
        key=lambda x: x[1]["high"],
        reverse=True
    )[:3]

    # ------------------------------
    # 2️⃣ KEYWORD PATTERN ANALYSIS
    # ------------------------------
    texts = db.execute(
        text("""
            SELECT input_text
            FROM scan_history
            WHERE user_id = CAST(:uid AS uuid)
              AND created_at >= NOW() - INTERVAL '30 days'
        """),
        {"uid": str(current_user.id)},
    ).scalars().all()

    keyword_hits = Counter()

    for text_value in texts:
        if not text_value:
            continue
        t = text_value.lower()
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in t:
                keyword_hits[kw] += 1

    top_keywords = keyword_hits.most_common(5)

    # ------------------------------
    # 3️⃣ RECOMMENDATIONS
    # ------------------------------
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
                {"keyword": k, "count": c} for k, c in top_keywords
            ],
        },
        "recommendations": recommendations,
    }
