from fastapi import APIRouter, Depends
from pydantic import BaseModel
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.routes.auth import get_current_user
from app.models.user import User
from app.data.news_data import NEWS_CACHE, fetch_news

router = APIRouter(prefix="/home", tags=["Home"])


# ---------------------------
# Response Schemas
# ---------------------------

class SecuritySnapshot(BaseModel):
    scans_done: int
    threats_detected: int
    last_scan_at: Optional[datetime]
    overall_risk: str


class GlobalThreatPulse(BaseModel):
    last_24h_incidents_estimated: int
    threat_level: str
    updated_at: datetime
    source: str


class HotNewsItem(BaseModel):
    title: str
    category: str
    source: str
    published_at: datetime


class FinancialImpact(BaseModel):
    year: int
    estimated_global_loss_usd: int
    display_text: str
    source: str


class HomeOverviewResponse(BaseModel):
    security_snapshot: SecuritySnapshot
    global_threat_pulse: GlobalThreatPulse
    hot_news: List[HotNewsItem]
    financial_impact: FinancialImpact


# ---------------------------
# Static / Cached Data
# ---------------------------

FINANCIAL_IMPACT_2026 = {
    "year": 2026,
    "estimated_global_loss_usd": 10500000000000,  # $10.5T
    "display_text": "Estimated global cybercrime losses in 2026",
    "source": "IBM / Verizon / Industry reports",
}

GLOBAL_THREAT_PULSE_CACHE = {
    "last_24h_incidents_estimated": 2900,
    "threat_level": "Medium",
    "updated_at": datetime.now(tz=timezone.utc),
    "source": "Aggregated public threat feeds",
}


# ---------------------------
# Helpers
# ---------------------------

def compute_overall_risk(high: int, medium: int) -> str:
    if high > 0:
        return "High"
    if medium > 0:
        return "Medium"
    return "Low"


# ---------------------------
# Route
# ---------------------------

@router.get("/overview", response_model=HomeOverviewResponse)
def home_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    user_id = str(current_user.id)

    # ---- Scan stats ----
    scan_stats = db.execute(
        text("""
            SELECT
                COUNT(*) AS scans_done,
                COUNT(*) FILTER (WHERE risk = 'high') AS high_count,
                COUNT(*) FILTER (WHERE risk = 'medium') AS medium_count,
                MAX(created_at) AS last_scan_at
            FROM scan_history
            WHERE user_id = :uid
        """),
        {"uid": user_id},
    ).mappings().first()

    scans_done = scan_stats["scans_done"] or 0
    high_scans = scan_stats["high_count"] or 0
    medium_scans = scan_stats["medium_count"] or 0
    last_scan_at = scan_stats["last_scan_at"]

    # ---- Unread HIGH alerts ----
    high_alerts = db.execute(
        text("""
            SELECT COUNT(*)
            FROM alerts
            WHERE user_id = :uid
              AND read = false
              AND severity = 'HIGH'
        """),
        {"uid": user_id},
    ).scalar() or 0

    threats_detected = high_scans + medium_scans + high_alerts
    overall_risk = compute_overall_risk(high_scans + high_alerts, medium_scans)

    security_snapshot = SecuritySnapshot(
        scans_done=scans_done,
        threats_detected=threats_detected,
        last_scan_at=last_scan_at,
        overall_risk=overall_risk,
    )

    # ---- Global threat pulse (cached) ----
    global_threat_pulse = GlobalThreatPulse(**GLOBAL_THREAT_PULSE_CACHE)

    # ---- Hot news (top 2) ----
    if not NEWS_CACHE:
        fetch_news()

    hot_news = []
    for item in NEWS_CACHE[:2]:
        hot_news.append(
            HotNewsItem(
                title=item.get("title"),
                category=item.get("category"),
                source=item.get("source", "News"),
                published_at=item.get("published_at", datetime.now(tz=timezone.utc)),
            )
        )

    # ---- Financial impact ----
    financial_impact = FinancialImpact(**FINANCIAL_IMPACT_2026)

    return HomeOverviewResponse(
        security_snapshot=security_snapshot,
        global_threat_pulse=global_threat_pulse,
        hot_news=hot_news,
        financial_impact=financial_impact,
    )
