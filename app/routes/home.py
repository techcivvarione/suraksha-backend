from fastapi import APIRouter, Depends
from pydantic import BaseModel
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.routes.auth import get_current_user
from app.models.user import User


router = APIRouter(prefix="/home", tags=["Home"])


# ---------------------------
# Response Schemas
# ---------------------------

class SecuritySnapshot(BaseModel):
    scans_done: int
    threats_detected: int
    last_scan_at: Optional[datetime]
    overall_risk: str


class ThreatPulse(BaseModel):
    scope: str
    region_code: Optional[str]
    payload: Dict[str, Any]
    confidence: str
    sources: List[str]
    generated_at: datetime


class FinancialImpact(BaseModel):
    scope: str
    region_code: Optional[str]
    payload: Dict[str, Any]
    confidence: str
    sources: List[str]
    generated_at: datetime


class HomeOverviewResponse(BaseModel):
    security_snapshot: SecuritySnapshot
    threat_pulse: Dict[str, ThreatPulse]
    financial_impact: Dict[str, FinancialImpact]


# ---------------------------
# Helpers
# ---------------------------

def compute_overall_risk(high: int, medium: int) -> str:
    if high > 0:
        return "High"
    if medium > 0:
        return "Medium"
    return "Low"


def fetch_metric(
    db: Session,
    metric_type: str,
    scope: str,
    region_code: Optional[str],
):
    row = db.execute(
        text("""
            SELECT scope, region_code, payload, sources, confidence, generated_at
            FROM home_metrics
            WHERE metric_type = :metric_type
              AND scope = :scope
              AND (:region_code IS NULL OR region_code = :region_code)
              AND valid_until > now()
            ORDER BY generated_at DESC
            LIMIT 1
        """),
        {
            "metric_type": metric_type,
            "scope": scope,
            "region_code": region_code,
        },
    ).mappings().first()

    return row


# ---------------------------
# Route
# ---------------------------

@router.get("/overview", response_model=HomeOverviewResponse)
def home_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    user_id = str(current_user.id)

    # ---------------------------
    # Scan + Alert Snapshot
    # ---------------------------

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

    # ---------------------------
    # Region Resolution (Profile → Device → IP)
    # For now: profile-based
    # ---------------------------

    user_country = getattr(current_user, "country_code", None)
    user_region = getattr(current_user, "region_code", None)

    # ---------------------------
    # Threat Pulse
    # ---------------------------

    threat_pulse: Dict[str, ThreatPulse] = {}

    global_tp = fetch_metric(db, "threat_pulse", "global", None)
    if global_tp:
        threat_pulse["global"] = ThreatPulse(**global_tp)

    if user_country == "IN":
        india_tp = fetch_metric(db, "threat_pulse", "india", "IN")
        if india_tp:
            threat_pulse["india"] = ThreatPulse(**india_tp)

        if user_region:
            region_tp = fetch_metric(db, "threat_pulse", "region", user_region)
            if region_tp:
                threat_pulse["region"] = ThreatPulse(**region_tp)
            else:
                threat_pulse["region"] = ThreatPulse(
                    scope="region",
                    region_code=user_region,
                    payload={
                        "status": "no_recent_data",
                        "message": "No recent regional advisories. Showing India-wide risk.",
                    },
                    confidence="low",
                    sources=[],
                    generated_at=datetime.now(tz=timezone.utc),
                )

    # ---------------------------
    # Financial Impact
    # ---------------------------

    financial_impact: Dict[str, FinancialImpact] = {}

    global_fi = fetch_metric(db, "financial_impact", "global", None)
    if global_fi:
        financial_impact["global"] = FinancialImpact(**global_fi)

    if user_country == "IN":
        india_fi = fetch_metric(db, "financial_impact", "india", "IN")
        if india_fi:
            financial_impact["india"] = FinancialImpact(**india_fi)

    # ---------------------------
    # Final Response
    # ---------------------------

    return HomeOverviewResponse(
        security_snapshot=security_snapshot,
        threat_pulse=threat_pulse,
        financial_impact=financial_impact,
    )
