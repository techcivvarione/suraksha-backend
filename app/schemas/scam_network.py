from __future__ import annotations

from datetime import datetime
from typing import List, Literal

from pydantic import BaseModel, ConfigDict, Field


class ScamLocationInput(BaseModel):
    lat: float | None = None
    lng: float | None = None


class ScamRegionInput(BaseModel):
    city: str | None = None
    state: str | None = None
    country: str | None = None


class ScamReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_type: Literal["call", "sms", "link", "payment"]
    category: str
    scam_phone_number: str | None = None
    phishing_url: str | None = None
    payment_handle: str | None = None
    payment_provider: str | None = None
    scam_description: str = Field(min_length=5, max_length=4000)
    geo_location: ScamLocationInput | None = None
    region: ScamRegionInput | None = None


class ScamReportResponse(BaseModel):
    status: str
    report_id: str
    duplicate: bool
    message: str


class ScamNumberCheckRequest(BaseModel):
    phone_number: str
    lat: float | None = None
    lng: float | None = None
    city: str | None = None
    state: str | None = None
    country: str | None = None


class ScamNumberCheckResponse(BaseModel):
    suspicion_level: str
    report_count_24h: int
    report_count_30d: int
    message: str


class ScamMessageCheckRequest(BaseModel):
    message_text: str = Field(min_length=3, max_length=4000)


class ScamMessageCheckResponse(BaseModel):
    risk_score: int
    classification: str
    reason: str


class ScamVerifyCallResponse(BaseModel):
    risk_level: str
    reports: int
    category: str | None = None
    message: str


class ScamAlertItem(BaseModel):
    id: int | str
    entity_type: str
    entity_label: str
    category: str | None = None
    risk_level: str
    report_count_24h: int
    region: dict
    message: str
    created_at: datetime


class ScamAlertsResponse(BaseModel):
    alerts: list[ScamAlertItem]
    total: int


# ---- Frontend-compatible (camelCase) campaign schemas ----

class ScamActivityPoint(BaseModel):
    label: str
    value: int


class ScamCampaignItem(BaseModel):
    """Matches the Android ScamAlertCampaign data class (camelCase field names)."""
    id: str
    scamType: str
    reportCount: int
    regionsAffected: List[str] = []
    explanation: str
    preventionTips: List[str] = []
    category: str | None = None
    recentActivityTimeline: List[ScamActivityPoint] = []


class ScamCampaignPageResponse(BaseModel):
    """Matches the Android ScamAlertPageResponse data class (camelCase field names)."""
    items: List[ScamCampaignItem] = []
    page: int = 1
    hasMore: bool = False
