from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class CyberCardSignals(BaseModel):
    """Legacy signals object — kept for backward compatibility with V1 clients."""
    email_scan_count: int = 0
    password_scan_count: int = 0
    scan_reward_points: int = 0
    ocr_bonus: int = 0
    scam_reports: int = 0
    eligibility: str = "ELIGIBLE"
    lock_reason: str | None = None


class CyberCardPendingResponse(BaseModel):
    card_status: Literal["PENDING"]
    message: str
    # Eligibility signals — Android uses these to show the right copy
    eligible: bool = False            # True when distinct scan types >= 2
    distinct_scan_types: int = 0      # How many unique scan types the user has completed


class CyberCardLockedResponse(BaseModel):
    card_status: Literal["LOCKED"]
    score: int
    max_score: int = 1000
    risk_level: str
    signals: CyberCardSignals = Field(default_factory=CyberCardSignals)
    message: str


class CyberCardActiveResponse(BaseModel):
    """V2 active card response — includes real-time score, insights, and actions."""
    card_status: Literal["ACTIVE"]
    card_id: str
    name: str
    is_paid: bool
    score: int
    max_score: int = 1000
    risk_level: str                                    # human label: "Safe", "Elite", …
    level: str                                         # machine: MOSTLY_SAFE, EXCELLENT, …
    signals: CyberCardSignals = Field(default_factory=CyberCardSignals)
    factors: dict[str, Any] = Field(default_factory=dict)    # per-component breakdown
    insights: list[str] = Field(default_factory=list)        # human-readable findings
    actions: list[dict[str, Any]] = Field(default_factory=list)  # suggested next steps
    score_month: datetime
    updated_at: datetime | None = None
    score_version: str = "v2"


class CyberCardHistoryItem(BaseModel):
    month: date | datetime
    score: int
    max_score: int = 1000
    risk_level: str
    signals: CyberCardSignals = Field(default_factory=CyberCardSignals)


class CyberCardHistoryResponse(BaseModel):
    count: int
    history: list[CyberCardHistoryItem]
    message: str | None = None
