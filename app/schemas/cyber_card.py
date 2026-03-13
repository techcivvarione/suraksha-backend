from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel


class CyberCardSignals(BaseModel):
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


class CyberCardLockedResponse(BaseModel):
    card_status: Literal["LOCKED"]
    score: int
    max_score: int
    risk_level: str
    signals: CyberCardSignals
    message: str


class CyberCardActiveResponse(BaseModel):
    card_status: Literal["ACTIVE"]
    card_id: str
    name: str
    is_paid: bool
    score: int
    max_score: int
    risk_level: str
    signals: CyberCardSignals
    score_month: datetime
    score_version: str = "v1"


class CyberCardHistoryItem(BaseModel):
    month: date | datetime
    score: int
    max_score: int
    risk_level: str
    signals: CyberCardSignals


class CyberCardHistoryResponse(BaseModel):
    count: int
    history: list[CyberCardHistoryItem]
    message: str | None = None
