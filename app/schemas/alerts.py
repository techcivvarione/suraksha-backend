from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import BaseResponse


class MediaRiskAlertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    media_hash: str = Field(min_length=16, max_length=128)
    analysis_type: str = Field(min_length=2, max_length=32)
    risk_score: int = Field(ge=0, le=100)


class MediaRiskAlertResponse(BaseResponse):
    dispatch: dict[str, Any]
