from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ExplainScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str | None = None
    text: str | None = None
    language: str = "en"


class ExplainScanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    ai_explanation: str | None
