from pydantic import BaseModel, Field


class QRScanRequest(BaseModel):
    raw_payload: str = Field(..., min_length=1, max_length=1024)
