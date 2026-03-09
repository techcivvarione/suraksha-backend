from pydantic import BaseModel, Field


class PasswordScanRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)
