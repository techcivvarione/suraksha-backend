from pydantic import BaseModel, Field


class EmailScanRequest(BaseModel):
    email: str = Field(..., max_length=320)
