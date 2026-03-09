from pydantic import BaseModel, Field, EmailStr


class EmailScanRequest(BaseModel):
    email: EmailStr = Field(..., max_length=320)
