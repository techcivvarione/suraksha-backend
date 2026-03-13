from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict


class SignupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    email: Optional[str]
    phone_number: Optional[str]
    password: str
    confirm_password: str
    accepted_terms: bool
    terms_version: Optional[str] = "v1"
    privacy_version: Optional[str] = "v1"
