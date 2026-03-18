from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict


class SignupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    email: Optional[str]
    phone_number: Optional[str]
    phone: Optional[str] = None
    password: str
    confirm_password: str
    accepted_terms: bool
    terms_version: Optional[str] = "v1"
    privacy_version: Optional[str] = "v1"


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    needs_phone_verification: bool = False
    needs_terms_acceptance: bool | None = None


class AuthMeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    plan: Optional[str] = None
    profile_image_url: Optional[str] = None
    token_version: int = 0
    subscription_status: Optional[str] = None
    subscription_expires_at: Optional[str] = None


class SendPhoneOtpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    phone: str


class VerifyPhoneOtpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    phone: str
    otp: str


class GoogleLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    google_id_token: str


class DeleteAccountRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm_username: str
