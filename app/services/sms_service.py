from __future__ import annotations

import hashlib
import os
import secrets

import requests


MSG91_URL = "https://control.msg91.com/api/v5/flow"
MSG91_API_KEY = os.getenv("MSG91_API_KEY")
MSG91_TEMPLATE_ID = os.getenv("DLT_TEMPLATE_ID") or os.getenv("MSG91_TEMPLATE_ID")
OTP_HASH_SECRET = os.getenv("OTP_SECRET_SALT") or os.getenv("SECRET_KEY")
OTP_LENGTH = 6


class SMSDeliveryError(RuntimeError):
    pass


def generate_otp() -> str:
    return str(secrets.randbelow(10**OTP_LENGTH)).zfill(OTP_LENGTH)


def hash_otp(phone: str, otp: str) -> str:
    if not OTP_HASH_SECRET:
        raise RuntimeError("OTP hash secret not configured")
    return hashlib.sha256(f"{phone}{otp}{OTP_HASH_SECRET}".encode("utf-8")).hexdigest()


def send_sms(phone: str, otp: str) -> None:
    if not MSG91_API_KEY or not MSG91_TEMPLATE_ID:
        raise SMSDeliveryError("SMS provider is not configured")

    response = requests.post(
        MSG91_URL,
        headers={
            "authkey": MSG91_API_KEY,
            "content-type": "application/json",
        },
        json={
            "template_id": MSG91_TEMPLATE_ID,
            "recipients": [
                {
                    "mobiles": phone,
                    "VAR1": otp,
                }
            ],
        },
        timeout=15,
    )
    if response.status_code >= 400:
        raise SMSDeliveryError("SMS delivery failed")
