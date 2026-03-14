import hashlib
import hmac
import json

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.services.subscription import verify_revenuecat_signature


def _request(headers):
    scope = {"type": "http", "method": "POST", "path": "/webhooks/revenuecat", "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()]}
    return Request(scope)


def test_verify_revenuecat_signature_accepts_bearer(monkeypatch):
    monkeypatch.setenv("REVENUECAT_WEBHOOK_SECRET", "secret-value")
    verify_revenuecat_signature(_request({"authorization": "Bearer secret-value"}), b"{}")


def test_verify_revenuecat_signature_accepts_hmac(monkeypatch):
    monkeypatch.setenv("REVENUECAT_WEBHOOK_SECRET", "secret-value")
    body = json.dumps({"event": "ok"}).encode()
    digest = hmac.new(b"secret-value", body, hashlib.sha256).hexdigest()
    verify_revenuecat_signature(_request({"x-revenuecat-signature": digest}), body)


def test_verify_revenuecat_signature_rejects_invalid(monkeypatch):
    monkeypatch.setenv("REVENUECAT_WEBHOOK_SECRET", "secret-value")
    with pytest.raises(HTTPException):
        verify_revenuecat_signature(_request({"authorization": "Bearer wrong"}), b"{}")
