from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import uuid

from fastapi.testclient import TestClient

from app.main import app
from app.db import get_db
from app.models.user import User
from app.routes import auth
import app.routes.qr_secure as qr_secure


class _FakeUserQuery:
    def __init__(self, user):
        self.user = user

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self.user


class _FakeDb:
    def __init__(self, user):
        self.user = user

    def query(self, model):
        if model is User:
            return _FakeUserQuery(self.user)
        raise AssertionError(f"Unexpected model query: {model}")

    def begin(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _client_with_user(user):
    fake_db = _FakeDb(user)
    app.dependency_overrides[get_db] = lambda: fake_db
    app.router.on_startup.clear()
    app.router.on_shutdown.clear()
    return TestClient(app, raise_server_exceptions=False)


def test_qr_analyze_invalid_token_returns_structured_error():
    with _client_with_user(None) as client:
        response = client.post(
            "/qr/analyze",
            headers={"Authorization": "Bearer not-a-real-token"},
            json={"raw_payload": "https://example.com"},
        )

    app.dependency_overrides.clear()
    assert response.status_code == 401
    assert response.json() == {
        "success": False,
        "error": "INVALID_TOKEN",
        "message": "Invalid token",
    }


def test_qr_analyze_expired_token_returns_structured_error():
    user = SimpleNamespace(
        id=uuid.uuid4(),
        email="user@example.com",
        plan="FREE",
        password_changed_at=None,
    )
    now = datetime.now(tz=timezone.utc)
    expired_token = auth.jwt.encode(
        {
            "sub": str(user.id),
            "email": user.email,
            "plan": user.plan,
            "iat": int((now - timedelta(hours=2)).timestamp()),
            "exp": int((now - timedelta(hours=1)).timestamp()),
        },
        auth.SECRET_KEY,
        algorithm=auth.ALGORITHM,
    )

    with _client_with_user(user) as client:
        response = client.post(
            "/qr/analyze",
            headers={"Authorization": f"Bearer {expired_token}"},
            json={"raw_payload": "https://example.com"},
        )

    app.dependency_overrides.clear()
    assert response.status_code == 401
    assert response.json() == {
        "success": False,
        "error": "TOKEN_EXPIRED",
        "message": "Token expired",
    }


def test_qr_analyze_accepts_bearer_token_and_reaches_analysis(monkeypatch):
    user = SimpleNamespace(
        id=uuid.uuid4(),
        email="user@example.com",
        plan="FREE",
        password_changed_at=None,
        created_at=datetime.now(tz=timezone.utc) - timedelta(days=2),
    )
    token = auth.create_access_token(user)

    monkeypatch.setattr(qr_secure, "enforce_rate_limits", lambda user_id, ip, qr_hash: None)
    monkeypatch.setattr(
        qr_secure,
        "get_or_create_reputation",
        lambda db, qr_hash: SimpleNamespace(reported_count=0, is_flagged=False),
    )

    with _client_with_user(user) as client:
        response = client.post(
            "/qr/analyze",
            headers={"Authorization": f"Bearer {token}"},
            json={"raw_payload": "https://example.com"},
        )

    app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["detected_type"] == "URL"
    assert "risk_score" in payload
