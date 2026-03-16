from types import SimpleNamespace

import pytest
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt

from app.routes import auth


class _QueryResult:
    def __init__(self, user, token_version):
        self.user = user
        self.token_version = token_version

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        if self.user is None:
            return None
        return self.user, self.token_version


class _FakeDb:
    def __init__(self, user, token_version=0):
        self.user = user
        self.token_version = token_version

    def query(self, *models):
        return _QueryResult(self.user, self.token_version)


class _Url:
    path = "/auth/me"


class _State:
    pass


class _Request:
    def __init__(self):
        self.url = _Url()
        self.state = _State()


class _Client:
    host = "127.0.0.1"


class _LoginRequest:
    client = _Client()


def test_create_access_token_embeds_identity_and_timestamps():
    user = SimpleNamespace(id="user-1", email="user@example.com", plan="FREE", token_version=3)
    token = auth.create_access_token(user)
    payload = jwt.get_unverified_claims(token)
    assert payload["token_version"] == 3
    assert payload["tv"] == 3
    assert payload["user_id"] == "user-1"
    assert payload["sub"] == "user-1"
    assert payload["issued_at"] == payload["iat"]
    assert payload["expiration"] == payload["exp"]
    assert payload["expiration"] > payload["issued_at"]


def test_login_path_handles_existing_token_version(monkeypatch):
    user = SimpleNamespace(
        id="user-1",
        email="user@example.com",
        phone_number="919876543210",
        plan="FREE",
        token_version=5,
        password_hash="hash",
        phone_verified=True,
        accepted_terms=True,
    )
    monkeypatch.setattr(auth, "verify_password", lambda password, hashed: True)
    monkeypatch.setattr(auth, "create_audit_log", lambda **kwargs: None)
    monkeypatch.setattr(auth, "_touch_last_login", lambda db, user, provider: user)

    response = auth.login(auth.LoginRequest(identifier="user@example.com", password="secret"), _LoginRequest(), _FakeDb(user, token_version=5))

    assert response["token_type"] == "bearer"
    assert response["needs_phone_verification"] is False


def test_logout_all_invalidation_rejects_old_tokens(monkeypatch):
    active_user = SimpleNamespace(id="user-1", email="user@example.com", plan="FREE", token_version=2, password_changed_at=None, subscription_expires_at=None)
    stale_user = SimpleNamespace(id="user-1", email="user@example.com", plan="FREE", token_version=1)
    token = auth.create_access_token(stale_user)
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    monkeypatch.setattr(auth, "maybe_auto_downgrade_expired_subscription", lambda db, user, request=None: user)

    with pytest.raises(auth.HTTPException) as exc:
        auth._resolve_current_user(_Request(), credentials, _FakeDb(active_user, token_version=2), True)

    assert exc.value.detail["error_code"] == "TOKEN_EXPIRED"


def test_password_change_invalidation_rejects_old_tokens(monkeypatch):
    old_token_user = SimpleNamespace(id="user-1", email="user@example.com", plan="FREE", token_version=0)
    current_user = SimpleNamespace(
        id="user-1",
        email="user@example.com",
        plan="FREE",
        token_version=0,
        password_changed_at=auth.datetime.now(auth.timezone.utc) + auth.timedelta(seconds=1),
        subscription_expires_at=None,
    )
    token = auth.create_access_token(old_token_user)
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    monkeypatch.setattr(auth, "maybe_auto_downgrade_expired_subscription", lambda db, user, request=None: user)

    with pytest.raises(auth.HTTPException) as exc:
        auth._resolve_current_user(_Request(), credentials, _FakeDb(current_user, token_version=0), True)

    assert exc.value.detail["error_code"] == "TOKEN_EXPIRED"


def test_email_login_requires_phone_verification(monkeypatch):
    user = SimpleNamespace(
        id="user-1",
        email="user@example.com",
        phone_number=None,
        plan="FREE",
        token_version=0,
        password_hash="hash",
        phone_verified=False,
        accepted_terms=False,
    )
    monkeypatch.setattr(auth, "verify_password", lambda password, hashed: True)

    with pytest.raises(auth.HTTPException) as exc:
        auth.login(auth.LoginRequest(identifier="user@example.com", password="secret"), _LoginRequest(), _FakeDb(user, token_version=0))

    assert exc.value.status_code == 403
    assert exc.value.detail["error_code"] == "PHONE_VERIFICATION_REQUIRED"
