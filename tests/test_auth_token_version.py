from types import SimpleNamespace

from fastapi import Request
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt

from app.routes import auth


class _QueryResult:
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
        return _QueryResult(self.user)


class _Url:
    path = "/auth/me"


class _State:
    pass


class _Request:
    def __init__(self):
        self.url = _Url()
        self.state = _State()


def test_create_access_token_embeds_token_version():
    user = SimpleNamespace(id="user-1", email="user@example.com", plan="FREE", token_version=3)
    token = auth.create_access_token(user)
    payload = jwt.get_unverified_claims(token)
    assert payload["tv"] == 3


def test_resolve_current_user_rejects_stale_token(monkeypatch):
    user = SimpleNamespace(
        id="user-1",
        email="user@example.com",
        plan="FREE",
        token_version=4,
        password_changed_at=None,
        subscription_expires_at=None,
    )
    stale_user = SimpleNamespace(id="user-1", email="user@example.com", plan="FREE", token_version=1)
    token = auth.create_access_token(stale_user)
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    monkeypatch.setattr(auth, "maybe_auto_downgrade_expired_subscription", lambda db, user, request=None: user)

    try:
        auth._resolve_current_user(_Request(), credentials, _FakeDb(user), True)
        assert False, "expected token invalidation"
    except auth.HTTPException as exc:
        assert exc.detail["error"] == "TOKEN_EXPIRED"
