from types import SimpleNamespace

import pytest

from app.routes import auth


class _FakeDb:
    def __init__(self):
        self.added = []
        self.commits = 0
        self.refreshed = []

    def add(self, user):
        self.added.append(user)

    def commit(self):
        self.commits += 1

    def refresh(self, user):
        self.refreshed.append(user)


def test_resolve_google_user_identity_links_existing_email_account(monkeypatch):
    fake_db = _FakeDb()
    existing_user = SimpleNamespace(
        id="user-1",
        email="user@example.com",
        name="Existing",
        auth_provider="email",
        google_sub=None,
        email_verified=False,
        phone_verified=True,
    )
    monkeypatch.setattr(auth, "_find_user_by_google_sub", lambda db, google_sub: None)
    monkeypatch.setattr(auth, "_find_user_by_email_exact", lambda db, email: existing_user)
    monkeypatch.setattr(auth, "_touch_last_login", lambda db, user, provider: user)

    resolved = auth._resolve_google_user_identity(fake_db, google_sub="google-sub-1", email="user@example.com", name="Existing")

    assert resolved is existing_user
    assert existing_user.google_sub == "google-sub-1"
    assert existing_user.email_verified is True


def test_resolve_google_user_identity_prefers_existing_google_sub(monkeypatch):
    existing_user = SimpleNamespace(id="user-1", email="user@example.com", auth_provider="google", google_sub="google-sub-1", email_verified=True)
    monkeypatch.setattr(auth, "_find_user_by_google_sub", lambda db, google_sub: existing_user)
    monkeypatch.setattr(auth, "_touch_last_login", lambda db, user, provider: user)

    resolved = auth._resolve_google_user_identity(_FakeDb(), google_sub="google-sub-1", email="user@example.com", name="User")

    assert resolved is existing_user


def test_resolve_google_user_identity_creates_new_google_account(monkeypatch):
    fake_db = _FakeDb()
    monkeypatch.setattr(auth, "_find_user_by_google_sub", lambda db, google_sub: None)
    monkeypatch.setattr(auth, "_find_user_by_email_exact", lambda db, email: None)

    resolved = auth._resolve_google_user_identity(fake_db, google_sub="google-sub-1", email="user@example.com", name="User")

    assert resolved.google_sub == "google-sub-1"
    assert resolved.auth_provider == "google"
    assert resolved.email == "user@example.com"
    assert resolved.email_verified is True
    assert resolved.phone_verified is False
    assert fake_db.commits == 1
