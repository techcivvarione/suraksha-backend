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


def test_resolve_google_user_identity_rejects_password_account_email_conflict(monkeypatch):
    existing_user = SimpleNamespace(id="user-1", email="user@example.com", auth_provider="password", google_sub=None)
    monkeypatch.setattr(auth, "_find_user_by_google_sub", lambda db, google_sub: None)
    monkeypatch.setattr(auth, "_find_user_by_email_exact", lambda db, email: existing_user)

    with pytest.raises(auth.HTTPException) as exc:
        auth._resolve_google_user_identity(_FakeDb(), google_sub="google-sub-1", email="user@example.com", name="User")

    assert exc.value.status_code == 409


def test_resolve_google_user_identity_backfills_legacy_google_account(monkeypatch):
    fake_db = _FakeDb()
    existing_user = SimpleNamespace(id="user-1", email="user@example.com", name="Existing", auth_provider="google", google_sub=None)
    monkeypatch.setattr(auth, "_find_user_by_google_sub", lambda db, google_sub: None)
    monkeypatch.setattr(auth, "_find_user_by_email_exact", lambda db, email: existing_user)

    resolved = auth._resolve_google_user_identity(fake_db, google_sub="google-sub-1", email="user@example.com", name="Existing")

    assert resolved is existing_user
    assert existing_user.google_sub == "google-sub-1"
    assert fake_db.commits == 1


def test_resolve_google_user_identity_creates_new_google_account(monkeypatch):
    fake_db = _FakeDb()
    monkeypatch.setattr(auth, "_find_user_by_google_sub", lambda db, google_sub: None)
    monkeypatch.setattr(auth, "_find_user_by_email_exact", lambda db, email: None)

    resolved = auth._resolve_google_user_identity(fake_db, google_sub="google-sub-1", email="user@example.com", name="User")

    assert resolved.google_sub == "google-sub-1"
    assert resolved.auth_provider == "google"
    assert resolved.email == "user@example.com"
    assert fake_db.commits == 1
