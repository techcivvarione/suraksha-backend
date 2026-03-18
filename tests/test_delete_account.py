from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.routes import auth


class _FakeDb:
    def __init__(self):
        self.added = []
        self.deleted = []
        self.committed = False
        self.rolled_back = False

    def add(self, obj):
        self.added.append(obj)

    def delete(self, obj):
        self.deleted.append(obj)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def get_bind(self):
        return object()

    def execute(self, *args, **kwargs):
        raise AssertionError("execute should be monkeypatched in this test")


class _Url:
    path = "/auth/delete-account"


class _Request:
    url = _Url()


def test_delete_account_rejects_wrong_confirmation_name():
    user = SimpleNamespace(id="user-1", name="maddy", token_version=0)

    with pytest.raises(HTTPException) as exc:
        auth.delete_account(
            auth.DeleteAccountRequest(confirm_username="other"),
            _Request(),
            _FakeDb(),
            user,
        )

    assert exc.value.status_code == 400
    assert exc.value.detail == "Confirmation name does not match"


def test_delete_account_invalidates_and_deletes_current_user(monkeypatch):
    db = _FakeDb()
    user = SimpleNamespace(id="user-1", name="maddy", token_version=2, updated_at=None)
    calls = []

    monkeypatch.setattr(auth, "_delete_account_related_data", lambda db, user_id: calls.append(user_id))

    response = auth.delete_account(
        auth.DeleteAccountRequest(confirm_username="maddy"),
        _Request(),
        db,
        user,
    )

    assert calls == ["user-1"]
    assert user.token_version == 3
    assert db.deleted == [user]
    assert db.committed is True
    assert response == {"status": "success", "message": "Account deleted permanently"}


def test_delete_account_rolls_back_when_cleanup_fails(monkeypatch):
    db = _FakeDb()
    user = SimpleNamespace(id="user-1", name="maddy", token_version=1, updated_at=None)

    def _boom(db, user_id):
        raise RuntimeError("db failed")

    monkeypatch.setattr(auth, "_delete_account_related_data", _boom)

    with pytest.raises(HTTPException) as exc:
        auth.delete_account(
            auth.DeleteAccountRequest(confirm_username="maddy"),
            _Request(),
            db,
            user,
        )

    assert exc.value.status_code == 500
    assert exc.value.detail == "Unable to delete account"
    assert db.rolled_back is True


def test_delete_account_related_data_deletes_expected_tables(monkeypatch):
    executed = []

    class _DeleteDb:
        def get_bind(self):
            return object()

        def execute(self, statement, params):
            executed.append((str(statement), params))

    class _Inspector:
        def get_table_names(self):
            return [
                "trusted_alerts",
                "trusted_contacts",
                "family_alerts",
                "alert_events",
                "audit_logs",
                "qr_reports",
                "qr_scan_logs",
                "scan_history",
                "scan_jobs",
                "scam_reports",
                "subscription_events",
                "user_devices",
            ]

    monkeypatch.setattr(auth, "inspect", lambda bind: _Inspector())

    auth._delete_account_related_data(_DeleteDb(), user_id="user-1")

    sql = "\n".join(statement for statement, _ in executed)
    assert "DELETE FROM trusted_alerts" in sql
    assert "DELETE FROM family_alerts" in sql
    assert "DELETE FROM trusted_contacts" in sql
    assert "DELETE FROM alert_events" in sql
    assert "DELETE FROM audit_logs" in sql
    assert "DELETE FROM qr_reports" in sql
    assert "DELETE FROM qr_scan_logs" in sql
    assert "DELETE FROM scan_history" in sql
    assert "DELETE FROM scan_jobs" in sql
    assert "DELETE FROM scam_reports" in sql
    assert "DELETE FROM subscription_events" in sql
    assert "DELETE FROM user_devices" in sql
