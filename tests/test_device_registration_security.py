from fastapi import HTTPException

from app.services import device_service


class _Result:
    def __init__(self, row=None):
        self.row = row

    def first(self):
        return self.row


class _FakeDb:
    def __init__(self, existing_row=None):
        self.existing_row = existing_row
        self.executed = []
        self.commits = 0

    def execute(self, statement, params=None):
        sql = str(statement)
        self.executed.append((sql, params))
        if "SELECT user_id" in sql:
            return _Result(self.existing_row)
        return _Result(None)

    def commit(self):
        self.commits += 1


def test_register_device_rejects_cross_account_reassignment(monkeypatch):
    monkeypatch.setattr(device_service, "ensure_user_devices_table", lambda: None)
    fake_db = _FakeDb(existing_row=("user-b",))

    try:
        device_service.register_device(user_id="user-a", device_token="device-1", device_type="android", db=fake_db)
        assert False, "expected ownership conflict"
    except HTTPException as exc:
        assert exc.status_code == 409
        assert exc.detail == "Device token is already registered to another account"


def test_register_device_allows_same_user_idempotent_update(monkeypatch):
    monkeypatch.setattr(device_service, "ensure_user_devices_table", lambda: None)
    fake_db = _FakeDb(existing_row=("user-a",))

    device_service.register_device(user_id="user-a", device_token="device-1", device_type="android", db=fake_db)

    assert fake_db.commits == 1
    assert any("ON CONFLICT (device_token)" in sql for sql, _ in fake_db.executed)
