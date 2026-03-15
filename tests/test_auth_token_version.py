from types import SimpleNamespace

from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt

from app.main import ensure_token_version_column
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


class _FakeConnection:
    def __init__(self, missing=True):
        self.missing = missing
        self.statements = []

    def execute(self, statement):
        sql = str(statement)
        self.statements.append(sql)
        if "information_schema.columns" in sql:
            return _FakeResult(None if self.missing else ("token_version",))
        return _FakeResult(None)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeResult:
    def __init__(self, value):
        self.value = value

    def first(self):
        return self.value


class _FakeEngine:
    def __init__(self, missing=True):
        self.connection = _FakeConnection(missing=missing)

    def begin(self):
        return self.connection


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
    user = SimpleNamespace(id="user-1", email="user@example.com", phone_number=None, plan="FREE", token_version=5, password_hash="hash")
    monkeypatch.setattr(auth, "verify_password", lambda password, hashed: True)
    loaded = auth._find_login_user(_FakeDb(user, token_version=5), "user@example.com")
    assert loaded is user
    assert loaded.token_version == 5


def test_schema_auto_repair_applies_when_column_missing(monkeypatch):
    fake_engine = _FakeEngine(missing=True)
    monkeypatch.setattr("app.main.engine", fake_engine)
    applied = ensure_token_version_column()
    assert applied is True
    assert any("ALTER TABLE users ADD COLUMN token_version" in statement for statement in fake_engine.connection.statements)
    assert any("CREATE INDEX IF NOT EXISTS idx_users_token_version" in statement for statement in fake_engine.connection.statements)


def test_schema_auto_repair_skips_when_column_exists(monkeypatch):
    fake_engine = _FakeEngine(missing=False)
    monkeypatch.setattr("app.main.engine", fake_engine)
    applied = ensure_token_version_column()
    assert applied is False
    assert all("ALTER TABLE users ADD COLUMN token_version" not in statement for statement in fake_engine.connection.statements)


def test_logout_all_invalidation_rejects_old_tokens(monkeypatch):
    active_user = SimpleNamespace(id="user-1", email="user@example.com", plan="FREE", token_version=2, password_changed_at=None, subscription_expires_at=None)
    stale_user = SimpleNamespace(id="user-1", email="user@example.com", plan="FREE", token_version=1)
    token = auth.create_access_token(stale_user)
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    monkeypatch.setattr(auth, "maybe_auto_downgrade_expired_subscription", lambda db, user, request=None: user)

    try:
        auth._resolve_current_user(_Request(), credentials, _FakeDb(active_user, token_version=2), True)
        assert False, "expected token invalidation"
    except auth.HTTPException as exc:
        assert exc.detail["error"] == "TOKEN_EXPIRED"


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

    try:
        auth._resolve_current_user(_Request(), credentials, _FakeDb(current_user, token_version=0), True)
        assert False, "expected password change invalidation"
    except auth.HTTPException as exc:
        assert exc.detail["error"] == "TOKEN_EXPIRED"
