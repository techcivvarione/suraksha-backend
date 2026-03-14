import os
import time
import uuid
from types import SimpleNamespace

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("OTP_SECRET_SALT", "test-salt")

from app.main import app
from app.routes import auth, scan_base
from app.services import redis_store


class FakePipeline:
    def __init__(self, redis):
        self.redis = redis
        self.ops = []

    def zremrangebyscore(self, key, minimum, maximum):
        self.ops.append(("zremrangebyscore", key, minimum, maximum))
        return self

    def zcard(self, key):
        self.ops.append(("zcard", key))
        return self

    def zadd(self, key, mapping):
        self.ops.append(("zadd", key, mapping))
        return self

    def expire(self, key, seconds):
        self.ops.append(("expire", key, seconds))
        return self

    def execute(self):
        results = []
        for op in self.ops:
            name = op[0]
            if name == "zremrangebyscore":
                results.append(self.redis.zremrangebyscore(*op[1:]))
            elif name == "zcard":
                results.append(self.redis.zcard(*op[1:]))
            elif name == "zadd":
                results.append(self.redis.zadd(*op[1:]))
            elif name == "expire":
                results.append(self.redis.expire(*op[1:]))
        self.ops.clear()
        return results


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.expiry = {}
        self.zsets = {}

    def clear(self):
        self.values.clear()
        self.expiry.clear()
        self.zsets.clear()

    def _is_expired(self, key):
        expires_at = self.expiry.get(key)
        if expires_at is None:
            return False
        if expires_at <= time.time():
            self.values.pop(key, None)
            self.expiry.pop(key, None)
            self.zsets.pop(key, None)
            return True
        return False

    def set(self, key, value, nx=False, ex=None):
        self._is_expired(key)
        if nx and (key in self.values or key in self.zsets):
            return False
        self.values[key] = value
        if ex is not None:
            self.expiry[key] = time.time() + ex
        return True

    def get(self, key):
        if self._is_expired(key):
            return None
        return self.values.get(key)

    def exists(self, key):
        if self._is_expired(key):
            return 0
        return int(key in self.values or key in self.zsets)

    def pipeline(self):
        return FakePipeline(self)

    def zremrangebyscore(self, key, minimum, maximum):
        zset = self.zsets.setdefault(key, {})
        before = len(zset)
        self.zsets[key] = {member: score for member, score in zset.items() if not (minimum <= score <= maximum)}
        return before - len(self.zsets[key])

    def zcard(self, key):
        return len(self.zsets.get(key, {}))

    def zadd(self, key, mapping):
        zset = self.zsets.setdefault(key, {})
        zset.update(mapping)
        return len(mapping)

    def expire(self, key, seconds):
        self.expiry[key] = time.time() + seconds
        return True

    def eval(self, script, key_count, *args):
        if "redis.call('GET', KEYS[1]) == ARGV[1]" in script:
            key, token = args
            if self.get(key) == token:
                self.values.pop(key, None)
                self.expiry.pop(key, None)
                return 1
            return 0

        key, ttl_seconds, limit = args
        self._is_expired(key)
        if "return {1, current}" in script:
            current = int(self.values.get(key, 0))
            if current >= int(limit):
                return [0, current]
            current += 1
            self.values[key] = current
            self.expiry[key] = time.time() + int(ttl_seconds)
            return [1, current]

        current = int(self.values.get(key, 0)) + 1
        self.values[key] = current
        self.expiry[key] = time.time() + int(ttl_seconds)
        return 1 if current <= int(limit) else 0


class StubDetector:
    def __init__(self, probability):
        self.probability = probability

    async def detect(self, file_path, mime_type, filename=None, fast_mode=False):
        return {"probability": self.probability, "provider_used": "stub-provider"}


@pytest.fixture(autouse=True)
def redis_mock(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(redis_store, "_redis_client", fake)
    return fake


@pytest.fixture(autouse=True)
def stub_detectors(monkeypatch):
    import app.routes.scan_reality_audio as scan_reality_audio
    import app.routes.scan_reality_image as scan_reality_image
    import app.routes.scan_reality_video as scan_reality_video

    monkeypatch.setattr(scan_reality_image, "image_detector", StubDetector(0.2))
    monkeypatch.setattr(scan_reality_video, "video_detector", StubDetector(0.8))
    monkeypatch.setattr(scan_reality_audio, "audio_detector", StubDetector(0.6))


@pytest.fixture
def token_users():
    return {
        "free-token": SimpleNamespace(id=uuid.uuid4(), email="free@example.com", name="Free User", plan="FREE", token="free-token"),
        "pro-token": SimpleNamespace(id=uuid.uuid4(), email="pro@example.com", name="Pro User", plan="GO_PRO", token="pro-token"),
        "ultra-token": SimpleNamespace(id=uuid.uuid4(), email="ultra@example.com", name="Ultra User", plan="GO_ULTRA", token="ultra-token"),
    }


@pytest.fixture
def client(token_users):
    def resolve_user(request: Request):
        header = request.headers.get("Authorization", "")
        token = header.replace("Bearer ", "", 1)
        user = token_users.get(token)
        if user is None:
            raise auth.HTTPException(status_code=401, detail="Invalid token")
        request.state.user = user
        return user

    app.dependency_overrides[scan_base.require_user] = resolve_user
    app.dependency_overrides[auth.get_current_user] = resolve_user
    app.dependency_overrides[auth.get_current_user_optional] = resolve_user
    app.router.on_startup.clear()
    app.router.on_shutdown.clear()

    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture
def auth_token():
    return "free-token"


@pytest.fixture
def free_user_token():
    return "free-token"


@pytest.fixture
def go_pro_token():
    return "pro-token"


@pytest.fixture
def auth_user(token_users):
    return token_users["free-token"]
