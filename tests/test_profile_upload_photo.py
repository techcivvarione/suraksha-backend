import io

from PIL import Image

from app.db import get_db
from app.routes import profile as profile_routes


class _FakeStorageBucket:
    def __init__(self):
        self.upload_calls = []

    def upload(self, path, file, file_options=None):
        self.upload_calls.append({"path": path, "file": file, "file_options": file_options})
        return {"path": path}

    def get_public_url(self, path):
        return f"https://example.supabase.co/storage/v1/object/public/profile-pictures/{path}"


class _FakeStorage:
    def __init__(self, bucket):
        self.bucket = bucket

    def from_(self, name):
        assert name == "profile-pictures"
        return self.bucket


class _FakeSupabase:
    def __init__(self, bucket):
        self.storage = _FakeStorage(bucket)


class _FakeDb:
    def __init__(self):
        self.executed = []
        self.commits = 0

    def execute(self, statement, params=None):
        self.executed.append((str(statement), params))

    def commit(self):
        self.commits += 1


def _png_bytes() -> bytes:
    image = Image.new("RGB", (8, 8), color=(10, 20, 30))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def test_upload_profile_photo_success(client, monkeypatch):
    fake_db = _FakeDb()
    bucket = _FakeStorageBucket()
    client.app.dependency_overrides[get_db] = lambda: fake_db
    monkeypatch.setattr(profile_routes, "get_supabase", lambda: _FakeSupabase(bucket))

    response = client.post(
        "/profile/upload-photo",
        headers={"Authorization": "Bearer free-token"},
        files={"image": ("photo.png", _png_bytes(), "image/png")},
    )

    client.app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200
    body = response.json()
    assert body["profile_image_url"].startswith("https://example.supabase.co/storage/v1/object/public/profile-pictures/profiles/profile_")
    assert body["profile_image_url"].endswith(".jpg")
    assert bucket.upload_calls[0]["path"].startswith("profiles/profile_")
    assert bucket.upload_calls[0]["path"].endswith(".jpg")
    assert bucket.upload_calls[0]["file_options"]["content-type"] == "image/jpeg"
    assert fake_db.commits == 1
    assert any("UPDATE users" in statement for statement, _ in fake_db.executed)


def test_upload_profile_photo_rejects_invalid_type(client):
    response = client.post(
        "/profile/upload-photo",
        headers={"Authorization": "Bearer free-token"},
        files={"image": ("photo.gif", b"GIF89a", "image/gif")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid file type"


def test_upload_profile_photo_rejects_large_file(client):
    payload = b"x" * (5 * 1024 * 1024 + 1)
    response = client.post(
        "/profile/upload-photo",
        headers={"Authorization": "Bearer free-token"},
        files={"image": ("photo.jpg", payload, "image/jpeg")},
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "File too large"


def test_auth_me_returns_complete_restore_identity(client, token_users):
    user = token_users["free-token"]
    user.phone_number = "+919876543210"
    user.profile_image_url = "https://example.supabase.co/storage/v1/object/public/profile-pictures/profiles/profile_test.jpg"
    user.subscription_status = "ACTIVE"
    user.subscription_expires_at = None
    user.token_version = 7

    response = client.get("/auth/me", headers={"Authorization": "Bearer free-token"})

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(user.id)
    assert body["phone_number"] == "+919876543210"
    assert body["phone"] == "+919876543210"
    assert body["profile_image_url"] == user.profile_image_url
    assert body["token_version"] == 7
