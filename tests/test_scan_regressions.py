import io
import logging

import pytest
from redis.exceptions import RedisError

from app.services.rate_limit import RateLimitResult


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _upload_payload(kind: str) -> tuple[str, io.BytesIO, str]:
    if kind == "image":
        return ("test.png", io.BytesIO(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32), "image/png")
    if kind == "video":
        return ("test.mp4", io.BytesIO(b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 32), "video/mp4")
    return ("test.mp3", io.BytesIO(b"ID3" + b"\x00" * 32), "audio/mpeg")


@pytest.mark.parametrize(
    ("token", "path", "payload_kind", "body", "analysis_type"),
    [
        ("free-token", "/scan/threat", "json", {"text": "Verify account now at https://bit.ly/phish"}, "THREAT"),
        ("pro-token", "/scan/threat", "json", {"text": "Verify account now at https://bit.ly/phish"}, "THREAT"),
        ("free-token", "/scan/email", "json", {"email": "user@example.com"}, "EMAIL"),
        ("pro-token", "/scan/email", "json", {"email": "user@example.com"}, "EMAIL"),
        ("free-token", "/scan/password", "json", {"password": "UniquePass!"}, "PASSWORD"),
        ("pro-token", "/scan/password", "json", {"password": "UniquePass!"}, "PASSWORD"),
        ("free-token", "/scan/reality/image", "image", None, "REALITY_IMAGE"),
        ("pro-token", "/scan/reality/image", "image", None, "REALITY_IMAGE"),
        ("free-token", "/scan/reality/video", "video", None, "REALITY_VIDEO"),
        ("pro-token", "/scan/reality/video", "video", None, "REALITY_VIDEO"),
        ("free-token", "/scan/reality/audio", "audio", None, "REALITY_AUDIO"),
        ("pro-token", "/scan/reality/audio", "audio", None, "REALITY_AUDIO"),
    ],
)
def test_scan_endpoints_succeed_for_free_and_go_pro(client, token, path, payload_kind, body, analysis_type, monkeypatch):
    from app.services.email.providers.hibp_provider import HIBPProvider
    from app.services.password import hibp_checker

    monkeypatch.setattr(
        HIBPProvider,
        "lookup",
        lambda self, email: {
            "breach_count": 1,
            "latest_year": 2024,
            "breaches": [{"name": "Example", "domain": "example.com"}],
        },
    )
    monkeypatch.setattr(hibp_checker, "check_password_pwned", lambda password: 0)

    kwargs = {"json": body} if payload_kind == "json" else {"files": {"file": _upload_payload(payload_kind)}}
    response = client.post(path, headers=_headers(token), **kwargs)

    assert response.status_code == 200
    payload = response.json()
    assert payload["analysis_type"] == analysis_type
    if path == "/scan/email" and token == "pro-token":
        assert payload["breaches"] == [{"name": "Example", "domain": "example.com"}]
    if path == "/scan/email" and token == "free-token":
        assert payload.get("breaches") in (None, [])


def test_free_plan_limit_is_enforced_with_structured_error(client, monkeypatch):
    import app.routes.scan_base as scan_base

    monkeypatch.setattr(
        scan_base,
        "check_rate_limit",
        lambda namespace, limit, window_seconds, *keys: RateLimitResult(allowed=False, count=limit, limit=limit),
    )

    response = client.post(
        "/scan/password",
        headers=_headers("free-token"),
        json={"password": "UniquePass!"},
    )

    assert response.status_code == 429
    assert response.json() == {
        "success": False,
        "error": "SCAN_LIMIT_REACHED",
        "message": "Free scan limit reached.",
    }


def test_go_pro_bypasses_scan_limits(client, monkeypatch):
    import app.routes.scan_base as scan_base

    calls = {"count": 0}

    def deny(*args, **kwargs):
        calls["count"] += 1
        return RateLimitResult(allowed=False, count=999, limit=1)

    monkeypatch.setattr(scan_base, "check_rate_limit", deny)

    response = client.post(
        "/scan/threat",
        headers=_headers("pro-token"),
        json={"text": "Normal message"},
    )

    assert response.status_code == 200
    assert calls["count"] == 0


def test_email_scan_handles_cache_backend_failure(client, monkeypatch):
    from app.services.email import email_analyzer
    from app.services.email.providers.hibp_provider import HIBPProvider

    monkeypatch.setattr(email_analyzer, "get_json", lambda *args, **kwargs: (_ for _ in ()).throw(RedisError("boom")))
    monkeypatch.setattr(
        HIBPProvider,
        "lookup",
        lambda self, email: {"breach_count": 0, "latest_year": None, "breaches": None},
    )

    response = client.post(
        "/scan/email",
        headers=_headers("free-token"),
        json={"email": "cache-failure@example.com"},
    )

    assert response.status_code == 200
    assert response.json()["analysis_type"] == "EMAIL"


def test_scan_processing_failure_returns_structured_error(client, monkeypatch):
    import app.routes.scan_email as scan_email

    monkeypatch.setattr(scan_email.email_analyzer, "analyze_email", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))

    response = client.post(
        "/scan/email",
        headers=_headers("free-token"),
        json={"email": "broken@example.com"},
    )

    assert response.status_code == 500
    assert response.json() == {
        "success": False,
        "error": "SCAN_PROCESSING_ERROR",
        "message": "Scan could not be completed.",
    }


def test_middleware_returns_structured_error_and_request_id(client, caplog, monkeypatch):
    import app.routes.scan_threat as scan_threat

    caplog.set_level(logging.INFO)
    monkeypatch.setattr(scan_threat, "log_scan_event", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("log failed")))

    response = client.post(
        "/scan/threat",
        headers=_headers("free-token"),
        json={"text": "hello"},
    )

    assert response.status_code == 500
    assert response.json() == {
        "success": False,
        "error": "SCAN_PROCESSING_ERROR",
        "message": "Scan could not be completed.",
    }
    assert response.headers["X-Request-ID"]
    assert any("request_failed" == record.msg for record in caplog.records)


def test_scan_limit_check_logs_include_plan_endpoint_and_decision(client, caplog):
    caplog.set_level(logging.INFO)
    response = client.post(
        "/scan/threat",
        headers=_headers("pro-token"),
        json={"text": "hello"},
    )

    assert response.status_code == 200
    matching = [
        record
        for record in caplog.records
        if "scan_limit_check" in record.getMessage() and getattr(record, "endpoint", None) == "/scan/threat"
    ]
    assert matching
    assert getattr(matching[0], "plan", None) == "GO_PRO"
