import asyncio
import tempfile

import httpx
import pytest

from app.services.reality.providers.http_provider import HttpProbabilityProvider, RealityDetectionError


class DummyResponse:
    def __init__(self, status_code=200, json_data=None, text_data=""):
        self.status_code = status_code
        self._json = json_data or {"synthetic_probability": 0.8}
        self.text = text_data

    def json(self):
        return self._json


def test_generic_provider_returns_probability(monkeypatch):
    captured = {}

    async def fake_post(self, url, files=None, headers=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["files"] = files
        return DummyResponse()

    class DummyClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        post = fake_post

    monkeypatch.setattr(httpx, "AsyncClient", DummyClient)

    prov = HttpProbabilityProvider(api_url="http://test", api_key="secret", timeout=1)
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"\x00" * 10)
        tmp.flush()
        result = asyncio.run(prov.detect(tmp.name, "video/mp4"))

    assert result["probability"] == 0.8
    assert captured["headers"] == {"Authorization": "Bearer secret"}
    assert "file" in captured["files"]


def test_hive_provider_uses_token_header_and_media_field(monkeypatch, caplog):
    captured = {}
    hive_payload = {
        "status": [
            {
                "response": {
                    "output": [
                        {
                            "classes": [
                                {"class": "ai_generated", "score": 0.83},
                                {"class": "not_ai_generated", "score": 0.17},
                            ]
                        }
                    ]
                }
            }
        ]
    }

    async def fake_post(self, url, files=None, headers=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["files"] = files
        return DummyResponse(status_code=200, json_data=hive_payload)

    class DummyClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        post = fake_post

    caplog.set_level("INFO")
    monkeypatch.setattr(httpx, "AsyncClient", DummyClient)

    prov = HttpProbabilityProvider(
        api_url="https://api.thehive.ai/api/v2/task/sync",
        api_key="hive-key",
        timeout=1,
    )
    with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
        tmp.write(b"\xff\xd8" + b"\x00" * 10)
        tmp.flush()
        result = asyncio.run(prov.detect(tmp.name, "image/jpeg"))

    assert result == {"probability": 0.83, "provider_used": "hive"}
    assert captured["url"] == "https://api.thehive.ai/api/v2/task/sync"
    assert captured["headers"] == {"Authorization": "Token hive-key"}
    assert "media" in captured["files"]
    assert any("hive_request" in record.getMessage() for record in caplog.records)


def test_hive_provider_logs_error_body_and_raises(monkeypatch, caplog):
    async def fake_post(self, url, files=None, headers=None):
        return DummyResponse(status_code=400, json_data={"error": "invalid file format"}, text_data='{"error":"invalid file format"}')

    class DummyClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        post = fake_post

    caplog.set_level("INFO")
    monkeypatch.setattr(httpx, "AsyncClient", DummyClient)

    prov = HttpProbabilityProvider(
        api_url="https://api.thehive.ai/api/v2/task/sync",
        api_key="hive-key",
        timeout=1,
    )
    with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
        tmp.write(b"\xff\xd8" + b"\x00" * 10)
        tmp.flush()
        with pytest.raises(RealityDetectionError) as excinfo:
            asyncio.run(prov.detect(tmp.name, "image/jpeg"))

    assert excinfo.value.provider == "hive"
    assert excinfo.value.status_code == 400
    assert excinfo.value.response_body == '{"error":"invalid file format"}'
    assert any("provider_error_response" in record.getMessage() for record in caplog.records)
