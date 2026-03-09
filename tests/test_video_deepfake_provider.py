import asyncio
import tempfile

import pytest

from app.services.reality.providers.http_provider import HttpProbabilityProvider, RealityDetectionError


class DummyResponse:
    def __init__(self, status_code=200, json_data=None):
        self._json = json_data or {"synthetic_probability": 0.8}
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception("error")

    def json(self):
        return self._json


@pytest.mark.asyncio
async def test_video_deepfake_provider(monkeypatch):
    async def fake_post(self, url, files=None, headers=None):
        return DummyResponse()

    class DummyClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        post = fake_post

    monkeypatch.setattr("httpx.AsyncClient", DummyClient)

    prov = HttpProbabilityProvider(api_url="http://test", api_key=None, timeout=1)
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"\x00" * 10)
        tmp.flush()
        result = await prov.detect(tmp.name, "video/mp4")
        assert result["probability"] == 0.8


@pytest.mark.asyncio
async def test_invalid_provider_response(monkeypatch):
    async def fake_post(self, url, files=None, headers=None):
        return DummyResponse(json_data={"synthetic_probability": 1.5})

    class DummyClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        post = fake_post

    monkeypatch.setattr("httpx.AsyncClient", DummyClient)
    prov = HttpProbabilityProvider(api_url="http://test", api_key=None, timeout=1)
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"\x00" * 10)
        tmp.flush()
        with pytest.raises(RealityDetectionError):
            await prov.detect(tmp.name, "video/mp4")
